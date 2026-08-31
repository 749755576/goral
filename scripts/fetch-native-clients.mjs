#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import zlib from "node:zlib";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(SCRIPT_DIR, "..");

export const LOCKED_RELEASES = Object.freeze({
  mosh: Object.freeze({
    release: "moshcatty-0.1.8",
    baseUrl: "https://github.com/binaricat/MoshCatty/releases/download/moshcatty-0.1.8",
    license: "GPL-3.0-or-later",
  }),
  et: Object.freeze({
    release: "et-bin-6.2.10-1",
    baseUrl: "https://github.com/binaricat/Netcatty-et-bin/releases/download/et-bin-6.2.10-1",
    license: "Apache-2.0",
  }),
});

const MAX_SUMS_BYTES = 1024 * 1024;
const MAX_ARCHIVE_BYTES = 128 * 1024 * 1024;
const MAX_TAR_BYTES = 256 * 1024 * 1024;
const MAX_BINARY_BYTES = 128 * 1024 * 1024;
const MAX_TAR_ENTRIES = 128;
const MAX_TAR_PATH_BYTES = 4096;
const DOWNLOAD_TIMEOUT_MS = 60_000;

const TARGETS = Object.freeze({
  mosh: Object.freeze({
    "linux-x64": Object.freeze({
      asset: "mosh-client-linux-x64.tar.gz",
      binary: "mosh-client",
      accepted: ["mosh-client", "mosh-client-linux-x64"],
    }),
    "linux-arm64": Object.freeze({
      asset: "mosh-client-linux-arm64.tar.gz",
      binary: "mosh-client",
      accepted: ["mosh-client", "mosh-client-linux-arm64"],
    }),
    "darwin-universal": Object.freeze({
      asset: "mosh-client-darwin-universal.tar.gz",
      binary: "mosh-client",
      accepted: ["mosh-client", "mosh-client-darwin-universal"],
    }),
    "win32-x64": Object.freeze({
      asset: "mosh-client-win32-x64.tar.gz",
      binary: "mosh-client.exe",
      accepted: ["mosh-client.exe", "mosh-client-win32-x64.exe"],
    }),
  }),
  et: Object.freeze({
    "linux-x64": Object.freeze({
      asset: "et-linux-x64.tar.gz",
      binary: "et",
      accepted: ["et", "et-linux-x64"],
    }),
    "linux-arm64": Object.freeze({
      asset: "et-linux-arm64.tar.gz",
      binary: "et",
      accepted: ["et", "et-linux-arm64"],
    }),
    "darwin-universal": Object.freeze({
      asset: "et-darwin-universal.tar.gz",
      binary: "et",
      accepted: ["et", "et-darwin-universal"],
    }),
    "win32-x64": Object.freeze({
      asset: "et-win32-x64.tar.gz",
      binary: "et.exe",
      accepted: ["et.exe", "et-win32-x64.exe"],
    }),
  }),
});

function safeError(message) {
  return new Error(message);
}

function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function assertSafeSegment(value, label) {
  if (typeof value !== "string" || !/^[A-Za-z0-9._-]+$/.test(value)) {
    throw safeError(`invalid ${label}`);
  }
  return value;
}

export function defaultStorageRoots(platform = process.platform, env = process.env) {
  // Keep the former development-only variable as a read-only compatibility
  // alias so existing D-drive setups continue to reuse their locked cache.
  const configuredRoot = env.GORAL_DEV_SETTING_ROOT
    || env.LUMENDOCK_DEV_SETTING_ROOT
    || env.NETCATTY_DEV_SETTING_ROOT;
  const pathApi = platform === "win32" ? path.win32 : path.posix;
  const defaultCacheRoot = platform === "win32"
    ? env.LOCALAPPDATA || path.win32.join(os.homedir(), "AppData", "Local")
    : env.XDG_CACHE_HOME || path.posix.join(os.homedir(), ".cache");
  const developmentRoot = configuredRoot
    ? pathApi.resolve(configuredRoot)
    : pathApi.join(defaultCacheRoot, "Goral", "development");
  const temporaryRoot = configuredRoot
    ? pathApi.join(developmentRoot, "temp")
    : pathApi.join(env.TEMP || env.TMP || os.tmpdir(), "Goral", "native-client-temp");
  return {
    developmentRoot,
    cacheRoot: pathApi.join(developmentRoot, "native-client-cache"),
    tempRoot: temporaryRoot,
  };
}

export function resolveHostTarget(product, platform = process.platform, arch = process.arch) {
  if (!Object.hasOwn(TARGETS, product)) throw safeError("unknown native client");
  const key = platform === "darwin"
    ? "darwin-universal"
    : `${platform}-${arch}`;
  const target = TARGETS[product][key];
  if (!target) {
    throw safeError(`no bundled ${product} client for the current platform`);
  }
  return { ...target, product, platform, arch: platform === "darwin" ? "universal" : arch };
}

export function parseSha256Sums(text) {
  if (typeof text !== "string" || Buffer.byteLength(text, "utf8") > MAX_SUMS_BYTES) {
    throw safeError("SHA256SUMS is invalid or too large");
  }
  const sums = new Map();
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const match = line.match(/^([0-9a-fA-F]{64})[ \t]+\*?([^ \t]+)$/);
    if (!match) throw safeError("SHA256SUMS contains a malformed entry");
    const file = match[2];
    if (path.posix.basename(file) !== file || path.win32.basename(file) !== file) {
      throw safeError("SHA256SUMS contains an unsafe asset name");
    }
    const digest = match[1].toLowerCase();
    if (sums.has(file)) throw safeError("SHA256SUMS contains a duplicate asset");
    sums.set(file, digest);
  }
  if (sums.size === 0) throw safeError("SHA256SUMS contains no entries");
  return sums;
}

function readTarString(buffer) {
  const zero = buffer.indexOf(0);
  const end = zero === -1 ? buffer.length : zero;
  return buffer.subarray(0, end).toString("utf8");
}

function parseTarOctal(buffer, label) {
  const value = readTarString(buffer).trim().replace(/^0+/, "") || "0";
  if (!/^[0-7]+$/.test(value)) throw safeError(`tar contains an invalid ${label}`);
  const parsed = Number.parseInt(value, 8);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw safeError(`tar contains an invalid ${label}`);
  }
  return parsed;
}

function isZeroBlock(block) {
  return block.every((byte) => byte === 0);
}

function verifyTarHeaderChecksum(header) {
  const expected = parseTarOctal(header.subarray(148, 156), "header checksum");
  let actual = 0;
  for (let index = 0; index < header.length; index += 1) {
    actual += index >= 148 && index < 156 ? 0x20 : header[index];
  }
  if (actual !== expected) throw safeError("tar header checksum mismatch");
}

export function validateTarPath(rawName, entryType = "entry") {
  if (typeof rawName !== "string" || Buffer.byteLength(rawName, "utf8") > MAX_TAR_PATH_BYTES) {
    throw safeError(`tar contains an invalid ${entryType} path`);
  }
  if (!rawName || rawName.includes("\\") || rawName.startsWith("/") || /^[A-Za-z]:/.test(rawName)) {
    throw safeError(`tar contains an unsafe ${entryType} path`);
  }
  const parts = rawName.split("/").filter((part) => part !== "" && part !== ".");
  if (parts.length === 0 || parts.some((part) => part === ".." || part.includes("\0"))) {
    throw safeError(`tar contains an unsafe ${entryType} path`);
  }
  return parts.join("/");
}

export function extractSingleBinary(archive, target) {
  if (!Buffer.isBuffer(archive) || archive.length === 0 || archive.length > MAX_ARCHIVE_BYTES) {
    throw safeError("native client archive is invalid or too large");
  }
  let tar;
  try {
    tar = zlib.gunzipSync(archive, { maxOutputLength: MAX_TAR_BYTES });
  } catch {
    throw safeError("native client archive is not a valid bounded gzip stream");
  }

  const regularFiles = [];
  let offset = 0;
  let entries = 0;
  let sawTerminator = false;
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    if (isZeroBlock(header)) {
      const second = tar.subarray(offset + 512, offset + 1024);
      if (second.length !== 512 || !isZeroBlock(second)) {
        throw safeError("tar is missing its end marker");
      }
      sawTerminator = true;
      offset += 1024;
      break;
    }
    entries += 1;
    if (entries > MAX_TAR_ENTRIES) throw safeError("tar contains too many entries");
    verifyTarHeaderChecksum(header);

    const name = readTarString(header.subarray(0, 100));
    const prefix = readTarString(header.subarray(345, 500));
    const fullName = prefix ? `${prefix}/${name}` : name;
    const safeName = validateTarPath(fullName);
    const size = parseTarOctal(header.subarray(124, 136), "entry size");
    const type = header[156] === 0 ? "0" : String.fromCharCode(header[156]);
    const dataStart = offset + 512;
    const paddedSize = Math.ceil(size / 512) * 512;
    const nextOffset = dataStart + paddedSize;
    if (nextOffset > tar.length) throw safeError("tar entry exceeds the archive boundary");

    if (type === "0") {
      if (size === 0 || size > MAX_BINARY_BYTES) {
        throw safeError("native client binary is empty or too large");
      }
      regularFiles.push({ name: safeName, data: Buffer.from(tar.subarray(dataStart, dataStart + size)) });
      if (regularFiles.length > 1) throw safeError("tar contains extra regular files");
    } else if (type === "5") {
      if (size !== 0) throw safeError("tar directory contains unexpected data");
    } else if (type === "1" || type === "2") {
      throw safeError("tar contains a symbolic or hard link");
    } else if (type === "x" || type === "g") {
      if (size > 64 * 1024) throw safeError("tar metadata is too large");
    } else {
      throw safeError("tar contains an unsupported entry type");
    }
    offset = nextOffset;
  }
  if (!sawTerminator || tar.subarray(offset).some((byte) => byte !== 0)) {
    throw safeError("tar has invalid trailing data");
  }
  if (regularFiles.length !== 1) throw safeError("tar does not contain exactly one client binary");

  const file = regularFiles[0];
  const basename = path.posix.basename(file.name);
  if (!target.accepted.includes(basename)) {
    throw safeError("tar contains the wrong native client binary");
  }
  validateExecutableMagic(file.data, target.platform);
  return file.data;
}

export function validateExecutableMagic(binary, platform) {
  if (!Buffer.isBuffer(binary) || binary.length < 4) {
    throw safeError("native client executable is invalid");
  }
  if (platform === "win32") {
    if (binary[0] !== 0x4d || binary[1] !== 0x5a) {
      throw safeError("native client executable is not a Windows PE image");
    }
    return;
  }
  if (platform === "linux") {
    if (!binary.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))) {
      throw safeError("native client executable is not a Linux ELF image");
    }
    return;
  }
  if (platform === "darwin") {
    const magic = binary.readUInt32BE(0);
    const accepted = new Set([
      0xfeedface, 0xcefaedfe, 0xfeedfacf, 0xcffaedfe,
      0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca,
    ]);
    if (!accepted.has(magic)) {
      throw safeError("native client executable is not a macOS Mach-O image");
    }
    return;
  }
  throw safeError("unsupported native client platform");
}

async function downloadBuffer(url, {
  fetchImpl,
  label,
  maxBytes,
  allowInsecureHttp = false,
  redirectDepth = 0,
}) {
  if (redirectDepth > 5) throw safeError(`${label} returned too many redirects`);
  const parsed = new URL(url);
  if (parsed.protocol !== "https:" && !(allowInsecureHttp && parsed.protocol === "http:")) {
    throw safeError(`${label} must use HTTPS`);
  }
  let response;
  try {
    response = await fetchImpl(parsed, {
      redirect: "manual",
      signal: AbortSignal.timeout(DOWNLOAD_TIMEOUT_MS),
      headers: { "user-agent": "Goral-native-client-fetch/1" },
    });
  } catch {
    throw safeError(`${label} download failed`);
  }
  if (response.status >= 300 && response.status < 400) {
    const location = response.headers.get("location");
    if (!location) throw safeError(`${label} returned an invalid redirect`);
    return downloadBuffer(new URL(location, parsed).toString(), {
      fetchImpl,
      label,
      maxBytes,
      allowInsecureHttp,
      redirectDepth: redirectDepth + 1,
    });
  }
  if (response.status !== 200 || !response.body) {
    throw safeError(`${label} download returned HTTP ${response.status}`);
  }
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) {
    await response.body.cancel();
    throw safeError(`${label} download is too large`);
  }
  const chunks = [];
  let total = 0;
  const reader = response.body.getReader();
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw safeError(`${label} download is too large`);
      }
      chunks.push(Buffer.from(value));
    }
  } catch (error) {
    if (error?.message === `${label} download is too large`) throw error;
    throw safeError(`${label} download failed`);
  }
  return Buffer.concat(chunks, total);
}

function readBoundedRegularFile(file, maximumBytes) {
  let stat;
  try {
    stat = fs.lstatSync(file);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw safeError("native client cache is unavailable");
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > maximumBytes) {
    throw safeError("native client cache contains an unsafe entry");
  }
  return fs.readFileSync(file);
}

function atomicWrite(file, data, mode = 0o600) {
  const directory = path.dirname(file);
  fs.mkdirSync(directory, { recursive: true });
  const temporary = path.join(directory, `.${path.basename(file)}.${crypto.randomUUID()}.tmp`);
  let handle;
  try {
    handle = fs.openSync(temporary, "wx", mode);
    fs.writeFileSync(handle, data);
    fs.fsyncSync(handle);
    fs.closeSync(handle);
    handle = undefined;
    if (fs.existsSync(file)) {
      const existing = fs.lstatSync(file);
      if (!existing.isFile() || existing.isSymbolicLink()) {
        throw safeError("native client destination is unsafe");
      }
    }
    fs.renameSync(temporary, file);
    if (process.platform !== "win32") fs.chmodSync(file, mode);
  } finally {
    if (handle !== undefined) fs.closeSync(handle);
    try { fs.unlinkSync(temporary); } catch (error) { if (error?.code !== "ENOENT") throw error; }
  }
}

async function verifiedArchive(product, target, source, roots, options) {
  const sumsBuffer = await downloadBuffer(`${source.baseUrl}/SHA256SUMS`, {
    ...options,
    label: `${product} SHA256SUMS`,
    maxBytes: MAX_SUMS_BYTES,
  });
  const sums = parseSha256Sums(sumsBuffer.toString("utf8"));
  const expected = sums.get(target.asset);
  if (!expected) throw safeError(`${product} SHA256SUMS has no entry for the locked asset`);

  const cacheFile = path.join(
    roots.cacheRoot,
    assertSafeSegment(product, "client name"),
    assertSafeSegment(source.release, "release tag"),
    assertSafeSegment(target.asset, "asset name"),
  );
  const cached = readBoundedRegularFile(cacheFile, MAX_ARCHIVE_BYTES);
  if (cached && sha256(cached) === expected) return { archive: cached, archiveSha256: expected, cached: true };

  const archive = await downloadBuffer(`${source.baseUrl}/${target.asset}`, {
    ...options,
    label: `${product} locked asset`,
    maxBytes: MAX_ARCHIVE_BYTES,
  });
  const actual = sha256(archive);
  if (actual !== expected) throw safeError(`${product} locked asset failed SHA-256 verification`);
  atomicWrite(cacheFile, archive, 0o600);
  return { archive, archiveSha256: actual, cached: false };
}

export async function fetchNativeClients({
  products = ["mosh", "et"],
  platform = process.platform,
  arch = process.arch,
  outputRoot = path.join(PROJECT_ROOT, "src-tauri", "resources"),
  storageRoots = defaultStorageRoots(platform),
  sources = LOCKED_RELEASES,
  fetchImpl = globalThis.fetch,
  allowInsecureHttp = false,
} = {}) {
  if (typeof fetchImpl !== "function") throw safeError("Node.js fetch is unavailable");
  const uniqueProducts = [...new Set(products)];
  if (uniqueProducts.length === 0 || uniqueProducts.some((product) => !Object.hasOwn(LOCKED_RELEASES, product))) {
    throw safeError("invalid native client selection");
  }
  fs.mkdirSync(storageRoots.cacheRoot, { recursive: true });
  fs.mkdirSync(storageRoots.tempRoot, { recursive: true });
  const operationRoot = fs.mkdtempSync(path.join(storageRoots.tempRoot, "goral-native-clients-"));
  const results = [];
  try {
    for (const product of uniqueProducts) {
      const target = resolveHostTarget(product, platform, arch);
      const source = sources[product];
      if (!source || source.release !== LOCKED_RELEASES[product].release) {
        throw safeError(`${product} source is not the locked release`);
      }
      const verified = await verifiedArchive(product, target, source, storageRoots, {
        fetchImpl,
        allowInsecureHttp,
      });
      const binary = extractSingleBinary(verified.archive, target);
      const destination = path.join(outputRoot, product, target.binary);
      atomicWrite(destination, binary, 0o755);
      results.push({
        product,
        release: source.release,
        asset: target.asset,
        binary: target.binary,
        archiveSha256: verified.archiveSha256,
        binarySha256: sha256(binary),
        cached: verified.cached,
      });
    }
  } finally {
    fs.rmSync(operationRoot, { recursive: true, force: true });
  }
  return results;
}

function parseCli(argv) {
  let products = ["mosh", "et"];
  for (const argument of argv) {
    if (argument === "--help") return { help: true, products };
    if (argument.startsWith("--client=")) {
      const value = argument.slice("--client=".length);
      if (value === "all") products = ["mosh", "et"];
      else if (value === "mosh" || value === "et") products = [value];
      else throw safeError("--client must be all, mosh, or et");
      continue;
    }
    throw safeError("unknown command-line option");
  }
  return { help: false, products };
}

async function main(argv = process.argv.slice(2)) {
  const { help, products } = parseCli(argv);
  if (help) {
    console.log("Usage: node scripts/fetch-native-clients.mjs [--client=all|mosh|et]");
    console.log("Downloads only the current platform from the source-locked releases.");
    return;
  }
  const results = await fetchNativeClients({ products });
  for (const result of results) {
    console.log(
      `[native-clients] ${result.product} ${result.release}/${result.asset} -> ${result.binary} ` +
      `(archive sha256=${result.archiveSha256}, ${result.cached ? "verified cache" : "downloaded"})`,
    );
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(`[native-clients] FATAL ${error?.message || "native client fetch failed"}`);
    process.exitCode = 1;
  });
}
