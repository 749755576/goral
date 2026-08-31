import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import zlib from "node:zlib";

import {
  LOCKED_RELEASES,
  defaultStorageRoots,
  extractSingleBinary,
  fetchNativeClients,
  parseSha256Sums,
  resolveHostTarget,
  validateTarPath,
} from "./fetch-native-clients.mjs";

const TEST_TEMP_ROOT = path.join(os.tmpdir(), "goral-native-client-tests");

function writeText(target, offset, length, value) {
  const bytes = Buffer.from(value, "utf8");
  if (bytes.length > length) throw new Error("test tar field too long");
  bytes.copy(target, offset);
}

function writeOctal(target, offset, length, value) {
  const text = value.toString(8).padStart(length - 1, "0") + "\0";
  writeText(target, offset, length, text);
}

function tarHeader({ name, type = "0", size = 0, linkName = "" }) {
  const header = Buffer.alloc(512);
  writeText(header, 0, 100, name);
  writeOctal(header, 100, 8, type === "5" ? 0o755 : 0o755);
  writeOctal(header, 108, 8, 0);
  writeOctal(header, 116, 8, 0);
  writeOctal(header, 124, 12, size);
  writeOctal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  header[156] = type.charCodeAt(0);
  writeText(header, 157, 100, linkName);
  writeText(header, 257, 6, "ustar\0");
  writeText(header, 263, 2, "00");
  let checksum = 0;
  for (const byte of header) checksum += byte;
  const checksumText = checksum.toString(8).padStart(6, "0") + "\0 ";
  writeText(header, 148, 8, checksumText);
  return header;
}

function makeArchive(entries, { trailing = Buffer.alloc(0) } = {}) {
  const chunks = [];
  for (const entry of entries) {
    const data = Buffer.from(entry.data || Buffer.alloc(0));
    chunks.push(tarHeader({
      name: entry.name,
      type: entry.type || "0",
      size: data.length,
      linkName: entry.linkName || "",
    }));
    chunks.push(data);
    const padding = (512 - (data.length % 512)) % 512;
    if (padding) chunks.push(Buffer.alloc(padding));
  }
  chunks.push(Buffer.alloc(1024));
  chunks.push(trailing);
  return zlib.gzipSync(Buffer.concat(chunks));
}

function executable(platform, marker = "client") {
  const body = Buffer.from(marker, "utf8");
  if (platform === "win32") return Buffer.concat([Buffer.from("MZ"), Buffer.alloc(2), body]);
  if (platform === "linux") return Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), body]);
  return Buffer.concat([Buffer.from([0xca, 0xfe, 0xba, 0xbe]), body]);
}

function digest(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function testDirectory(t) {
  fs.mkdirSync(TEST_TEMP_ROOT, { recursive: true });
  const root = fs.mkdtempSync(path.join(TEST_TEMP_ROOT, "netcatty-native-fetch-test-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

async function serve(t, routes) {
  const counts = new Map();
  const server = http.createServer((request, response) => {
    const pathname = new URL(request.url, "http://127.0.0.1").pathname;
    counts.set(pathname, (counts.get(pathname) || 0) + 1);
    const route = routes[pathname];
    if (!route) {
      response.writeHead(404).end();
      return;
    }
    response.writeHead(route.status || 200, {
      "content-type": route.type || "application/octet-stream",
      "content-length": route.body.length,
      ...(route.headers || {}),
    });
    response.end(route.body);
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const address = server.address();
  return { baseUrl: `http://127.0.0.1:${address.port}`, counts };
}

test("release locks and host target selection are exact", () => {
  assert.equal(LOCKED_RELEASES.mosh.release, "moshcatty-0.1.8");
  assert.equal(LOCKED_RELEASES.et.release, "et-bin-6.2.10-1");
  assert.equal(resolveHostTarget("mosh", "linux", "x64").asset, "mosh-client-linux-x64.tar.gz");
  assert.equal(resolveHostTarget("et", "darwin", "arm64").asset, "et-darwin-universal.tar.gz");
  assert.throws(() => resolveHostTarget("et", "win32", "arm64"), /current platform/);
});

test("Tauri resource mapping matches the native runtime lookup contract", () => {
  const config = JSON.parse(fs.readFileSync(
    new URL("../src-tauri/tauri.conf.json", import.meta.url),
    "utf8",
  ));
  assert.deepEqual(config.bundle.resources, {
    "resources/mosh/mosh-client*": "mosh/",
    "resources/mosh/moshcatty.version": "mosh/moshcatty.version",
    "resources/et/et*": "et/",
  });
  assert.equal(
    fs.readFileSync(new URL("../src-tauri/resources/mosh/moshcatty.version", import.meta.url), "utf8").trim(),
    "0.1.8",
  );
});

test("storage defaults are portable while an explicit development root remains authoritative", () => {
  const defaults = defaultStorageRoots("win32", {
    LOCALAPPDATA: "C:\\Users\\Example\\AppData\\Local",
    TEMP: "C:\\Temp",
  });
  assert.equal(defaults.developmentRoot, "C:\\Users\\Example\\AppData\\Local\\Goral\\development");
  assert.equal(defaults.cacheRoot, `${defaults.developmentRoot}\\native-client-cache`);
  assert.equal(defaults.tempRoot, "C:\\Temp\\Goral\\native-client-temp");

  const configured = defaultStorageRoots("win32", {
    GORAL_DEV_SETTING_ROOT: "R:\\goral-dev-root",
  });
  assert.equal(configured.developmentRoot, "R:\\goral-dev-root");
  assert.match(configured.cacheRoot, /^R:\\goral-dev-root\\/i);
  assert.match(configured.tempRoot, /^R:\\goral-dev-root\\/i);
});

test("SHA256SUMS parser rejects malformed, duplicate, and path-bearing entries", () => {
  const hash = "a".repeat(64);
  assert.equal(parseSha256Sums(`${hash}  asset.tar.gz\n`).get("asset.tar.gz"), hash);
  assert.throws(() => parseSha256Sums("not-a-sum"), /malformed/);
  assert.throws(
    () => parseSha256Sums(`${hash} asset.tar.gz\n${hash} asset.tar.gz\n`),
    /duplicate/,
  );
  assert.throws(() => parseSha256Sums(`${hash} ../asset.tar.gz\n`), /unsafe/);
});

test("tar path validation rejects traversal, absolute, drive, and backslash forms", () => {
  for (const value of ["../et", "a/../../et", "/tmp/et", "C:/temp/et", "dir\\et"] ) {
    assert.throws(() => validateTarPath(value), /unsafe/);
  }
  assert.equal(validateTarPath("./release/et"), "release/et");
});

test("strict tar reader accepts exactly one expected regular client", () => {
  const target = resolveHostTarget("et", "linux", "x64");
  const binary = executable("linux");
  const archive = makeArchive([
    { name: "release/", type: "5" },
    { name: "release/et", data: binary },
  ]);
  assert.deepEqual(extractSingleBinary(archive, target), binary);
});

test("strict tar reader rejects traversal, links, extra files, and wrong binaries", () => {
  const target = resolveHostTarget("et", "linux", "x64");
  const binary = executable("linux");
  assert.throws(
    () => extractSingleBinary(makeArchive([{ name: "../et", data: binary }]), target),
    /unsafe/,
  );
  assert.throws(
    () => extractSingleBinary(makeArchive([{ name: "et", type: "2", linkName: "elsewhere" }]), target),
    /link/,
  );
  assert.throws(
    () => extractSingleBinary(makeArchive([
      { name: "et", data: binary },
      { name: "README", data: Buffer.from("extra") },
    ]), target),
    /extra regular files/,
  );
  assert.throws(
    () => extractSingleBinary(makeArchive([{ name: "different", data: binary }]), target),
    /wrong native client/,
  );
});

test("strict tar reader verifies executable format and trailing bytes", () => {
  const target = resolveHostTarget("mosh", "win32", "x64");
  assert.throws(
    () => extractSingleBinary(makeArchive([{ name: "mosh-client.exe", data: Buffer.from("not PE") }]), target),
    /PE image/,
  );
  assert.throws(
    () => extractSingleBinary(
      makeArchive([{ name: "mosh-client.exe", data: executable("win32") }], {
        trailing: Buffer.from([1]),
      }),
      target,
    ),
    /trailing data/,
  );
});

test("end-to-end fetch verifies sums, stages only the host client, and reuses verified cache", async (t) => {
  const root = testDirectory(t);
  const target = resolveHostTarget("mosh", "win32", "x64");
  const archive = makeArchive([{ name: "bundle/mosh-client.exe", data: executable("win32", "mosh") }]);
  const checksum = digest(archive);
  const { baseUrl, counts } = await serve(t, {
    "/SHA256SUMS": { body: Buffer.from(`${checksum}  ${target.asset}\n`) },
    [`/${target.asset}`]: { body: archive },
  });
  const outputRoot = path.join(root, "resources");
  const storageRoots = {
    developmentRoot: root,
    cacheRoot: path.join(root, "cache"),
    tempRoot: path.join(root, "temp"),
  };
  const sources = {
    ...LOCKED_RELEASES,
    mosh: { ...LOCKED_RELEASES.mosh, baseUrl },
  };

  const first = await fetchNativeClients({
    products: ["mosh"],
    platform: "win32",
    arch: "x64",
    outputRoot,
    storageRoots,
    sources,
    allowInsecureHttp: true,
  });
  const second = await fetchNativeClients({
    products: ["mosh"],
    platform: "win32",
    arch: "x64",
    outputRoot,
    storageRoots,
    sources,
    allowInsecureHttp: true,
  });

  assert.equal(first[0].cached, false);
  assert.equal(second[0].cached, true);
  assert.equal(counts.get(`/${target.asset}`), 1);
  assert.equal(counts.get("/SHA256SUMS"), 2);
  assert.ok(fs.existsSync(path.join(outputRoot, "mosh", "mosh-client.exe")));
  assert.equal(fs.existsSync(path.join(outputRoot, "et", "et.exe")), false);
  assert.ok(fs.existsSync(path.join(storageRoots.cacheRoot, "mosh", LOCKED_RELEASES.mosh.release, target.asset)));
});

test("checksum mismatch fails closed before cache or staging publication", async (t) => {
  const root = testDirectory(t);
  const target = resolveHostTarget("et", "win32", "x64");
  const archive = makeArchive([{ name: "et.exe", data: executable("win32", "et") }]);
  const { baseUrl } = await serve(t, {
    "/SHA256SUMS": { body: Buffer.from(`${"0".repeat(64)}  ${target.asset}\n`) },
    [`/${target.asset}`]: { body: archive },
  });
  const outputRoot = path.join(root, "resources");
  const storageRoots = {
    developmentRoot: root,
    cacheRoot: path.join(root, "cache"),
    tempRoot: path.join(root, "temp"),
  };
  await assert.rejects(
    fetchNativeClients({
      products: ["et"],
      platform: "win32",
      arch: "x64",
      outputRoot,
      storageRoots,
      sources: { ...LOCKED_RELEASES, et: { ...LOCKED_RELEASES.et, baseUrl } },
      allowInsecureHttp: true,
    }),
    /SHA-256 verification/,
  );
  assert.equal(fs.existsSync(path.join(outputRoot, "et", "et.exe")), false);
  assert.equal(fs.existsSync(path.join(storageRoots.cacheRoot, "et")), false);
});

test("missing checksum entry has no unverified escape hatch", async (t) => {
  const root = testDirectory(t);
  const target = resolveHostTarget("et", "win32", "x64");
  const archive = makeArchive([{ name: "et.exe", data: executable("win32") }]);
  const { baseUrl } = await serve(t, {
    "/SHA256SUMS": { body: Buffer.from(`${digest(archive)}  another.tar.gz\n`) },
    [`/${target.asset}`]: { body: archive },
  });
  await assert.rejects(
    fetchNativeClients({
      products: ["et"],
      platform: "win32",
      arch: "x64",
      outputRoot: path.join(root, "resources"),
      storageRoots: {
        developmentRoot: root,
        cacheRoot: path.join(root, "cache"),
        tempRoot: path.join(root, "temp"),
      },
      sources: { ...LOCKED_RELEASES, et: { ...LOCKED_RELEASES.et, baseUrl } },
      allowInsecureHttp: true,
    }),
    /no entry for the locked asset/,
  );
});
