#!/usr/bin/env node

import crypto from "node:crypto";
import { constants as fsConstants, createReadStream } from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(SCRIPT_DIR, "..");

const PORTABLE_FORMAT = "goral-windows-portable-v2";
const DELIVERY_ROOT = "output/portable/windows-x64";
const STAGE_NAME = ".windows-x64.stage";
const PREVIOUS_NAME = ".windows-x64.previous";
const STAGE_MARKER = ".goral-portable-stage-v2";
const STAGE_MARKER_BODY = "goral-windows-portable-v2-stage\n";
const MANIFEST_NAME = "MANIFEST.json";
const MAX_PE_HEADER_OFFSET = 1024 * 1024;
const PE_X64_MACHINE = 0x8664;

export const WINDOWS_X64_NATIVE_CLIENTS = Object.freeze({
  mosh: Object.freeze({
    release: "moshcatty-0.1.8",
    version: "0.1.8",
    sha256: "E44616A22038F1742F765C7DE553796BA4D1698F2C1F7A7CFB0DAFD33ECDC78A",
  }),
  et: Object.freeze({
    release: "et-bin-6.2.10-1",
    sha256: "6212E2C089CD55AA9455DC2A9DE22AC83D0BC6C8AF76CE9AD096668931EE5A25",
  }),
});

// Goral.exe is deliberately last. A partially staged package therefore has
// no launchable desktop entry point, and the complete tree is verified before
// it can replace the current delivery.
const WINDOWS_FILES = Object.freeze([
  Object.freeze({
    source: "LICENSE",
    destination: "LICENSE",
  }),
  Object.freeze({
    source: "NOTICE.md",
    destination: "NOTICE.md",
  }),
  Object.freeze({
    source: "THIRD_PARTY_NOTICES.md",
    destination: "THIRD_PARTY_NOTICES.md",
  }),
  Object.freeze({
    source: "licenses/Inter-OFL-1.1.txt",
    destination: "licenses/Inter-OFL-1.1.txt",
  }),
  Object.freeze({
    source: "SOURCE.md",
    destination: "SOURCE.md",
  }),
  Object.freeze({
    source: "src-tauri/resources/README.md",
    destination: "NATIVE_CLIENTS.md",
  }),
  Object.freeze({
    source: "src-tauri/resources/mosh/moshcatty.version",
    destination: "mosh/moshcatty.version",
    versionManifest: true,
  }),
  Object.freeze({
    source: "src-tauri/resources/mosh/mosh-client.exe",
    destination: "mosh/mosh-client.exe",
    executable: true,
    nativeClient: "mosh",
  }),
  Object.freeze({
    source: "src-tauri/resources/et/et.exe",
    destination: "et/et.exe",
    executable: true,
    nativeClient: "et",
  }),
  Object.freeze({
    source: "target/release/goral-desktop.exe",
    destination: "Goral.exe",
    executable: true,
    desktopExecutable: true,
  }),
]);

const EXPECTED_FILES = Object.freeze(WINDOWS_FILES.map((entry) => entry.destination));
const EXPECTED_DIRECTORIES = Object.freeze(["et", "licenses", "mosh"]);
const STAGE_ALLOWED_FILES = Object.freeze([
  ...EXPECTED_FILES,
  MANIFEST_NAME,
  STAGE_MARKER,
]);

const portablePath = (value) => value.replaceAll("\\", "/");

const lstatOrNull = async (filePath) => {
  try {
    return await fs.lstat(filePath);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
};

const assertPlainDirectory = async (directory, label) => {
  const metadata = await lstatOrNull(directory);
  if (!metadata || metadata.isSymbolicLink() || !metadata.isDirectory()) {
    throw new Error(`${label} is not a plain directory`);
  }
};

const assertContainedRelativePath = (root, relativePath, label) => {
  if (typeof relativePath !== "string" || path.isAbsolute(relativePath)) {
    throw new Error(`${label} is outside the project root`);
  }
  const resolved = path.resolve(root, relativePath);
  const relative = path.relative(root, resolved);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error(`${label} is outside the project root`);
  }
  return { resolved, relative };
};

const assertPlainFileBelow = async (root, relativePath, label) => {
  const { resolved, relative } = assertContainedRelativePath(root, relativePath, label);
  let current = root;
  const components = relative.split(path.sep);
  for (let index = 0; index < components.length; index += 1) {
    current = path.join(current, components[index]);
    const metadata = await lstatOrNull(current);
    if (!metadata) throw new Error(`${label} is missing`);
    if (metadata.isSymbolicLink()) throw new Error(`${label} contains a symbolic link or junction`);
    if (index === components.length - 1) {
      if (!metadata.isFile()) throw new Error(`${label} is not a regular file`);
    } else if (!metadata.isDirectory()) {
      throw new Error(`${label} contains a non-directory path component`);
    }
  }
  return resolved;
};

const ensurePlainDirectoryBelow = async (root, relativePath, label) => {
  const { resolved, relative } = assertContainedRelativePath(root, relativePath, label);
  let current = root;
  for (const component of relative.split(path.sep)) {
    current = path.join(current, component);
    let metadata = await lstatOrNull(current);
    if (!metadata) {
      await fs.mkdir(current);
      metadata = await fs.lstat(current);
    }
    if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
      throw new Error(`${label} contains a symbolic link, junction, or non-directory`);
    }
  }
  return resolved;
};

const digestFile = async (filePath) => new Promise((resolve, reject) => {
  const hash = crypto.createHash("sha256");
  const stream = createReadStream(filePath);
  stream.on("error", reject);
  stream.on("data", (chunk) => hash.update(chunk));
  stream.on("end", () => resolve(hash.digest("hex").toUpperCase()));
});

const readExactly = async (handle, length, position, label) => {
  const buffer = Buffer.alloc(length);
  const { bytesRead } = await handle.read(buffer, 0, length, position);
  if (bytesRead !== length) throw new Error(`${label} has a truncated PE header`);
  return buffer;
};

const assertWindowsX64Pe = async (filePath, label) => {
  const handle = await fs.open(filePath, "r");
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile() || metadata.size < 70) {
      throw new Error(`${label} is not a valid Windows PE executable`);
    }
    const dosHeader = await readExactly(handle, 64, 0, label);
    if (dosHeader[0] !== 0x4d || dosHeader[1] !== 0x5a) {
      throw new Error(`${label} is not a valid Windows PE executable`);
    }
    const peOffset = dosHeader.readUInt32LE(0x3c);
    if (
      peOffset < 64
      || peOffset > MAX_PE_HEADER_OFFSET
      || peOffset + 6 > metadata.size
    ) {
      throw new Error(`${label} has an invalid PE header offset`);
    }
    const peHeader = await readExactly(handle, 6, peOffset, label);
    if (!peHeader.subarray(0, 4).equals(Buffer.from([0x50, 0x45, 0x00, 0x00]))) {
      throw new Error(`${label} is not a valid Windows PE executable`);
    }
    if (peHeader.readUInt16LE(4) !== PE_X64_MACHINE) {
      throw new Error(`${label} is not an x86-64 Windows executable`);
    }
  } finally {
    await handle.close();
  }
};

const normalizeNativeHashes = (overrides) => {
  const hashes = {
    mosh: overrides?.mosh ?? WINDOWS_X64_NATIVE_CLIENTS.mosh.sha256,
    et: overrides?.et ?? WINDOWS_X64_NATIVE_CLIENTS.et.sha256,
  };
  for (const [client, value] of Object.entries(hashes)) {
    if (typeof value !== "string" || !/^[A-Fa-f0-9]{64}$/.test(value)) {
      throw new Error(`The locked ${client} SHA-256 is invalid`);
    }
    hashes[client] = value.toUpperCase();
  }
  return Object.freeze(hashes);
};

const inspectSourceFiles = async (projectRoot, nativeHashes) => {
  const inspected = [];
  for (const entry of WINDOWS_FILES) {
    const label = `Portable source ${path.basename(entry.source)}`;
    const source = await assertPlainFileBelow(projectRoot, entry.source, label);
    const metadata = await fs.lstat(source);
    if (entry.executable) await assertWindowsX64Pe(source, label);
    const sha256 = await digestFile(source);
    if (entry.nativeClient && sha256 !== nativeHashes[entry.nativeClient]) {
      throw new Error(`Bundled ${entry.nativeClient} client failed the locked SHA-256 check`);
    }
    if (entry.versionManifest) {
      const version = (await fs.readFile(source, "utf8")).trim();
      if (version !== WINDOWS_X64_NATIVE_CLIENTS.mosh.version) {
        throw new Error("Bundled Mosh version manifest does not match the locked release");
      }
    }
    inspected.push(Object.freeze({
      ...entry,
      source,
      bytes: metadata.size,
      sha256,
    }));
  }
  return Object.freeze(inspected);
};

const buildManifest = (inspected, nativeHashes) => ({
  format: PORTABLE_FORMAT,
  platform: "windows",
  architecture: "x86_64",
  resourceRoot: ".",
  files: inspected.map((entry) => ({
    path: portablePath(entry.destination),
    bytes: entry.bytes,
    sha256: entry.sha256,
    executable: entry.executable === true,
  })),
  nativeClients: [
    {
      name: "mosh",
      release: WINDOWS_X64_NATIVE_CLIENTS.mosh.release,
      sha256: nativeHashes.mosh,
    },
    {
      name: "et",
      release: WINDOWS_X64_NATIVE_CLIENTS.et.release,
      sha256: nativeHashes.et,
    },
  ],
});

const scanPlainTree = async (root) => {
  await assertPlainDirectory(root, "Portable delivery root");
  const files = [];
  const directories = [];
  const visit = async (directory, relativeDirectory = "") => {
    const names = (await fs.readdir(directory)).sort((left, right) => left.localeCompare(right, "en"));
    for (const name of names) {
      const relative = relativeDirectory ? `${relativeDirectory}/${name}` : name;
      const current = path.join(directory, name);
      const metadata = await fs.lstat(current);
      if (metadata.isSymbolicLink()) {
        throw new Error(`Portable delivery contains a symbolic link or junction: ${relative}`);
      }
      if (metadata.isDirectory()) {
        directories.push(relative);
        await visit(current, relative);
      } else if (metadata.isFile()) {
        files.push(relative);
      } else {
        throw new Error(`Portable delivery contains an unsupported filesystem entry: ${relative}`);
      }
    }
  };
  await visit(root);
  return { files, directories };
};

const assertTreeAllowlist = async (root, {
  allowedFiles,
  allowedDirectories = EXPECTED_DIRECTORIES,
  exact = true,
}) => {
  const tree = await scanPlainTree(root);
  const allowedFileSet = new Set(allowedFiles);
  const allowedDirectorySet = new Set(allowedDirectories);
  for (const file of tree.files) {
    if (!allowedFileSet.has(file)) throw new Error(`Portable delivery contains an unexpected file: ${file}`);
  }
  for (const directory of tree.directories) {
    if (!allowedDirectorySet.has(directory)) {
      throw new Error(`Portable delivery contains an unexpected directory: ${directory}`);
    }
  }
  if (exact) {
    for (const file of allowedFileSet) {
      if (!tree.files.includes(file)) throw new Error(`Portable delivery is missing ${file}`);
    }
    for (const directory of allowedDirectorySet) {
      if (!tree.directories.includes(directory)) {
        throw new Error(`Portable delivery is missing ${directory}`);
      }
    }
  }
  return tree;
};

const assertManifestShape = (manifest, nativeHashes) => {
  if (
    !manifest
    || manifest.format !== PORTABLE_FORMAT
    || manifest.platform !== "windows"
    || manifest.architecture !== "x86_64"
    || manifest.resourceRoot !== "."
    || !Array.isArray(manifest.files)
    || manifest.files.length !== EXPECTED_FILES.length
    || !Array.isArray(manifest.nativeClients)
    || manifest.nativeClients.length !== 2
  ) {
    throw new Error("Portable delivery manifest is invalid");
  }
  for (let index = 0; index < EXPECTED_FILES.length; index += 1) {
    const file = manifest.files[index];
    const source = WINDOWS_FILES[index];
    if (
      !file
      || file.path !== EXPECTED_FILES[index]
      || !Number.isSafeInteger(file.bytes)
      || file.bytes < 0
      || typeof file.sha256 !== "string"
      || !/^[A-F0-9]{64}$/.test(file.sha256)
      || file.executable !== (source.executable === true)
    ) {
      throw new Error("Portable delivery manifest contains an invalid file entry");
    }
  }
  const expectedClients = [
    ["mosh", WINDOWS_X64_NATIVE_CLIENTS.mosh.release, nativeHashes.mosh],
    ["et", WINDOWS_X64_NATIVE_CLIENTS.et.release, nativeHashes.et],
  ];
  for (let index = 0; index < expectedClients.length; index += 1) {
    const [name, release, sha256] = expectedClients[index];
    const client = manifest.nativeClients[index];
    if (!client || client.name !== name || client.release !== release || client.sha256 !== sha256) {
      throw new Error("Portable delivery manifest contains an invalid native-client lock");
    }
  }
};

const verifyDelivery = async (root, nativeHashes, expectedManifest = null) => {
  await assertTreeAllowlist(root, {
    allowedFiles: [...EXPECTED_FILES, MANIFEST_NAME],
  });
  const manifestPath = path.join(root, MANIFEST_NAME);
  const rawManifest = await fs.readFile(manifestPath, "utf8");
  let manifest;
  try {
    manifest = JSON.parse(rawManifest);
  } catch {
    throw new Error("Portable delivery manifest is not valid JSON");
  }
  assertManifestShape(manifest, nativeHashes);
  if (expectedManifest) {
    const expectedText = `${JSON.stringify(expectedManifest, null, 2)}\n`;
    if (rawManifest !== expectedText) throw new Error("Portable delivery manifest is not deterministic");
  }
  for (let index = 0; index < WINDOWS_FILES.length; index += 1) {
    const definition = WINDOWS_FILES[index];
    const manifestFile = manifest.files[index];
    const filePath = path.join(root, ...definition.destination.split("/"));
    const metadata = await fs.lstat(filePath);
    if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.size !== manifestFile.bytes) {
      throw new Error(`Portable delivery file metadata mismatch: ${definition.destination}`);
    }
    if (await digestFile(filePath) !== manifestFile.sha256) {
      throw new Error(`Portable delivery file hash mismatch: ${definition.destination}`);
    }
    if (definition.executable) {
      await assertWindowsX64Pe(filePath, `Portable ${path.basename(definition.destination)}`);
    }
    if (definition.nativeClient && manifestFile.sha256 !== nativeHashes[definition.nativeClient]) {
      throw new Error(`Portable ${definition.nativeClient} client does not match its lock`);
    }
    if (definition.versionManifest) {
      const version = (await fs.readFile(filePath, "utf8")).trim();
      if (version !== WINDOWS_X64_NATIVE_CLIENTS.mosh.version) {
        throw new Error("Portable Mosh version manifest does not match the locked release");
      }
    }
  }
  return { manifest, rawManifest };
};

const copyVerifiedFile = async (entry, stageRoot) => {
  const destination = path.join(stageRoot, ...entry.destination.split("/"));
  await fs.mkdir(path.dirname(destination), { recursive: true });
  await fs.copyFile(entry.source, destination, fsConstants.COPYFILE_EXCL);
  const metadata = await fs.lstat(destination);
  if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.size !== entry.bytes) {
    throw new Error(`Staged portable file metadata mismatch: ${entry.destination}`);
  }
  if (await digestFile(destination) !== entry.sha256) {
    throw new Error(`Staged portable file hash mismatch: ${entry.destination}`);
  }
  if (entry.executable) {
    await assertWindowsX64Pe(destination, `Staged ${path.basename(entry.destination)}`);
  }
};

const safeRemoveGeneratedTree = async (root, { partial = false } = {}) => {
  await assertTreeAllowlist(root, {
    allowedFiles: partial ? STAGE_ALLOWED_FILES : [...EXPECTED_FILES, MANIFEST_NAME],
    exact: !partial,
  });
  await fs.rm(root, { recursive: true, force: false });
};

const recoverInterruptedPublication = async ({ finalRoot, stageRoot, previousRoot, nativeHashes }) => {
  const previous = await lstatOrNull(previousRoot);
  const final = await lstatOrNull(finalRoot);
  if (previous) {
    if (previous.isSymbolicLink() || !previous.isDirectory()) {
      throw new Error("Portable previous delivery is not a plain directory");
    }
    await verifyDelivery(previousRoot, nativeHashes);
    if (!final) {
      await fs.rename(previousRoot, finalRoot);
    } else {
      if (final.isSymbolicLink() || !final.isDirectory()) {
        throw new Error("Portable delivery root is not a plain directory");
      }
      await verifyDelivery(finalRoot, nativeHashes);
      await safeRemoveGeneratedTree(previousRoot);
    }
  }

  const stage = await lstatOrNull(stageRoot);
  if (!stage) return;
  if (stage.isSymbolicLink() || !stage.isDirectory()) {
    throw new Error("Portable stage is not a plain directory");
  }
  const marker = await lstatOrNull(path.join(stageRoot, STAGE_MARKER));
  if (marker) {
    if (marker.isSymbolicLink() || !marker.isFile()) {
      throw new Error("Portable stage marker is invalid");
    }
    if (await fs.readFile(path.join(stageRoot, STAGE_MARKER), "utf8") !== STAGE_MARKER_BODY) {
      throw new Error("Portable stage marker is invalid");
    }
    await safeRemoveGeneratedTree(stageRoot, { partial: true });
  } else {
    await verifyDelivery(stageRoot, nativeHashes);
    await safeRemoveGeneratedTree(stageRoot);
  }
};

const publishStage = async ({
  finalRoot,
  stageRoot,
  previousRoot,
  nativeHashes,
  manifest,
  testHooks,
}) => {
  let movedPrevious = false;
  let publishedStage = false;
  try {
    const current = await lstatOrNull(finalRoot);
    if (current) {
      if (current.isSymbolicLink() || !current.isDirectory()) {
        throw new Error("Portable delivery root is not a plain directory");
      }
      await verifyDelivery(finalRoot, nativeHashes);
      if (await lstatOrNull(previousRoot)) {
        throw new Error("Portable previous delivery already exists");
      }
      await fs.rename(finalRoot, previousRoot);
      movedPrevious = true;
      await testHooks?.afterPreviousMoved?.();
    }

    await fs.rename(stageRoot, finalRoot);
    publishedStage = true;
    await testHooks?.afterStagePublished?.();
    await verifyDelivery(finalRoot, nativeHashes, manifest);

    if (movedPrevious) {
      await verifyDelivery(previousRoot, nativeHashes);
      await safeRemoveGeneratedTree(previousRoot);
      movedPrevious = false;
    }
  } catch (error) {
    let rollbackError = null;
    try {
      if (publishedStage && await lstatOrNull(finalRoot)) {
        await safeRemoveGeneratedTree(finalRoot);
        publishedStage = false;
      }
      if (movedPrevious && await lstatOrNull(previousRoot)) {
        await fs.rename(previousRoot, finalRoot);
        movedPrevious = false;
      }
    } catch (rollback) {
      rollbackError = rollback;
    }
    if (rollbackError) {
      throw new Error(`Portable publish failed and rollback was incomplete: ${rollbackError.message}`, {
        cause: error,
      });
    }
    throw error;
  }
};

export const packageWindowsPortable = async ({
  projectRoot = PROJECT_ROOT,
  platform = process.platform,
  architecture = process.arch,
  outputRoot = DELIVERY_ROOT,
  nativeClientHashes,
  _testHooks: testHooks,
} = {}) => {
  if (platform !== "win32") {
    throw new Error("The unpackaged portable layout is currently verified only on Windows");
  }
  if (architecture !== "x64") {
    throw new Error("The unpackaged portable layout is currently verified only for Windows x64");
  }

  const resolvedRoot = path.resolve(projectRoot);
  await assertPlainDirectory(resolvedRoot, "Project root");
  const nativeHashes = normalizeNativeHashes(nativeClientHashes);

  // Validate every source before creating or touching the delivery base.
  const inspected = await inspectSourceFiles(resolvedRoot, nativeHashes);
  const manifest = buildManifest(inspected, nativeHashes);
  const manifestText = `${JSON.stringify(manifest, null, 2)}\n`;

  const output = assertContainedRelativePath(resolvedRoot, outputRoot, "Portable output root");
  const outputRelative = portablePath(output.relative);
  const outputBaseRelative = portablePath(path.dirname(output.relative));
  const outputBase = await ensurePlainDirectoryBelow(
    resolvedRoot,
    outputBaseRelative,
    "Portable output base",
  );
  const finalRoot = output.resolved;
  if (path.dirname(finalRoot) !== outputBase) {
    throw new Error("Portable output root must be a direct child of its managed output base");
  }
  const stageRoot = path.join(outputBase, STAGE_NAME);
  const previousRoot = path.join(outputBase, PREVIOUS_NAME);

  await recoverInterruptedPublication({ finalRoot, stageRoot, previousRoot, nativeHashes });

  let stageOwned = false;
  try {
    await fs.mkdir(stageRoot);
    stageOwned = true;
    await fs.writeFile(path.join(stageRoot, STAGE_MARKER), STAGE_MARKER_BODY, { flag: "wx" });

    const desktop = inspected.at(-1);
    if (!desktop?.desktopExecutable) throw new Error("Portable desktop executable order is invalid");
    for (const entry of inspected.slice(0, -1)) {
      await copyVerifiedFile(entry, stageRoot);
      await testHooks?.afterStagedFile?.(entry.destination);
    }
    await fs.writeFile(path.join(stageRoot, MANIFEST_NAME), manifestText, { flag: "wx" });
    await testHooks?.afterStagedFile?.(MANIFEST_NAME);

    // The desktop executable is the final staged file by contract.
    await copyVerifiedFile(desktop, stageRoot);
    await testHooks?.afterStagedFile?.(desktop.destination);
    await fs.rm(path.join(stageRoot, STAGE_MARKER));
    await verifyDelivery(stageRoot, nativeHashes, manifest);

    await publishStage({
      finalRoot,
      stageRoot,
      previousRoot,
      nativeHashes,
      manifest,
      testHooks,
    });
    stageOwned = false;
  } catch (error) {
    if (stageOwned && await lstatOrNull(stageRoot)) {
      await safeRemoveGeneratedTree(stageRoot, { partial: true }).catch(() => {});
    }
    throw error;
  }

  const verified = await verifyDelivery(finalRoot, nativeHashes, manifest);
  const manifestPath = `${outputRelative}/${MANIFEST_NAME}`;
  return Object.freeze({
    format: PORTABLE_FORMAT,
    resourceRoot: outputRelative,
    deliveryRoot: outputRelative,
    manifestPath,
    manifestSha256: crypto.createHash("sha256").update(verified.rawManifest).digest("hex").toUpperCase(),
    files: Object.freeze(manifest.files.map((entry) => Object.freeze({
      ...entry,
      path: `${outputRelative}/${entry.path}`,
    }))),
  });
};

const isMain = process.argv[1]
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
  packageWindowsPortable()
    .then((manifest) => process.stdout.write(`${JSON.stringify(manifest, null, 2)}\n`))
    .catch((error) => {
      process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
      process.exitCode = 1;
    });
}
