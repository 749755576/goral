import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  WINDOWS_X64_NATIVE_CLIENTS,
  packageWindowsPortable,
} from "./package-portable.mjs";

const DELIVERY_RELATIVE = "output/portable/windows-x64";
const DELIVERY_FILES = Object.freeze([
  "LICENSE",
  "NOTICE.md",
  "THIRD_PARTY_NOTICES.md",
  "licenses/Inter-OFL-1.1.txt",
  "licenses/Simple-Icons-CC0-1.0.txt",
  "licenses/portable-pty-MIT.txt",
  "SOURCE.md",
  "NATIVE_CLIENTS.md",
  "mosh/moshcatty.version",
  "mosh/mosh-client.exe",
  "et/et.exe",
  "Goral.exe",
]);

test("the portable release entry point performs a formal Tauri build before publication", async () => {
  const packageJson = JSON.parse(await fs.readFile(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(
    packageJson.scripts["package:portable"],
    "npm.cmd run tauri:build && node scripts/package-portable.mjs",
  );
});

const digest = (body) => crypto.createHash("sha256").update(body).digest("hex").toUpperCase();

const executable = (tag, machine = 0x8664) => {
  const payload = Buffer.from(tag, "utf8");
  const body = Buffer.alloc(128 + payload.length);
  body.write("MZ", 0, "ascii");
  body.writeUInt32LE(0x40, 0x3c);
  body.write("PE\0\0", 0x40, "binary");
  body.writeUInt16LE(machine, 0x44);
  payload.copy(body, 0x50);
  return body;
};

const writeFixtureFile = async (root, relativePath, body) => {
  const filePath = path.join(root, ...relativePath.split("/"));
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, body);
};

const makeFixture = async ({ legacyOutput = true } = {}) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "netcatty-portable-v2-test-"));
  const bodies = {
    desktop: executable("desktop-v1"),
    mosh: executable("mosh-v1"),
    et: executable("et-v1"),
    version: Buffer.from("0.1.8\n"),
    notices: Buffer.from("native notices\n"),
    license: Buffer.from("GPL-3.0-or-later\n"),
    notice: Buffer.from("Goral notices\n"),
    thirdParty: Buffer.from("Third-party notices\n"),
    interLicense: Buffer.from("Inter OFL-1.1 license and copyright\n"),
    simpleIconsLicense: Buffer.from("Simple Icons CC0-1.0 license and copyright\n"),
    portablePtyLicense: Buffer.from("portable-pty MIT license and copyright\n"),
    source: Buffer.from("Corresponding source\n"),
  };
  await writeFixtureFile(root, "LICENSE", bodies.license);
  await writeFixtureFile(root, "NOTICE.md", bodies.notice);
  await writeFixtureFile(root, "THIRD_PARTY_NOTICES.md", bodies.thirdParty);
  await writeFixtureFile(root, "licenses/Inter-OFL-1.1.txt", bodies.interLicense);
  await writeFixtureFile(root, "licenses/Simple-Icons-CC0-1.0.txt", bodies.simpleIconsLicense);
  await writeFixtureFile(root, "licenses/portable-pty-MIT.txt", bodies.portablePtyLicense);
  await writeFixtureFile(root, "SOURCE.md", bodies.source);
  await writeFixtureFile(root, "target/release/goral-desktop.exe", bodies.desktop);
  await writeFixtureFile(root, "src-tauri/resources/mosh/mosh-client.exe", bodies.mosh);
  await writeFixtureFile(root, "src-tauri/resources/mosh/moshcatty.version", bodies.version);
  await writeFixtureFile(root, "src-tauri/resources/et/et.exe", bodies.et);
  await writeFixtureFile(root, "src-tauri/resources/README.md", bodies.notices);
  if (legacyOutput) {
    await writeFixtureFile(root, "output/Goral.exe", "legacy-desktop");
    await writeFixtureFile(root, "output/native-release.png", "legacy-evidence");
  }
  return {
    root,
    bodies,
    nativeClientHashes: Object.freeze({
      mosh: digest(bodies.mosh),
      et: digest(bodies.et),
    }),
  };
};

const packageFixture = (fixture, options = {}) => packageWindowsPortable({
  projectRoot: fixture.root,
  platform: "win32",
  architecture: "x64",
  nativeClientHashes: fixture.nativeClientHashes,
  ...options,
});

const deliveryPath = (fixture, relativePath = "") => path.join(
  fixture.root,
  ...DELIVERY_RELATIVE.split("/"),
  ...relativePath.split("/").filter(Boolean),
);

const readManifestText = (fixture) => fs.readFile(deliveryPath(fixture, "MANIFEST.json"), "utf8");

const readTree = async (root, relative = "") => {
  const files = [];
  const names = (await fs.readdir(root)).sort();
  for (const name of names) {
    const filePath = path.join(root, name);
    const fileRelative = relative ? `${relative}/${name}` : name;
    const metadata = await fs.lstat(filePath);
    if (metadata.isDirectory()) files.push(...await readTree(filePath, fileRelative));
    else files.push(fileRelative);
  }
  return files;
};

const cleanup = (context, fixture) => {
  context.after(() => fs.rm(fixture.root, { recursive: true, force: true }));
};

test("portable v2 publishes a clean independent runtime tree and writes the desktop executable last", async (context) => {
  const fixture = await makeFixture();
  cleanup(context, fixture);
  const staged = [];

  const result = await packageFixture(fixture, {
    _testHooks: {
      afterStagedFile: (file) => staged.push(file),
    },
  });

  assert.equal(result.format, "goral-windows-portable-v2");
  assert.equal(result.resourceRoot, DELIVERY_RELATIVE);
  assert.equal(result.deliveryRoot, DELIVERY_RELATIVE);
  assert.equal(result.manifestPath, `${DELIVERY_RELATIVE}/MANIFEST.json`);
  assert.match(result.manifestSha256, /^[A-F0-9]{64}$/);
  assert.deepEqual(
    result.files.map((entry) => entry.path),
    DELIVERY_FILES.map((file) => `${DELIVERY_RELATIVE}/${file}`),
  );
  assert.deepEqual(staged, [
    "LICENSE",
    "NOTICE.md",
    "THIRD_PARTY_NOTICES.md",
    "licenses/Inter-OFL-1.1.txt",
    "licenses/Simple-Icons-CC0-1.0.txt",
    "licenses/portable-pty-MIT.txt",
    "SOURCE.md",
    "NATIVE_CLIENTS.md",
    "mosh/moshcatty.version",
    "mosh/mosh-client.exe",
    "et/et.exe",
    "MANIFEST.json",
    "Goral.exe",
  ]);
  assert.deepEqual(
    await readTree(deliveryPath(fixture)),
    [
      "Goral.exe",
      "LICENSE",
      "MANIFEST.json",
      "NATIVE_CLIENTS.md",
      "NOTICE.md",
      "SOURCE.md",
      "THIRD_PARTY_NOTICES.md",
      "et/et.exe",
      "licenses/Inter-OFL-1.1.txt",
      "licenses/Simple-Icons-CC0-1.0.txt",
      "licenses/portable-pty-MIT.txt",
      "mosh/mosh-client.exe",
      "mosh/moshcatty.version",
    ],
  );
  assert.deepEqual(await fs.readFile(deliveryPath(fixture, "Goral.exe")), fixture.bodies.desktop);
  assert.equal(await fs.readFile(path.join(fixture.root, "output/Goral.exe"), "utf8"), "legacy-desktop");
  assert.equal(await fs.readFile(path.join(fixture.root, "output/native-release.png"), "utf8"), "legacy-evidence");
  await assert.rejects(fs.lstat(path.join(fixture.root, "output/portable/.windows-x64.stage")), /ENOENT/);
  await assert.rejects(fs.lstat(path.join(fixture.root, "output/portable/.windows-x64.previous")), /ENOENT/);
});

test("MANIFEST.json is deterministic, relative, and verifies every delivered file", async (context) => {
  const first = await makeFixture({ legacyOutput: false });
  const second = await makeFixture({ legacyOutput: false });
  cleanup(context, first);
  cleanup(context, second);
  await fs.utimes(
    path.join(second.root, "target/release/goral-desktop.exe"),
    new Date("2030-01-01T00:00:00Z"),
    new Date("2030-01-01T00:00:00Z"),
  );

  const firstResult = await packageFixture(first);
  const secondResult = await packageFixture(second);
  const firstText = await readManifestText(first);
  const secondText = await readManifestText(second);
  assert.equal(firstText, secondText);
  assert.equal(firstResult.manifestSha256, secondResult.manifestSha256);

  const manifest = JSON.parse(firstText);
  assert.deepEqual(
    {
      format: manifest.format,
      platform: manifest.platform,
      architecture: manifest.architecture,
      resourceRoot: manifest.resourceRoot,
    },
    {
      format: "goral-windows-portable-v2",
      platform: "windows",
      architecture: "x86_64",
      resourceRoot: ".",
    },
  );
  assert.ok(!/[A-Z]:\\|netcatty-portable-v2-test-|generatedAt|timestamp|pid/i.test(firstText));
  assert.deepEqual(manifest.files.map((entry) => entry.path), DELIVERY_FILES);
  for (const entry of manifest.files) {
    const body = await fs.readFile(deliveryPath(first, entry.path));
    assert.equal(entry.bytes, body.length);
    assert.equal(entry.sha256, digest(body));
  }
});

test("production native-client locks are exact and uppercase", () => {
  assert.deepEqual(WINDOWS_X64_NATIVE_CLIENTS, {
    mosh: {
      release: "moshcatty-0.1.8",
      version: "0.1.8",
      sha256: "E44616A22038F1742F765C7DE553796BA4D1698F2C1F7A7CFB0DAFD33ECDC78A",
    },
    et: {
      release: "et-bin-6.2.10-1",
      sha256: "6212E2C089CD55AA9455DC2A9DE22AC83D0BC6C8AF76CE9AD096668931EE5A25",
    },
  });
});

test("tampered native clients fail locked SHA-256 checks without replacing the delivery", async (context) => {
  const fixture = await makeFixture();
  cleanup(context, fixture);
  await packageFixture(fixture);
  const before = await readManifestText(fixture);

  for (const relative of [
    "src-tauri/resources/mosh/mosh-client.exe",
    "src-tauri/resources/et/et.exe",
  ]) {
    const original = await fs.readFile(path.join(fixture.root, ...relative.split("/")));
    const tampered = Buffer.from(original);
    tampered[tampered.length - 1] ^= 0xff;
    await fs.writeFile(path.join(fixture.root, ...relative.split("/")), tampered);
    await assert.rejects(packageFixture(fixture), /locked SHA-256/);
    assert.equal(await readManifestText(fixture), before);
    await fs.writeFile(path.join(fixture.root, ...relative.split("/")), original);
  }
});

test("Mosh version mismatch fails before touching the current delivery", async (context) => {
  const fixture = await makeFixture();
  cleanup(context, fixture);
  await packageFixture(fixture);
  const before = await readManifestText(fixture);
  await fs.writeFile(
    path.join(fixture.root, "src-tauri/resources/mosh/moshcatty.version"),
    "0.1.7\n",
  );
  await assert.rejects(packageFixture(fixture), /version manifest/);
  assert.equal(await readManifestText(fixture), before);
});

test("non-PE and non-x64 executables are rejected before publication", async (context) => {
  const fixture = await makeFixture();
  cleanup(context, fixture);

  await fs.writeFile(path.join(fixture.root, "target/release/goral-desktop.exe"), "not-pe");
  await assert.rejects(packageFixture(fixture), /Windows PE executable/);
  await fs.writeFile(
    path.join(fixture.root, "target/release/goral-desktop.exe"),
    executable("arm64-desktop", 0xaa64),
  );
  await assert.rejects(packageFixture(fixture), /not an x86-64/);
  await assert.rejects(
    packageFixture(fixture, { architecture: "arm64" }),
    /only for Windows x64/,
  );
  await assert.rejects(fs.lstat(deliveryPath(fixture)), /ENOENT/);
});

test("a non-x64 native client fails PE validation before its hash check", async (context) => {
  const fixture = await makeFixture();
  cleanup(context, fixture);
  await fs.writeFile(
    path.join(fixture.root, "src-tauri/resources/mosh/mosh-client.exe"),
    executable("arm64-mosh", 0xaa64),
  );
  await assert.rejects(packageFixture(fixture), /not an x86-64/);
  await assert.rejects(fs.lstat(deliveryPath(fixture)), /ENOENT/);
});

test("symbolic links or junctions are rejected but Cargo-style hard links remain valid", async (context) => {
  const fixture = await makeFixture({ legacyOutput: false });
  cleanup(context, fixture);
  const desktop = path.join(fixture.root, "target/release/goral-desktop.exe");
  const hardLinkSource = path.join(fixture.root, "target/release/goral-desktop-deps.exe");
  await fs.rename(desktop, hardLinkSource);
  await fs.link(hardLinkSource, desktop);
  await packageFixture(fixture);

  const mosh = path.join(fixture.root, "src-tauri/resources/mosh/mosh-client.exe");
  const realMosh = path.join(fixture.root, "src-tauri/resources/mosh/mosh-client-real.exe");
  await fs.rename(mosh, realMosh);
  try {
    await fs.symlink(realMosh, mosh, "file");
  } catch (error) {
    if (error?.code === "EPERM") {
      const moshDirectory = path.dirname(mosh);
      const realMoshDirectory = `${moshDirectory}-real`;
      await fs.rename(moshDirectory, realMoshDirectory);
      await fs.symlink(realMoshDirectory, moshDirectory, "junction");
    } else {
      throw error;
    }
  }
  await assert.rejects(packageFixture(fixture), /symbolic link or junction/);
});

test("source directory junctions are rejected", async (context) => {
  const fixture = await makeFixture({ legacyOutput: false });
  cleanup(context, fixture);
  const mosh = path.join(fixture.root, "src-tauri/resources/mosh");
  const realMosh = path.join(fixture.root, "src-tauri/resources/mosh-real");
  await fs.rename(mosh, realMosh);
  await fs.symlink(realMosh, mosh, "junction");
  await assert.rejects(packageFixture(fixture), /symbolic link or junction/);
  await assert.rejects(fs.lstat(deliveryPath(fixture)), /ENOENT/);
});

test("a delivery-root junction is rejected without writing through it", async (context) => {
  const fixture = await makeFixture({ legacyOutput: false });
  cleanup(context, fixture);
  const base = path.join(fixture.root, "output/portable");
  const outside = path.join(fixture.root, "outside-delivery");
  await fs.mkdir(base, { recursive: true });
  await fs.mkdir(outside);
  await fs.symlink(outside, path.join(base, "windows-x64"), "junction");

  await assert.rejects(packageFixture(fixture), /plain directory/);
  assert.deepEqual(await fs.readdir(outside), []);
});

test("missing sources preserve an existing complete delivery", async (context) => {
  const fixture = await makeFixture();
  cleanup(context, fixture);
  await packageFixture(fixture);
  const before = await readManifestText(fixture);
  await fs.rm(path.join(fixture.root, "src-tauri/resources/et/et.exe"));

  await assert.rejects(packageFixture(fixture), /missing/);
  assert.equal(await readManifestText(fixture), before);
  await assert.rejects(fs.lstat(path.join(fixture.root, "output/portable/.windows-x64.stage")), /ENOENT/);
});

test("a staging failure leaves the old delivery intact and removes only its private stage", async (context) => {
  const fixture = await makeFixture();
  cleanup(context, fixture);
  await packageFixture(fixture);
  const oldDesktop = await fs.readFile(deliveryPath(fixture, "Goral.exe"));
  await fs.writeFile(
    path.join(fixture.root, "target/release/goral-desktop.exe"),
    executable("desktop-v2"),
  );

  await assert.rejects(
    packageFixture(fixture, {
      _testHooks: {
        afterStagedFile(file) {
          if (file === "et/et.exe") throw new Error("injected stage failure");
        },
      },
    }),
    /injected stage failure/,
  );
  assert.deepEqual(await fs.readFile(deliveryPath(fixture, "Goral.exe")), oldDesktop);
  await assert.rejects(fs.lstat(path.join(fixture.root, "output/portable/.windows-x64.stage")), /ENOENT/);
});

test("publish rollback restores the previous directory before and after the staged rename", async (context) => {
  const fixture = await makeFixture();
  cleanup(context, fixture);
  await packageFixture(fixture);
  const oldDesktop = await fs.readFile(deliveryPath(fixture, "Goral.exe"));
  await fs.writeFile(
    path.join(fixture.root, "target/release/goral-desktop.exe"),
    executable("desktop-v2"),
  );

  for (const hook of ["afterPreviousMoved", "afterStagePublished"]) {
    await assert.rejects(
      packageFixture(fixture, {
        _testHooks: {
          [hook]() {
            throw new Error(`injected ${hook} failure`);
          },
        },
      }),
      new RegExp(`injected ${hook} failure`),
    );
    assert.deepEqual(await fs.readFile(deliveryPath(fixture, "Goral.exe")), oldDesktop);
    await assert.rejects(fs.lstat(path.join(fixture.root, "output/portable/.windows-x64.stage")), /ENOENT/);
    await assert.rejects(fs.lstat(path.join(fixture.root, "output/portable/.windows-x64.previous")), /ENOENT/);
  }
});

test("a successful update replaces the whole managed tree without carrying stale files", async (context) => {
  const fixture = await makeFixture();
  cleanup(context, fixture);
  await packageFixture(fixture);
  const updated = executable("desktop-v2");
  await fs.writeFile(path.join(fixture.root, "target/release/goral-desktop.exe"), updated);
  await packageFixture(fixture);

  assert.deepEqual(await fs.readFile(deliveryPath(fixture, "Goral.exe")), updated);
  assert.equal((await readTree(deliveryPath(fixture))).length, DELIVERY_FILES.length + 1);
  await assert.rejects(fs.lstat(path.join(fixture.root, "output/portable/.windows-x64.previous")), /ENOENT/);
});

test("interrupted previous and partial-stage states recover before the next publication", async (context) => {
  const fixture = await makeFixture();
  cleanup(context, fixture);
  await packageFixture(fixture);
  const base = path.join(fixture.root, "output/portable");
  const final = path.join(base, "windows-x64");
  const previous = path.join(base, ".windows-x64.previous");
  const stage = path.join(base, ".windows-x64.stage");

  await fs.rename(final, previous);
  await fs.mkdir(stage);
  await fs.writeFile(
    path.join(stage, ".goral-portable-stage-v2"),
    "goral-windows-portable-v2-stage\n",
  );
  await fs.writeFile(path.join(stage, "NATIVE_CLIENTS.md"), "partial");
  const updated = executable("desktop-after-recovery");
  await fs.writeFile(path.join(fixture.root, "target/release/goral-desktop.exe"), updated);

  await packageFixture(fixture);
  assert.deepEqual(await fs.readFile(deliveryPath(fixture, "Goral.exe")), updated);
  await assert.rejects(fs.lstat(previous), /ENOENT/);
  await assert.rejects(fs.lstat(stage), /ENOENT/);
});

test("an unmanaged or contaminated final directory fails closed and is not deleted", async (context) => {
  const fixture = await makeFixture({ legacyOutput: false });
  cleanup(context, fixture);
  await fs.mkdir(deliveryPath(fixture), { recursive: true });
  await fs.writeFile(deliveryPath(fixture, "user-file.txt"), "do-not-delete");

  await assert.rejects(packageFixture(fixture), /unexpected file|missing/);
  assert.equal(await fs.readFile(deliveryPath(fixture, "user-file.txt"), "utf8"), "do-not-delete");
  await assert.rejects(fs.lstat(path.join(fixture.root, "output/portable/.windows-x64.stage")), /ENOENT/);
});
