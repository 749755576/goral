import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import test from "node:test";

import {
  HOST_DISTRO_ASSETS,
  HOST_ICON_COLORS,
  getEffectiveHostDistro,
  normalizeDistroId,
  resolveHostAvatar,
  resolveHostIconColor,
} from "../../src/hostVisual.ts";

const avatarUrl = new URL("../../src/HostAvatar.tsx", import.meta.url);
const distroDirectoryUrl = new URL("../../public/distro/", import.meta.url);

test("legacy distro aliases resolve to the original asset IDs", () => {
  assert.equal(normalizeDistroId("Ubuntu 24.04 LTS"), "ubuntu");
  assert.equal(normalizeDistroId("Amazon Linux 2023 (amzn)"), "amazon");
  assert.equal(normalizeDistroId("Alibaba Cloud Linux 3 / alinux"), "alinux");
  assert.equal(normalizeDistroId("Darwin Kernel Version 23"), "macos");
  assert.equal(normalizeDistroId("Windows Server 2025"), "windows");
  assert.equal(normalizeDistroId("huawei"), "huawei");
  assert.equal(normalizeDistroId("not-a-known-system"), "");
});

test("manual distro mode overrides detection and safely falls back to detection", () => {
  assert.equal(
    getEffectiveHostDistro({
      distro: "Ubuntu",
      distroMode: "manual",
      manualDistro: "Rocky Linux",
    }),
    "rocky",
  );
  assert.equal(
    getEffectiveHostDistro({
      distro: "Ubuntu",
      distroMode: "manual",
      manualDistro: "unknown custom value",
    }),
    "ubuntu",
  );
  assert.equal(
    getEffectiveHostDistro({ distro: "Debian", distroMode: "auto", manualDistro: "Fedora" }),
    "debian",
  );
});

test("serial, custom icon, distro, and fallback precedence matches legacy Netcatty", () => {
  assert.deepEqual(
    resolveHostAvatar({
      protocol: "serial",
      distro: "ubuntu",
      iconMode: "custom",
      iconId: "database",
    }),
    { kind: "serial", backgroundColor: "#D97706", iconId: "usb" },
  );

  assert.deepEqual(
    resolveHostAvatar({
      distro: "ubuntu",
      iconMode: "custom",
      iconId: "database",
    }),
    { kind: "custom", backgroundColor: HOST_ICON_COLORS.cyan, iconId: "database" },
  );

  assert.deepEqual(resolveHostAvatar({ distro: "Ubuntu 24.04" }), {
    kind: "distro",
    backgroundColor: "#E95420",
    distroId: "ubuntu",
    logoPath: "/distro/ubuntu.svg",
    preserveBrandColors: false,
  });

  assert.deepEqual(resolveHostAvatar({ distro: "ruijie" }), {
    kind: "fallback",
    backgroundColor: "#0F172A",
    iconId: "server",
  });
  assert.equal(resolveHostAvatar({}).kind, "fallback");
});

test("legacy manual color semantics apply to custom icons and distro tiles", () => {
  assert.deepEqual(
    resolveHostIconColor({ iconColorMode: "manual", iconColor: "violet" }),
    { colorId: "violet", colorHex: "#7C3AED" },
  );
  assert.deepEqual(resolveHostIconColor({ iconColorCustom: "#12Ab34" }), {
    colorHex: "#12Ab34",
  });
  assert.equal(
    resolveHostIconColor({ iconColorMode: "auto", iconColorCustom: "#12Ab34" }),
    null,
  );

  const custom = resolveHostAvatar({
    iconMode: "custom",
    iconId: "router",
    iconColorMode: "manual",
    iconColor: "teal",
    iconColorCustom: "#123456",
  });
  assert.equal(custom.backgroundColor, "#123456");

  const distro = resolveHostAvatar({
    distro: "debian",
    iconColorMode: "manual",
    iconColor: "green",
  });
  assert.equal(distro.backgroundColor, HOST_ICON_COLORS.green);
});

test("all original distro SVG assets are present and mapped", async () => {
  const files = (await readdir(distroDirectoryUrl))
    .filter((name) => name.endsWith(".svg"))
    .sort();
  const mapped = Object.values(HOST_DISTRO_ASSETS)
    .map((path) => path.slice(path.lastIndexOf("/") + 1))
    .sort();

  assert.equal(files.length, 28);
  assert.deepEqual(files, mapped);
});

test("HostAvatar is self-contained, memoized, size-compatible, and asset-failure safe", async () => {
  const source = await readFile(avatarUrl, "utf8");
  assert.match(source, /export type HostAvatarSize = "xs" \| "sm" \| "md" \| "tree" \| "log" \| "lg"/);
  assert.match(source, /resolveHostAvatar\(host\)/);
  assert.match(source, /onError=\{\(\) => setFailedAsset\(resolvedKey\)\}/);
  assert.match(source, /\? FALLBACK_HOST_AVATAR/);
  assert.match(source, /data-host-avatar-kind=\{avatar\.kind\}/);
  assert.match(source, /export const HostAvatar = memo\(HostAvatarInner\)/);
  assert.doesNotMatch(source, /lucide-react|\.\/styles\.css/);
});
