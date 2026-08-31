export const HOST_DISTRO_ASSETS = {
  ubuntu: "/distro/ubuntu.svg",
  debian: "/distro/debian.svg",
  centos: "/distro/centos.svg",
  rocky: "/distro/rocky.svg",
  fedora: "/distro/fedora.svg",
  arch: "/distro/arch.svg",
  alpine: "/distro/alpine.svg",
  amazon: "/distro/amazon.svg",
  opensuse: "/distro/opensuse.svg",
  redhat: "/distro/redhat.svg",
  oracle: "/distro/oracle.svg",
  kali: "/distro/kali.svg",
  almalinux: "/distro/almalinux.svg",
  alinux: "/distro/alinux.svg",
  openeuler: "/distro/openeuler.svg",
  macos: "/distro/macos.svg",
  freebsd: "/distro/freebsd.svg",
  windows: "/distro/windows.svg",
  linux: "/distro/linux.svg",
  cisco: "/distro/cisco.svg",
  juniper: "/distro/juniper.svg",
  huawei: "/distro/huawei.svg",
  h3c: "/distro/h3c.svg",
  hpe: "/distro/hpe.svg",
  mikrotik: "/distro/mikrotik.svg",
  fortinet: "/distro/fortinet.svg",
  paloalto: "/distro/paloalto.svg",
  zyxel: "/distro/zyxel.svg",
} as const;

export type HostDistroId = keyof typeof HOST_DISTRO_ASSETS;

export const HOST_DISTRO_COLORS: Readonly<Record<HostDistroId, string>> = {
  ubuntu: "#E95420",
  debian: "#A81D33",
  centos: "#9C27B0",
  rocky: "#0B9B69",
  fedora: "#3C6EB4",
  arch: "#1793D1",
  alpine: "#0D597F",
  amazon: "#FF9900",
  opensuse: "#73BA25",
  redhat: "#EE0000",
  oracle: "#C74634",
  kali: "#0F6DB3",
  almalinux: "#173B66",
  alinux: "#FF6A00",
  openeuler: "#002FA7",
  macos: "#333333",
  freebsd: "#AB2B28",
  windows: "#0078D4",
  linux: "#333333",
  cisco: "#1BA0D7",
  juniper: "#0A6EB4",
  huawei: "#CF0A2C",
  h3c: "#FFFFFF",
  hpe: "#01A982",
  mikrotik: "#293239",
  fortinet: "#EE3124",
  paloalto: "#FA582D",
  zyxel: "#00497A",
};

export const HOST_ICON_IDS = [
  "server",
  "terminal",
  "database",
  "cloud",
  "router",
  "shield",
  "code",
  "box",
  "globe",
  "cpu",
  "hard-drive",
  "network",
  "wifi",
  "lock",
  "key",
  "monitor",
  "container",
  "activity",
  "zap",
  "server-cog",
] as const;

export type HostIconId = (typeof HOST_ICON_IDS)[number];

export const HOST_ICON_COLORS = {
  blue: "#2563EB",
  green: "#16A34A",
  red: "#DC2626",
  amber: "#B45309",
  purple: "#9333EA",
  cyan: "#0891B2",
  orange: "#EA580C",
  slate: "#475569",
  violet: "#7C3AED",
  pink: "#DB2777",
  rose: "#E11D48",
  lime: "#65A30D",
  teal: "#0D9488",
  sky: "#0284C7",
  indigo: "#4F46E5",
  zinc: "#52525B",
} as const;

export type HostIconColorId = keyof typeof HOST_ICON_COLORS;

export const HOST_ICON_DEFAULT_COLORS: Readonly<Record<HostIconId, HostIconColorId>> = {
  server: "blue",
  terminal: "slate",
  database: "cyan",
  cloud: "sky",
  router: "orange",
  shield: "green",
  code: "violet",
  box: "amber",
  globe: "teal",
  cpu: "indigo",
  "hard-drive": "zinc",
  network: "lime",
  wifi: "purple",
  lock: "rose",
  key: "amber",
  monitor: "sky",
  container: "teal",
  activity: "red",
  zap: "orange",
  "server-cog": "slate",
};

export type HostVisual = {
  os: "linux" | "windows" | "macos" | null;
  distro: string | null;
  distroMode: "auto" | "manual" | null;
  manualDistro: string | null;
  iconMode: "auto" | "custom" | null;
  iconId: HostIconId | null;
  iconColorMode: "auto" | "manual" | null;
  iconColor: HostIconColorId | null;
  iconColorCustom: string | null;
};

export type HostVisualSource = Partial<{
  protocol: string | null;
  os: string | null;
  distro: string | null;
  distroMode: string | null;
  manualDistro: string | null;
  iconMode: string | null;
  iconId: string | null;
  iconColorMode: string | null;
  iconColor: string | null;
  iconColorCustom: string | null;
}>;

const NETWORK_DEVICE_IDS = new Set([
  "cisco",
  "juniper",
  "huawei",
  "h3c",
  "hpe",
  "mikrotik",
  "fortinet",
  "paloalto",
  "zyxel",
  // The legacy detector knows Ruijie, but the original asset catalog does not
  // ship a ruijie.svg. It therefore intentionally resolves to the fallback.
  "ruijie",
]);

export function normalizeDistroId(value: unknown): string {
  const distro = typeof value === "string" ? value.toLowerCase().trim() : "";
  if (!distro) return "";
  if (
    distro === "darwin" ||
    distro === "macos" ||
    distro === "mac os" ||
    distro === "mac os x" ||
    distro.includes("darwin kernel") ||
    distro.includes("macos") ||
    distro.includes("mac os")
  ) {
    return "macos";
  }
  if (distro.includes("freebsd")) return "freebsd";
  if (distro.includes("windows")) return "windows";
  if (distro.includes("ubuntu")) return "ubuntu";
  if (distro.includes("debian")) return "debian";
  if (distro.includes("centos")) return "centos";
  if (distro.includes("rocky")) return "rocky";
  if (distro.includes("fedora")) return "fedora";
  if (distro.includes("arch") || distro.includes("manjaro")) return "arch";
  if (distro.includes("alpine")) return "alpine";
  if (distro.includes("amzn") || distro.includes("amazon") || distro.includes("aws")) {
    return "amazon";
  }
  if (distro.includes("opensuse") || distro.includes("suse") || distro.includes("sles")) {
    return "opensuse";
  }
  if (distro.includes("red hat") || distro.includes("redhat") || distro.includes("rhel")) {
    return "redhat";
  }
  if (distro.includes("almalinux")) return "almalinux";
  if (distro.includes("oracle")) return "oracle";
  if (distro.includes("kali")) return "kali";
  if (distro.includes("openeuler") || distro.includes("open euler")) return "openeuler";
  if (
    distro.includes("alinux") ||
    distro.includes("aliyun") ||
    distro.includes("alibaba cloud")
  ) {
    return "alinux";
  }
  if (NETWORK_DEVICE_IDS.has(distro)) return distro;
  if (distro === "linux" || distro.includes("linux")) return "linux";
  return "";
}

export function getEffectiveHostDistro(host: HostVisualSource): string {
  const detected = normalizeDistroId(host.distro);
  const manual = normalizeDistroId(host.manualDistro);
  if (host.distroMode === "manual") return manual || detected;
  return detected;
}

export function isHostIconId(value: unknown): value is HostIconId {
  return typeof value === "string" && (HOST_ICON_IDS as readonly string[]).includes(value);
}

export function isHostIconColorId(value: unknown): value is HostIconColorId {
  return typeof value === "string" && Object.hasOwn(HOST_ICON_COLORS, value);
}

export function isHostIconCustomColor(value: unknown): value is string {
  return typeof value === "string" && /^#[0-9a-fA-F]{6}$/.test(value);
}

type ResolvedManualColor = {
  colorId?: HostIconColorId;
  colorHex: string;
};

export function resolveHostIconColor(host: HostVisualSource): ResolvedManualColor | null {
  const hasImplicitManualColor =
    host.iconColorMode !== "auto" &&
    (isHostIconColorId(host.iconColor) || isHostIconCustomColor(host.iconColorCustom));
  if (host.iconColorMode !== "manual" && !hasImplicitManualColor) return null;
  if (isHostIconCustomColor(host.iconColorCustom)) {
    return { colorHex: host.iconColorCustom };
  }
  const colorId = isHostIconColorId(host.iconColor) ? host.iconColor : "blue";
  return { colorId, colorHex: HOST_ICON_COLORS[colorId] };
}

export type ResolvedHostAvatar =
  | {
      kind: "serial";
      backgroundColor: string;
      iconId: "usb";
    }
  | {
      kind: "custom";
      backgroundColor: string;
      iconId: HostIconId;
    }
  | {
      kind: "distro";
      backgroundColor: string;
      distroId: HostDistroId;
      logoPath: string;
      preserveBrandColors: boolean;
    }
  | {
      kind: "fallback";
      backgroundColor: string;
      iconId: "server";
    };

export const FALLBACK_HOST_AVATAR: ResolvedHostAvatar = {
  kind: "fallback",
  // Matches the legacy `bg-primary` default (slate-900 in the stock theme),
  // while an explicitly selected custom Server icon still uses its blue
  // curated default above.
  backgroundColor: "#0F172A",
  iconId: "server",
};

export function resolveHostAvatar(host: HostVisualSource): ResolvedHostAvatar {
  if (host.protocol === "serial") {
    return { kind: "serial", backgroundColor: "#D97706", iconId: "usb" };
  }

  const manualColor = resolveHostIconColor(host);
  if (host.iconMode === "custom" && isHostIconId(host.iconId)) {
    const defaultColor = HOST_ICON_DEFAULT_COLORS[host.iconId];
    return {
      kind: "custom",
      backgroundColor: manualColor?.colorHex ?? HOST_ICON_COLORS[defaultColor],
      iconId: host.iconId,
    };
  }

  const effectiveDistro = getEffectiveHostDistro(host);
  if (Object.hasOwn(HOST_DISTRO_ASSETS, effectiveDistro)) {
    const distroId = effectiveDistro as HostDistroId;
    return {
      kind: "distro",
      backgroundColor: manualColor?.colorHex ?? HOST_DISTRO_COLORS[distroId],
      distroId,
      logoPath: HOST_DISTRO_ASSETS[distroId],
      preserveBrandColors: distroId === "h3c",
    };
  }

  return FALLBACK_HOST_AVATAR;
}
