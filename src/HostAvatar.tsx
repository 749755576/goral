import React, { memo, useEffect, useState } from "react";

import {
  FALLBACK_HOST_AVATAR,
  resolveHostAvatar,
  type HostIconId,
  type HostVisualSource,
  type ResolvedHostAvatar,
} from "./hostVisual";

export type HostAvatarSize = "xs" | "sm" | "md" | "tree" | "log" | "lg";

export type HostAvatarProps = {
  host: HostVisualSource;
  size?: HostAvatarSize;
  className?: string;
  style?: React.CSSProperties;
  ariaLabel?: string;
  title?: string;
};

const SIZE_METRICS: Readonly<
  Record<HostAvatarSize, { edge: number; radius: number; icon: number }>
> = {
  xs: { edge: 16, radius: 4, icon: 10 },
  sm: { edge: 20, radius: 5, icon: 12 },
  md: { edge: 32, radius: 8, icon: 16 },
  tree: { edge: 24, radius: 6, icon: 14 },
  log: { edge: 36, radius: 10, icon: 20 },
  lg: { edge: 44, radius: 12, icon: 20 },
};

type AvatarGlyphId = HostIconId | "usb";

const GLYPH_PATHS: Readonly<Record<AvatarGlyphId, readonly string[]>> = {
  server: [
    "M4 2h16a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2Z",
    "M4 14h16a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2v-4a2 2 0 0 1 2-2Z",
    "M6 6h.01M6 18h.01",
  ],
  terminal: ["m4 17 6-6-6-6", "M12 19h8"],
  database: [
    "M12 2c5 0 9 1.8 9 4s-4 4-9 4-9-1.8-9-4 4-4 9-4Z",
    "M3 6v6c0 2.2 4 4 9 4s9-1.8 9-4V6",
    "M3 12v6c0 2.2 4 4 9 4s9-1.8 9-4v-6",
  ],
  cloud: ["M17.5 19H7a5 5 0 1 1 1-9.9A7 7 0 0 1 21 12a4 4 0 0 1-3.5 7Z"],
  router: [
    "M3 13h18v7H3z",
    "M8.5 17h.01M5.5 17h.01M12 17h6",
    "M8 9a6 6 0 0 1 8 0M10 6a9 9 0 0 1 4 0",
  ],
  shield: ["M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"],
  code: ["m8 9-4 3 4 3", "m16 9 4 3-4 3", "m14 5-4 14"],
  box: ["m21 8-9 5-9-5 9-5 9 5Z", "M3 8v8l9 5 9-5V8", "M12 13v8"],
  globe: [
    "M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20Z",
    "M2 12h20",
    "M12 2a15 15 0 0 1 0 20M12 2a15 15 0 0 0 0 20",
  ],
  cpu: [
    "M7 7h10v10H7z",
    "M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3",
  ],
  "hard-drive": [
    "M22 12H2l3-8h14l3 8Z",
    "M2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6",
    "M6 16h.01M10 16h.01",
  ],
  network: [
    "M9 3h6v6H9zM3 15h6v6H3zM15 15h6v6h-6z",
    "M12 9v3M6 15v-3h12v3",
  ],
  wifi: [
    "M2 8.8a15 15 0 0 1 20 0",
    "M5 12.3a10 10 0 0 1 14 0",
    "M8.5 15.8a5 5 0 0 1 7 0",
    "M12 20h.01",
  ],
  lock: ["M5 10h14v12H5z", "M8 10V7a4 4 0 0 1 8 0v3"],
  key: [
    "M21 2l-2 2m-7.4 7.4a6 6 0 1 1-3-3L21 2l1 1-3 3 2 2-3 3-2-2-2.4 2.4Z",
  ],
  monitor: ["M2 3h20v14H2z", "M8 21h8M12 17v4"],
  container: [
    "M3 6h18v13H3z",
    "M7 6V3h4v3M13 6V3h4v3",
    "M7 10h.01M11 10h.01M15 10h.01M7 14h.01M11 14h.01M15 14h.01",
  ],
  activity: ["M3 12h4l3-9 4 18 3-9h4"],
  zap: ["M13 2 3 14h9l-1 8 10-12h-9l1-8Z"],
  "server-cog": [
    "M3 4a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V4Z",
    "M6 6h.01M7 18H5a2 2 0 0 1-2-2v-2",
    "M16 14.5a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7ZM16 12v2.5M16 21.5V24M12.1 13.6l1.8 1.8M18.1 20.6l1.8 1.8M10 18h2.5M19.5 18H22M12.1 22.4l1.8-1.8M18.1 15.4l1.8-1.8",
  ],
  usb: [
    "M12 2v14",
    "m9 5 3-3 3 3",
    "M5 10h4a3 3 0 0 1 3 3v3",
    "M19 10h-4a3 3 0 0 0-3 3",
    "M5 8v4M17 8h4v4h-4zM10 20a2 2 0 1 0 4 0 2 2 0 0 0-4 0Z",
  ],
};

function HostAvatarGlyph({ iconId, size }: { iconId: AvatarGlyphId; size: number }) {
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {GLYPH_PATHS[iconId].map((path, index) => (
        <path key={`${iconId}-${index}`} d={path} />
      ))}
    </svg>
  );
}

function avatarKey(avatar: ResolvedHostAvatar): string {
  if (avatar.kind === "distro") return avatar.logoPath;
  return `${avatar.kind}:${avatar.iconId}`;
}

function HostAvatarInner({
  host,
  size = "md",
  className,
  style,
  ariaLabel,
  title,
}: HostAvatarProps) {
  const resolved = resolveHostAvatar(host);
  const [failedAsset, setFailedAsset] = useState<string | null>(null);
  const resolvedKey = avatarKey(resolved);

  useEffect(() => {
    setFailedAsset(null);
  }, [resolvedKey]);

  const avatar = resolved.kind === "distro" && failedAsset === resolvedKey
    ? FALLBACK_HOST_AVATAR
    : resolved;
  const metrics = SIZE_METRICS[size];
  const iconId = avatar.kind === "distro" ? null : avatar.iconId;

  return (
    <span
      className={className}
      data-host-avatar-kind={avatar.kind}
      data-host-distro={avatar.kind === "distro" ? avatar.distroId : undefined}
      data-host-icon-id={iconId ?? undefined}
      role={ariaLabel ? "img" : undefined}
      aria-label={ariaLabel}
      aria-hidden={ariaLabel ? undefined : true}
      title={title}
      style={{
        alignItems: "center",
        backgroundColor: avatar.backgroundColor,
        borderRadius: metrics.radius,
        color: "#FFFFFF",
        display: "inline-flex",
        flex: "0 0 auto",
        height: metrics.edge,
        justifyContent: "center",
        overflow: "hidden",
        width: metrics.edge,
        ...style,
      }}
    >
      {avatar.kind === "distro" ? (
        <img
          src={avatar.logoPath}
          alt=""
          aria-hidden="true"
          draggable={false}
          onError={() => setFailedAsset(resolvedKey)}
          style={{
            display: "block",
            filter: avatar.preserveBrandColors ? undefined : "brightness(0) invert(1)",
            height: avatar.preserveBrandColors ? "80%" : metrics.icon,
            objectFit: "contain",
            userSelect: "none",
            width: avatar.preserveBrandColors ? "80%" : metrics.icon,
          }}
        />
      ) : (
        <HostAvatarGlyph iconId={avatar.iconId} size={metrics.icon} />
      )}
    </span>
  );
}

export const HostAvatar = memo(HostAvatarInner);
HostAvatar.displayName = "HostAvatar";
