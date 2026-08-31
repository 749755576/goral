import type { Translate } from "../i18n";
import { formatAiTokenCount, type AiContextUsage } from "./aiContextUsage";

export type AiContextUsageRingProps = Readonly<{
  usage: AiContextUsage;
  t: Translate;
}>;

const percentLabel = (percent: number): string => (
  percent > 0 && percent < 1 ? "<1" : String(Math.round(percent))
);

export default function AiContextUsageRing({ usage, t }: AiContextUsageRingProps) {
  const used = formatAiTokenCount(usage.estimatedTextTokens);
  const model = usage.modelId || t("ai.contextUsage.currentModel");
  const imageNotice = usage.containsImages ? ` ${t("ai.contextUsage.imagesExcluded")}` : "";
  const label = usage.contextWindowTokens === null || usage.percent === null
    ? `${t("ai.contextUsage.unknown", { used, model })}${imageNotice}`
    : `${t("ai.contextUsage.known", {
        used,
        max: formatAiTokenCount(usage.contextWindowTokens),
        percent: percentLabel(usage.percent),
        model,
      })}${imageNotice}`;
  const level = usage.percent === null
    ? "unknown"
    : usage.percent >= 80
      ? "critical"
      : usage.percent >= 50
        ? "warning"
      : "normal";
  const compactValue = usage.percent === null
    ? `≈${used}`
    : `${percentLabel(usage.percent)}%`;

  return (
    <span
      className="ai-context-usage-ring"
      data-level={level}
      title={label}
      {...(usage.percent === null ? {
        role: "img" as const,
        "aria-label": label,
      } : {
        role: "progressbar" as const,
        "aria-label": label,
        "aria-valuemin": 0,
        "aria-valuemax": 100,
        "aria-valuenow": Math.round(usage.percent),
        "aria-valuetext": label,
      })}
    >
      {usage.percent === null ? null : (
        <svg aria-hidden="true" focusable="false" viewBox="0 0 24 24">
          <circle className="ai-context-usage-track" cx="12" cy="12" r="9" />
          <circle
            className="ai-context-usage-value"
            cx="12"
            cy="12"
            r="9"
            pathLength="100"
            strokeDasharray={100}
            strokeDashoffset={100 - usage.percent}
          />
        </svg>
      )}
      <span className="ai-context-usage-label" aria-hidden="true">{compactValue}</span>
    </span>
  );
}
