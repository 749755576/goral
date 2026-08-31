import type { Translate } from "../i18n";

export type AiQuickMessage = Readonly<{
  id: string;
  slug: string;
  name: string;
  description: string;
  content: string;
}>;

export type AiQuickMessageTrigger = Readonly<{
  start: number;
  end: number;
  query: string;
}>;

export const AI_COMPOSER_MAX_LENGTH = 100_000;

export const builtInAiQuickMessages = (t: Translate): readonly AiQuickMessage[] => Object.freeze([
  {
    id: "builtin-status",
    slug: "status",
    name: t("ai.quickMessage.status.name"),
    description: t("ai.quickMessage.status.description"),
    content: t("ai.quickMessage.status.content"),
  },
  {
    id: "builtin-diagnose",
    slug: "diagnose",
    name: t("ai.quickMessage.diagnose.name"),
    description: t("ai.quickMessage.diagnose.description"),
    content: t("ai.quickMessage.diagnose.content"),
  },
  {
    id: "builtin-explain",
    slug: "explain",
    name: t("ai.quickMessage.explain.name"),
    description: t("ai.quickMessage.explain.description"),
    content: t("ai.quickMessage.explain.content"),
  },
]);

const searchable = (value: string): string => value.normalize("NFKC").trim().toLocaleLowerCase();

/** Finds the slash token immediately before the caret. Unicode queries are allowed. */
export function findAiQuickMessageTrigger(value: string, caret: number): AiQuickMessageTrigger | null {
  if (!Number.isInteger(caret) || caret < 0 || caret > value.length) return null;
  const beforeCaret = value.slice(0, caret);
  const match = /(^|\s)\/([^\s/]*)$/u.exec(beforeCaret);
  if (!match) return null;
  const start = beforeCaret.length - match[0].length + match[1].length;
  return Object.freeze({ start, end: caret, query: match[2] ?? "" });
}

export function filterAiQuickMessages(
  messages: readonly AiQuickMessage[],
  query: string,
): readonly AiQuickMessage[] {
  const normalized = searchable(query);
  if (!normalized) return messages;
  return messages.filter((message) => [message.slug, message.name, message.description]
    .some((candidate) => searchable(candidate).includes(normalized)));
}

export function expandAiQuickMessage(
  value: string,
  trigger: AiQuickMessageTrigger,
  content: string,
): Readonly<{ value: string; caret: number }> | null {
  const before = value.slice(0, trigger.start);
  const after = value.slice(trigger.end);
  const spacerBefore = before && !/\s$/u.test(before) ? " " : "";
  const spacerAfter = after && !/^\s/u.test(after) ? " " : "";
  const inserted = `${spacerBefore}${content}${spacerAfter}`;
  const expandedValue = `${before}${inserted}${after}`;
  if (expandedValue.length > AI_COMPOSER_MAX_LENGTH) return null;
  return Object.freeze({
    value: expandedValue,
    caret: before.length + inserted.length - spacerAfter.length,
  });
}

export type AiQuickMessageNavigationKey = "ArrowDown" | "ArrowUp" | "Home" | "End";

export function resolveAiQuickMessageIndex(
  key: AiQuickMessageNavigationKey,
  current: number,
  count: number,
): number | null {
  if (!Number.isInteger(count) || count <= 0) return null;
  if (key === "Home") return 0;
  if (key === "End") return count - 1;
  if (key === "ArrowDown") return (Math.max(-1, current) + 1) % count;
  return current <= 0 ? count - 1 : current - 1;
}
