/**
 * Renderer-local AI context estimate.
 *
 * Providers do not currently return one shared, trustworthy prompt-usage
 * contract. This estimate is therefore deliberately labelled as estimated in
 * the UI. It measures only the text messages that Goral is about to send;
 * provider-specific image accounting and hidden server-side prompt additions
 * are excluded.
 */

const CHAT_PRIMING_TOKENS = 2;
const MESSAGE_FRAME_TOKENS = 4;
const utf8 = new TextEncoder();
const CJK_SCALAR = /[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}]/u;
const PICTOGRAPHIC_SCALAR = /\p{Extended_Pictographic}/u;

export type AiContextUsage = Readonly<{
  estimatedTextTokens: number;
  contextWindowTokens: number | null;
  percent: number | null;
  modelId: string;
  containsImages: boolean;
}>;

type TextMessage = Readonly<{ content: string }>;

/**
 * A deterministic tokenizer-independent approximation. CJK scalars are
 * counted individually, pictographs as two tokens, and all other UTF-8 text
 * at roughly four bytes per token. It must never be presented as provider
 * billing or exact tokenizer output.
 */
export function estimateAiTextTokens(text: string): number {
  if (!text) return 0;
  let estimated = 0;
  let ordinaryRun = "";
  const flushOrdinaryRun = () => {
    if (!ordinaryRun) return;
    estimated += Math.ceil(utf8.encode(ordinaryRun).byteLength / 4);
    ordinaryRun = "";
  };

  for (const scalar of text) {
    if (CJK_SCALAR.test(scalar)) {
      flushOrdinaryRun();
      estimated += 1;
    } else if (PICTOGRAPHIC_SCALAR.test(scalar)) {
      flushOrdinaryRun();
      estimated += 2;
    } else {
      ordinaryRun += scalar;
    }
  }
  flushOrdinaryRun();
  return estimated;
}

export function estimateAiChatTextTokens(messages: readonly TextMessage[]): number {
  return CHAT_PRIMING_TOKENS + messages.reduce(
    (total, message) => total + MESSAGE_FRAME_TOKENS + estimateAiTextTokens(message.content),
    0,
  );
}

const explicitContextWindowFromModelId = (modelId: string): number | null => {
  // Prefer an explicit model suffix such as moonshot-v1-32k or model-1m.
  for (const match of modelId.matchAll(/(?:^|[-_.])(\d{1,4}(?:\.\d+)?)([km])(?:$|[-_.])/giu)) {
    const quantity = Number(match[1]);
    const multiplier = match[2]?.toLowerCase() === "m" ? 1_000_000 : 1_000;
    const tokens = Math.round(quantity * multiplier);
    if (Number.isSafeInteger(tokens) && tokens >= 4_000 && tokens <= 10_000_000) return tokens;
  }
  return null;
};

/**
 * Returns only model windows that can be reasonably inferred from a stable
 * family name. Custom/local model IDs remain unknown instead of silently
 * borrowing an unrelated default.
 */
export function inferAiContextWindowTokens(modelId: string): number | null {
  const normalized = modelId.trim().toLowerCase();
  if (!normalized) return null;
  const explicit = explicitContextWindowFromModelId(normalized);
  if (explicit !== null) return explicit;

  const model = normalized.split("/").at(-1) ?? normalized;
  if (/^gpt-4\.1(?:$|[-_.])/u.test(model)) return 1_000_000;
  if (/^gpt-5(?:$|[-_.])/u.test(model)) return 400_000;
  if (/^(?:o1|o3|o4)(?:$|[-_.])/u.test(model)) return 200_000;
  if (/^gpt-4o(?:$|[-_.])/u.test(model) || /^gpt-4-turbo(?:$|[-_.])/u.test(model)) return 128_000;
  if (/^gpt-4(?:$|[-_.])/u.test(model)) return 8_192;
  if (/^gpt-3\.5-turbo(?:$|[-_.])/u.test(model)) return 16_384;
  if (/^claude-(?:3|4)(?:$|[-_.])/u.test(model) || /^claude-(?:haiku|sonnet|opus)(?:$|[-_.])/u.test(model)) return 200_000;
  if (/^gemini-(?:1\.5|2|2\.5|3)(?:$|[-_.])/u.test(model)) return 1_000_000;
  if (/^deepseek(?:$|[-_.])/u.test(model)) return 128_000;
  if (/^qwen-plus(?:$|[-_.])/u.test(model)) return 1_000_000;
  if (/^glm-4(?:$|[-_.])/u.test(model)) return 128_000;
  return null;
}

export function createAiContextUsage(
  messages: readonly TextMessage[],
  modelId: string,
  containsImages: boolean,
): AiContextUsage {
  const estimatedTextTokens = estimateAiChatTextTokens(messages);
  const contextWindowTokens = inferAiContextWindowTokens(modelId);
  const percent = contextWindowTokens === null
    ? null
    : Math.min(100, Math.max(0, (estimatedTextTokens / contextWindowTokens) * 100));
  return Object.freeze({
    estimatedTextTokens,
    contextWindowTokens,
    percent,
    modelId: modelId.trim(),
    containsImages,
  });
}

export function formatAiTokenCount(tokens: number): string {
  const bounded = Math.max(0, Math.round(tokens));
  if (bounded >= 1_000_000) return `${(bounded / 1_000_000).toFixed(bounded >= 10_000_000 ? 0 : 1)}M`;
  if (bounded >= 1_000) return `${(bounded / 1_000).toFixed(bounded >= 100_000 ? 0 : 1)}K`;
  return String(bounded);
}
