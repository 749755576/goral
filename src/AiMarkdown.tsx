import { Fragment, type ReactNode, useCallback, useState } from "react";

export type AiMarkdownLabels = Readonly<{
  copyCode: string;
  copiedCode: string;
}>;

export type AiMarkdownProps = Readonly<{
  content: string;
  labels: AiMarkdownLabels;
}>;

type MarkdownSegment = Readonly<{
  kind: "text" | "code";
  content: string;
  language?: string;
}>;

const SAFE_LINK_PROTOCOLS = new Set(["http:", "https:"]);

const safeLink = (value: string): string | null => {
  try {
    const url = new URL(value);
    return SAFE_LINK_PROTOCOLS.has(url.protocol) ? url.toString() : null;
  } catch {
    return null;
  }
};

const splitMarkdown = (content: string): MarkdownSegment[] => {
  const segments: MarkdownSegment[] = [];
  const fence = /```([^\n`]*)\n?([\s\S]*?)```/gu;
  let offset = 0;
  let match: RegExpExecArray | null;
  while ((match = fence.exec(content)) !== null) {
    if (match.index > offset) {
      segments.push({ kind: "text", content: content.slice(offset, match.index) });
    }
    segments.push({
      kind: "code",
      language: (match[1] ?? "").trim().toLowerCase(),
      content: (match[2] ?? "").replace(/\n$/u, ""),
    });
    offset = match.index + match[0].length;
  }
  if (offset < content.length) segments.push({ kind: "text", content: content.slice(offset) });
  return segments.length > 0 ? segments : [{ kind: "text", content }];
};

const inlinePattern = /(`[^`\n]+`|\*\*[^*\n]+\*\*|\[[^\]\n]+\]\(https?:\/\/[^\s)]+\))/gu;

const renderInline = (content: string, keyPrefix: string): ReactNode[] => {
  const nodes: ReactNode[] = [];
  let offset = 0;
  let index = 0;
  let match: RegExpExecArray | null;
  while ((match = inlinePattern.exec(content)) !== null) {
    if (match.index > offset) nodes.push(content.slice(offset, match.index));
    const token = match[0];
    const key = `${keyPrefix}-${index}`;
    if (token.startsWith("`")) {
      nodes.push(<code key={key}>{token.slice(1, -1)}</code>);
    } else if (token.startsWith("**")) {
      nodes.push(<strong key={key}>{token.slice(2, -2)}</strong>);
    } else {
      const link = /^\[([^\]]+)\]\((.+)\)$/u.exec(token);
      const href = link ? safeLink(link[2]) : null;
      nodes.push(href
        ? <a key={key} href={href} target="_blank" rel="noreferrer">{link?.[1]}</a>
        : token);
    }
    offset = match.index + token.length;
    index += 1;
  }
  if (offset < content.length) nodes.push(content.slice(offset));
  return nodes;
};

const renderTextBlocks = (content: string, keyPrefix: string): ReactNode[] => {
  const lines = content.replace(/\r\n?/gu, "\n").split("\n");
  const blocks: ReactNode[] = [];
  let paragraph: string[] = [];
  let list: Array<{ ordered: boolean; value: string }> = [];

  const flushParagraph = () => {
    if (paragraph.length === 0) return;
    const value = paragraph.join("\n").trim();
    if (value) {
      blocks.push(<p key={`${keyPrefix}-p-${blocks.length}`}>{renderInline(value, `${keyPrefix}-p-${blocks.length}`)}</p>);
    }
    paragraph = [];
  };

  const flushList = () => {
    if (list.length === 0) return;
    const ordered = list[0].ordered;
    const items = list.map((entry, index) => (
      <li key={`${keyPrefix}-li-${blocks.length}-${index}`}>
        {renderInline(entry.value, `${keyPrefix}-li-${blocks.length}-${index}`)}
      </li>
    ));
    blocks.push(ordered
      ? <ol key={`${keyPrefix}-ol-${blocks.length}`}>{items}</ol>
      : <ul key={`${keyPrefix}-ul-${blocks.length}`}>{items}</ul>);
    list = [];
  };

  lines.forEach((line) => {
    const heading = /^(#{1,3})\s+(.+)$/u.exec(line);
    const listItem = /^\s*(?:(\d+)\.|[-*])\s+(.+)$/u.exec(line);
    const quote = /^>\s?(.*)$/u.exec(line);
    if (heading) {
      flushParagraph();
      flushList();
      const body = renderInline(heading[2], `${keyPrefix}-h-${blocks.length}`);
      const level = heading[1].length;
      blocks.push(level === 1
        ? <h3 key={`${keyPrefix}-h-${blocks.length}`}>{body}</h3>
        : level === 2
          ? <h4 key={`${keyPrefix}-h-${blocks.length}`}>{body}</h4>
          : <h5 key={`${keyPrefix}-h-${blocks.length}`}>{body}</h5>);
      return;
    }
    if (listItem) {
      flushParagraph();
      const ordered = Boolean(listItem[1]);
      if (list.length > 0 && list[0].ordered !== ordered) flushList();
      list.push({ ordered, value: listItem[2] });
      return;
    }
    if (quote) {
      flushParagraph();
      flushList();
      blocks.push(
        <blockquote key={`${keyPrefix}-quote-${blocks.length}`}>
          {renderInline(quote[1], `${keyPrefix}-quote-${blocks.length}`)}
        </blockquote>,
      );
      return;
    }
    if (!line.trim()) {
      flushParagraph();
      flushList();
      return;
    }
    paragraph.push(line);
  });
  flushParagraph();
  flushList();
  return blocks;
};

export function AiMarkdown({ content, labels }: AiMarkdownProps) {
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const copy = useCallback(async (value: string, index: number) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedIndex(index);
      window.setTimeout(() => setCopiedIndex((current) => current === index ? null : current), 1_500);
    } catch {
      setCopiedIndex(null);
    }
  }, []);

  return (
    <div className="ai-markdown">
      {splitMarkdown(content).map((segment, index) => segment.kind === "code" ? (
        <figure className="ai-markdown-code" key={`code-${index}`}>
          <figcaption>
            <span>{segment.language || "text"}</span>
            <button type="button" onClick={() => void copy(segment.content, index)}>
              {copiedIndex === index ? labels.copiedCode : labels.copyCode}
            </button>
          </figcaption>
          <pre><code>{segment.content}</code></pre>
        </figure>
      ) : (
        <Fragment key={`text-${index}`}>
          {renderTextBlocks(segment.content, `text-${index}`)}
        </Fragment>
      ))}
    </div>
  );
}

export default AiMarkdown;
