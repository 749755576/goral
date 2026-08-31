import type { ReactNode } from "react";

export type AiGlyphName = "spark" | "history" | "new" | "clear" | "settings" | "send" | "stop" | "terminal" | "context" | "image" | "close";

export default function AiGlyph({ name }: Readonly<{ name: AiGlyphName }>) {
  const paths: Record<AiGlyphName, ReactNode> = {
    spark: <path d="M12 2l1.4 5.1L18 9l-4.6 1.9L12 16l-1.4-5.1L6 9l4.6-1.9L12 2Zm6.5 12 .7 2.3 2.3.7-2.3.7-.7 2.3-.7-2.3-2.3-.7 2.3-.7.7-2.3Z" />,
    history: <path d="M4 5v4h4M5.4 17.5A8 8 0 1 0 4.2 9M12 7v5l3 2" />,
    new: <path d="M12 5v14M5 12h14" />,
    clear: <path d="M5 7h14M9 7V4h6v3m-8 0 1 13h8l1-13M10 11v5m4-5v5" />,
    settings: <path d="M12 8.5a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7Zm0-5 1 2.1 2.3.6 2-1.1 1.7 1.7-1.1 2 .6 2.3 2.1 1-2.1 1-.6 2.3 1.1 2-1.7 1.7-2-1.1-2.3.6-1 2.1-1-2.1-2.3-.6-2 1.1-1.7-1.7 1.1-2-.6-2.3-2.1-1 2.1-1 .6-2.3-1.1-2L6.7 5l2 1.1 2.3-.6 1-2Z" />,
    send: <path d="m4 4 17 8-17 8 3-8-3-8Zm3 8h14" />,
    stop: <path d="M7 7h10v10H7z" />,
    terminal: <path d="m5 7 4 4-4 4m6 0h8" />,
    context: <path d="M8.5 15.5 6 18a3.5 3.5 0 1 1-5-5l3-3a3.5 3.5 0 0 1 5 0m6.5-1.5L18 6a3.5 3.5 0 1 1 5 5l-3 3a3.5 3.5 0 0 1-5 0M8 12h8" />,
    image: <path d="M4 5h16v14H4V5Zm3 10 3.5-4 2.5 3 2-2 3 3M8 9h.01" />,
    close: <path d="m6 6 12 12M18 6 6 18" />,
  };
  return (
    <svg className="ai-glyph" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      {paths[name]}
    </svg>
  );
}
