export type AiConversationHistoryItem = Readonly<{
  id: string;
  title: string;
  messageCount: number;
  active: boolean;
}>;

export type AiConversationHistoryLabels = Readonly<{
  regionLabel: string;
  title: string;
  newConversation: string;
  empty: string;
  messageCount: string;
  selectConversation: string;
  deleteConversation: string;
  delete: string;
}>;

export type AiConversationHistoryProps = Readonly<{
  items: ReadonlyArray<AiConversationHistoryItem>;
  labels: AiConversationHistoryLabels;
  disabled?: boolean;
  onNew: () => void;
  onSelect: (id: string) => void;
  onDelete: (id: string) => void;
}>;

const formatItemLabel = (
  template: string,
  item: AiConversationHistoryItem,
): string => template
  .replaceAll("{{title}}", () => item.title)
  .replaceAll("{{count}}", () => String(item.messageCount))
  .replaceAll("{title}", () => item.title)
  .replaceAll("{count}", () => String(item.messageCount));

export function AiConversationHistory({
  items,
  labels,
  disabled = false,
  onNew,
  onSelect,
  onDelete,
}: AiConversationHistoryProps) {
  return (
    <section id="ai-conversation-history" className="ai-conversation-history" aria-label={labels.regionLabel}>
      <header className="ai-conversation-history-header">
        <h2>{labels.title}</h2>
        <button type="button" disabled={disabled} onClick={onNew}>
          {labels.newConversation}
        </button>
      </header>

      {items.length === 0 ? (
        <p className="ai-conversation-history-empty" role="status">
          {labels.empty}
        </p>
      ) : (
        <ul className="ai-conversation-history-list">
          {items.map((item) => (
            <li
              className={item.active ? "is-active" : undefined}
              key={item.id}
            >
              <button
                type="button"
                className="ai-conversation-history-select"
                aria-current={item.active ? "true" : undefined}
                aria-label={formatItemLabel(labels.selectConversation, item)}
                disabled={disabled}
                onClick={() => onSelect(item.id)}
              >
                <span className="ai-conversation-history-item-title">
                  <span title={item.title}>{item.title}</span>
                </span>
                <span className="ai-conversation-history-item-count">
                  {formatItemLabel(labels.messageCount, item)}
                </span>
              </button>
              <button
                type="button"
                className="ai-conversation-history-delete"
                aria-label={formatItemLabel(labels.deleteConversation, item)}
                disabled={disabled}
                onClick={(event) => {
                  event.stopPropagation();
                  onDelete(item.id);
                }}
              >
                {labels.delete}
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

export default AiConversationHistory;
