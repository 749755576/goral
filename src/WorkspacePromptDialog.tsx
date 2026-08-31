import { useEffect, useRef, useState, type FormEvent } from "react";

export type WorkspacePromptDialogRequest = Readonly<{
  id: number;
  kind: "text" | "confirm";
  title: string;
  message: string;
  initialValue?: string;
  confirmLabel: string;
  cancelLabel: string;
  danger?: boolean;
}>;

export type WorkspacePromptDialogProps = Readonly<{
  request: WorkspacePromptDialogRequest;
  onCancel: () => void;
  onConfirm: (result: string | true) => void;
}>;

export function WorkspacePromptDialog({
  request,
  onCancel,
  onConfirm,
}: WorkspacePromptDialogProps) {
  const [value, setValue] = useState(request.initialValue ?? "");
  const inputRef = useRef<HTMLInputElement>(null);
  const titleId = `workspace-prompt-title-${request.id}`;
  const inputId = `workspace-prompt-input-${request.id}`;

  useEffect(() => {
    inputRef.current?.focus();
    inputRef.current?.select();
  }, []);

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (request.kind === "text") {
      if (value.trim()) onConfirm(value);
      return;
    }
    onConfirm(true);
  };

  return (
    <div className="dialog-backdrop" role="presentation">
      <form
        className="trust-dialog saved-host-dialog password-identity-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        onSubmit={submit}
        onKeyDown={(event) => {
          if (event.key !== "Escape") return;
          event.preventDefault();
          onCancel();
        }}
      >
        <h2 id={titleId}>{request.title}</h2>
        {request.kind === "text" ? (
          <label htmlFor={inputId}>
            {request.message}
            <input
              ref={inputRef}
              id={inputId}
              value={value}
              maxLength={255}
              autoComplete="off"
              onChange={(event) => setValue(event.target.value)}
            />
          </label>
        ) : (
          <p>{request.message}</p>
        )}
        <div className="dialog-actions">
          <button type="button" onClick={onCancel}>{request.cancelLabel}</button>
          <button
            type="submit"
            className={request.danger ? "danger-button" : "primary-button"}
            disabled={request.kind === "text" && !value.trim()}
            autoFocus={request.kind === "confirm"}
          >
            {request.confirmLabel}
          </button>
        </div>
      </form>
    </div>
  );
}
