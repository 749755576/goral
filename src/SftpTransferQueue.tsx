import type { ReactNode } from "react";
import { createTranslator, type Locale, type Translate } from "./i18n";

import type {
  SftpSessionOwner,
  SftpTransferControlAction,
  SftpTransferSnapshot,
} from "./sftpSessionController";

export type SftpTransferGlyphName =
  | "upload"
  | "download"
  | "folder"
  | "pause"
  | "play"
  | "close"
  | "refresh";

export type SftpTransferQueueProps = Readonly<{
  locale?: Locale;
  transfers: readonly SftpTransferSnapshot[];
  activeOwner: SftpSessionOwner | null;
  canControlTransfer: (owner: SftpSessionOwner, transferId: string) => boolean;
  onControlTransfer: (
    transfer: SftpTransferSnapshot,
    action: SftpTransferControlAction,
  ) => void | Promise<void>;
  onRetryTransfer: (transfer: SftpTransferSnapshot) => void | Promise<void>;
  formatBytes: (bytes: number) => string;
  glyph: (name: SftpTransferGlyphName) => ReactNode;
}>;

const statusLabel = (status: SftpTransferSnapshot["status"], t: Translate): string => {
  if (status === "queued") return t("sftp.status.queued");
  if (status === "scanning") return t("sftp.status.scanning");
  if (status === "running") return t("sftp.status.running");
  if (status === "paused") return t("sftp.status.paused");
  if (status === "completed") return t("sftp.status.completed");
  if (status === "cancelled") return t("sftp.status.cancelled");
  return t("sftp.status.failed");
};

/**
 * Presentational SFTP transfer queue.
 *
 * The queue deliberately receives an already-authorized owner and callback
 * capabilities. It never looks up a session or talks to the backend itself;
 * session ownership therefore remains in TerminalWorkspace/SftpSessionController.
 */
export function SftpTransferQueue({
  locale = "zh-CN",
  transfers,
  activeOwner,
  canControlTransfer,
  onControlTransfer,
  onRetryTransfer,
  formatBytes,
  glyph,
}: SftpTransferQueueProps) {
  if (transfers.length === 0) return null;
  const t = createTranslator(locale);

  return (
    <div className="sftp-transfers" aria-label={t("sftp.transfers")}>
      <div className="sftp-transfer-queue-title">{t("sftp.transferQueue")}</div>
      {transfers.map((transfer) => {
        const percent = transfer.status === "completed"
          ? 100
          : transfer.totalBytes > 0
            ? Math.min(100, Math.round((transfer.bytesTransferred / transfer.totalBytes) * 100))
            : transfer.totalFiles > 0
              ? Math.min(100, Math.round((transfer.filesCompleted / transfer.totalFiles) * 100))
              : 0;
        const directorySummary = [
          t("sftp.filesSummary", { completed: transfer.filesCompleted, total: transfer.totalFiles }),
          `${formatBytes(transfer.bytesTransferred)} / ${formatBytes(transfer.totalBytes)}`,
          statusLabel(transfer.status, t),
          transfer.skippedEntries > 0 ? t("sftp.skipped", { count: transfer.skippedEntries }) : undefined,
          transfer.failedFiles > 0 ? t("sftp.failed", { count: transfer.failedFiles }) : undefined,
        ].filter(Boolean).join(" · ");
        const canRetry = (transfer.status === "cancelled" || transfer.status === "failed")
          && (transfer.isDirectory
            ? Boolean(transfer.directoryCheckpoint)
            : Boolean(
              transfer.checkpoint
              && transfer.checkpoint.bytesTransferred > 0
              && transfer.checkpoint.bytesTransferred < transfer.checkpoint.totalBytes,
            ));
        const canControl = activeOwner !== null
          && canControlTransfer(activeOwner, transfer.id);
        return (
          <div
            className={`sftp-transfer transfer-${transfer.status}${transfer.isDirectory ? " is-directory" : ""}`}
            key={transfer.id}
          >
            <div>
              <strong title={transfer.localPath}>
                {glyph(transfer.direction === "upload" ? "upload" : "download")}
                {transfer.isDirectory && glyph("folder")}
                {transfer.label}
              </strong>
              <small>
                {transfer.isDirectory ? directorySummary : `${percent}% · ${statusLabel(transfer.status, t)}`}
              </small>
              {transfer.currentPath && (
                <small className="transfer-current-path" title={transfer.currentPath}>
                  {transfer.currentPath}
                </small>
              )}
              {transfer.error && <small className="transfer-error">{transfer.error}</small>}
            </div>
            <progress max={100} value={percent} />
            <div className="transfer-actions">
              {(transfer.status === "running" || transfer.status === "scanning")
                && canControl && (
                <button
                  type="button"
                  title={t("sftp.pause")}
                  aria-label={t("sftp.pauseNamed", { name: transfer.label ?? "" })}
                  onClick={() => void onControlTransfer(transfer, "pause")}
                >
                  {glyph("pause")}
                </button>
              )}
              {transfer.status === "paused" && canControl && (
                <button
                  type="button"
                  title={t("sftp.resume")}
                  aria-label={t("sftp.resumeNamed", { name: transfer.label ?? "" })}
                  onClick={() => void onControlTransfer(transfer, "resume")}
                >
                  {glyph("play")}
                </button>
              )}
              {(transfer.status === "queued" || transfer.status === "scanning"
                || transfer.status === "running" || transfer.status === "paused")
                && canControl && (
                <button
                  type="button"
                  title={t("sftp.cancel")}
                  aria-label={t("sftp.cancelNamed", { name: transfer.label ?? "" })}
                  onClick={() => void onControlTransfer(transfer, "cancel")}
                >
                  {glyph("close")}
                </button>
              )}
              {canRetry && (
                <button
                  type="button"
                  title={t("sftp.retryTransfer")}
                  aria-label={t("sftp.retryNamed", { name: transfer.label ?? "" })}
                  onClick={() => void onRetryTransfer(transfer)}
                >
                  {glyph("refresh")}
                </button>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
