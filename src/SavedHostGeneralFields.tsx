import type { ReactNode } from "react";

import { createTranslator, type Locale } from "./i18n";
import type { SavedHostEditor } from "./SavedHostChainEditor";

export type SavedHostGeneralFieldsProps = Readonly<{
  editor: SavedHostEditor;
  locale: Locale;
  submitting: boolean;
  groups: readonly string[];
  onChange: (update: (current: SavedHostEditor) => SavedHostEditor) => void;
  glyph: (name: "settings" | "hosts") => ReactNode;
}>;

/**
 * Saved-host identity and network-address controls. The parent retains the
 * draft, validation, persistence, credential staging, and session authority.
 */
export function SavedHostGeneralFields({
  editor,
  locale,
  submitting,
  groups,
  onChange,
  glyph,
}: SavedHostGeneralFieldsProps) {
  const t = createTranslator(locale);
  return (
    <>
      <div className="host-editor-section-title">
        {glyph("settings")}
        <span>{t("savedHost.editor.general.section")}</span>
      </div>
      <label>
        {t("savedHost.editor.general.name")}
        <input
          value={editor.label}
          onChange={(event) => onChange((current) => ({
            ...current,
            label: event.target.value,
          }))}
          placeholder={t("savedHost.editor.general.namePlaceholder")}
          disabled={submitting}
        />
      </label>
      <label>
        {t("savedHost.editor.general.group")}
        <input
          value={editor.group}
          list="saved-host-group-options"
          onChange={(event) => onChange((current) => ({
            ...current,
            group: event.target.value,
          }))}
          placeholder={t("savedHost.editor.general.groupPlaceholder")}
          disabled={submitting}
        />
        <datalist id="saved-host-group-options">
          {groups.map((group) => <option value={group} key={group} />)}
        </datalist>
      </label>
      <label>
        {t("savedHost.editor.general.tags")}
        <input
          value={editor.tags}
          onChange={(event) => onChange((current) => ({
            ...current,
            tags: event.target.value,
          }))}
          placeholder={t("savedHost.editor.general.tagsPlaceholder")}
          disabled={submitting}
        />
        <small className="host-editor-field-hint">{t("savedHost.editor.general.tagsHint")}</small>
      </label>
      <div className="host-editor-section-title">
        {glyph("hosts")}
        <span>{t("savedHost.editor.general.addressSection")}</span>
      </div>
      <label>
        {t("savedHost.editor.general.host")}
        <input
          value={editor.hostname}
          autoComplete="off"
          onChange={(event) => onChange((current) => ({
            ...current,
            hostname: event.target.value,
          }))}
          disabled={submitting}
          required
          autoFocus
        />
      </label>
      <div className="field-row">
        <label>
          {t("savedHost.editor.general.port")}
          <input
            type="number"
            min="1"
            max="65535"
            value={editor.port}
            onChange={(event) => onChange((current) => ({
              ...current,
              port: event.target.value,
            }))}
            disabled={submitting}
            required
          />
        </label>
        <label>
          {t("savedHost.editor.general.username")}
          <input
            value={editor.username}
            autoComplete="username"
            onChange={(event) => onChange((current) => ({
              ...current,
              username: event.target.value,
            }))}
            disabled={submitting}
            required={editor.protocol === "ssh"}
          />
        </label>
      </div>
    </>
  );
}
