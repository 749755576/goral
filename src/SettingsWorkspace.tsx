import { isTauri } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import {
  type ChangeEvent,
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import { listLocalShells, type DiscoveredLocalShell } from "./backend";
import {
  deleteSavedAiApiKey,
  hasSavedAiApiKey,
  saveAiApiKey,
} from "./aiApi";
import { listAiModels } from "./aiModelsApi";
import { errorText, hasErrorCode } from "./errorCode";
import {
  AI_PROVIDER_PROFILE_LIMIT,
  AI_PROVIDER_PRESETS,
  AI_RESPONSE_IDLE_TIMEOUT_MAX_SECONDS,
  AI_RESPONSE_IDLE_TIMEOUT_MIN_SECONDS,
  createAiProviderProfile,
  createDefaultRendererSafeSettings,
  detectSettingsPlatform,
  formatLocalShellArgs,
  isRendererSafeLocalShell,
  isRendererSafeLocalShellArgs,
  isRendererSafeLocalStartDir,
  isPublicSettingsPageId,
  LOCAL_SHELL_LIMITS,
  parseLocalShellArgs,
  type AiProviderProfile,
  type AiProviderProtocol,
  type AiProviderPreset,
  type RendererSafeSettings,
  type RendererSafeSettingsAdapter,
  SETTINGS_PUBLIC_PAGES,
  SETTINGS_SEARCH_CATALOG,
  type SettingsAnchorId,
  type SettingsNestedTab,
  type SettingsPageDefinition,
  type SettingsPageId,
  updateRendererSafeSettings,
} from "./settingsUi";
import {
  createTranslator,
  localizeAiError,
  normalizeLocale,
  useI18n,
  type MessageKey,
  type Translate,
} from "./i18n";
import {
  isSettingsWindowTarget,
  readInitialSettingsWindowTarget,
  SETTINGS_WINDOW_FOCUS_EVENT,
  type SettingsWindowTarget,
} from "./settingsWindowApi";
import { useAppColorMode } from "./useAppColorMode";
import { useUiFontFamily } from "./useUiFontFamily";
import "./settings.css";
import "./goralTokens.css";
import "./goralSkin.css";
import "./goralContrast.css";
import "./settingsSkin.css";

type NativeSettingsAction =
  | "check-updates"
  | "report-problem"
  | "open-community"
  | "open-github"
  | "open-releases";

export type SettingsWorkspaceProps = {
  adapter?: RendererSafeSettingsAdapter;
  appVersion?: string;
  initialPage?: SettingsPageId;
  onClose?: () => void;
  onNativeAction?: (action: NativeSettingsAction) => void | Promise<void>;
  localShellSource?: () => Promise<DiscoveredLocalShell[]>;
  chooseLocalStartDirectory?: (title?: string) => Promise<string | null>;
};

const defaultLocalShellSource = (): Promise<DiscoveredLocalShell[]> =>
  isTauri() ? listLocalShells() : Promise.resolve([]);

const defaultLocalStartDirectoryPicker = async (title?: string): Promise<string | null> => {
  if (!isTauri()) return null;
  const selected = await open({
    directory: true,
    multiple: false,
    ...(title ? { title } : {}),
  });
  return typeof selected === "string" ? selected : null;
};

const SettingsTranslationContext = createContext<Translate>(createTranslator("zh-CN"));

const useSettingsTranslation = (): Translate => useContext(SettingsTranslationContext);

const settingsAnchorText = (t: Translate, id: SettingsAnchorId): string =>
  t(`settings.anchor.${id}` as MessageKey);

const settingsPageText = (t: Translate, id: SettingsPageId): string =>
  t(`settings.pages.${id}` as MessageKey);

const findLocalizedSettingsSearchHits = (
  query: string,
  t: Translate,
) => {
  const normalized = query.trim().toLocaleLowerCase();
  if (!normalized) return [];
  const terms = normalized.split(/\s+/u).filter(Boolean);
  return SETTINGS_SEARCH_CATALOG
    .map((entry) => {
      const label = settingsAnchorText(t, entry.id);
      const pageLabel = settingsPageText(t, entry.page);
      return {
        ...entry,
        label,
        pageLabel,
        searchText: `${entry.searchText} ${label} ${pageLabel}`.toLocaleLowerCase(),
      };
    })
    .filter((entry) => terms.every((term) => entry.searchText.includes(term)))
    .sort((left, right) => {
      const leftLabel = left.label.toLocaleLowerCase();
      const rightLabel = right.label.toLocaleLowerCase();
      const leftScore = leftLabel === normalized
        ? 0
        : leftLabel.startsWith(normalized) ? 1 : left.searchText.includes(normalized) ? 2 : 3;
      const rightScore = rightLabel === normalized
        ? 0
        : rightLabel.startsWith(normalized) ? 1 : right.searchText.includes(normalized) ? 2 : 3;
      return leftScore - rightScore || left.label.localeCompare(right.label);
    })
    .slice(0, 12);
};

function SettingsGlyph({ name }: { name: SettingsPageDefinition["glyph"] | "search" | "close" | "check" | "arrow" }) {
  const path = {
    app: "M4 3.5h8a1.5 1.5 0 0 1 1.5 1.5v7A1.5 1.5 0 0 1 12 13.5H4A1.5 1.5 0 0 1 2.5 12V5A1.5 1.5 0 0 1 4 3.5Zm-1.5 3h11M5 5h.01M7 5h.01",
    plugin: "M6.2 2.5v2.2H4.4v2.1H2.5v2.4h1.9v2.1h1.8v2.2h3.6v-2.2h1.8V9.2h1.9V6.8h-1.9V4.7H9.8V2.5H6.2Z",
    palette: "M8 2.5a5.5 5.5 0 1 0 0 11h.7c.8 0 1.2-.9.7-1.5-.6-.7-.1-1.8.8-1.8H12A1.5 1.5 0 0 0 13.5 8 5.5 5.5 0 0 0 8 2.5ZM5.2 7h.01M7 4.9h.01M9.6 5.1h.01M4.6 9.5h.01",
    terminal: "M2.5 3.5h11v9h-11v-9Zm2.1 2.2 2 1.8-2 1.8M8 10h3",
    keyboard: "M2.5 4.5h11v7h-11v-7Zm2 2h.01m2 0h.01m2 0h.01m2 0h.01m-6 2h.01m2 0h.01m2 0h.01m2 0h.01M5 10h6",
    file: "M4 2.5h5l3 3v8H4v-11Zm5 0v3h3M6 8h4m-4 2h4",
    ai: "M8 2.5 9.2 6 13 7.2 9.2 8.4 8 12l-1.2-3.6L3 7.2 6.8 6 8 2.5Z",
    cloud: "M5.2 12.5h6.2a2.1 2.1 0 0 0 .2-4.2A3.8 3.8 0 0 0 4.3 7a2.8 2.8 0 0 0 .9 5.5Z",
    system: "M8 5.4A2.6 2.6 0 1 0 8 10.6 2.6 2.6 0 0 0 8 5.4Zm0-2.9v1.1m0 8.8v1.1M2.5 8h1.1m8.8 0h1.1M4.1 4.1l.8.8m6.2 6.2.8.8m0-7.8-.8.8m-6.2 6.2-.8.8",
    search: "M7 3a4 4 0 1 0 0 8 4 4 0 0 0 0-8Zm3 7 3 3",
    close: "M4 4l8 8m0-8-8 8",
    check: "m3.5 8 3 3 6-7",
    arrow: "m6 3 5 5-5 5",
  }[name];
  return (
    <svg className="settings-glyph" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.35" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={path} />
    </svg>
  );
}

function SettingsAnchor({ id, className = "", children }: { id: SettingsAnchorId; className?: string; children: ReactNode }) {
  return (
    <div id={id} data-settings-anchor={id} tabIndex={-1} className={`settings-anchor ${className}`}>
      {children}
    </div>
  );
}

function SectionTitle({ children }: { children: ReactNode }) {
  return <h2 className="settings-section-title">{children}</h2>;
}

function SettingsCard({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <div className={`settings-card ${className}`}>{children}</div>;
}

function SettingRow({
  id,
  label,
  description,
  children,
}: {
  id: SettingsAnchorId;
  label?: string;
  description?: string;
  children: ReactNode;
}) {
  const t = useSettingsTranslation();
  return (
    <SettingsAnchor id={id} className="settings-row">
      <div className="settings-row-copy">
        <div className="settings-row-label">{label ?? settingsAnchorText(t, id)}</div>
        {description ? <div className="settings-row-description">{description}</div> : null}
      </div>
      <div className="settings-row-control">{children}</div>
    </SettingsAnchor>
  );
}

function Toggle({ checked, onChange, label }: { checked: boolean; onChange: (checked: boolean) => void; label: string }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      className="settings-toggle"
      onClick={() => onChange(!checked)}
    >
      <span />
    </button>
  );
}

function SelectControl({
  value,
  onChange,
  label,
  options,
}: {
  value: string;
  onChange: (value: string) => void;
  label: string;
  options: readonly { value: string; label: string }[];
}) {
  return (
    <select aria-label={label} className="settings-select" value={value} onChange={(event) => onChange(event.target.value)}>
      {options.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
    </select>
  );
}

type PageProps = {
  settings: RendererSafeSettings;
  patch: (mutator: (draft: RendererSafeSettings) => void) => Promise<SettingsSaveOutcome>;
  waitForSettingsSave: () => Promise<SettingsSaveOutcome>;
  settingsReady: boolean;
  onNativeAction?: SettingsWorkspaceProps["onNativeAction"];
  nestedTab: SettingsNestedTab;
  setNestedTab: (tab: SettingsNestedTab) => void;
  appVersion: string;
  localShellSource: NonNullable<SettingsWorkspaceProps["localShellSource"]>;
  chooseLocalStartDirectory: NonNullable<SettingsWorkspaceProps["chooseLocalStartDirectory"]>;
};

function ApplicationPage({ onNativeAction, appVersion }: PageProps) {
  const t = useSettingsTranslation();
  const action = (name: NativeSettingsAction) => () => { void onNativeAction?.(name); };
  return (
    <div className="settings-page-body settings-application-page">
      <div className="settings-app-identity">
        <div className="settings-app-logo" aria-hidden="true"><img src="/logo-goral.svg" alt="" /></div>
        <div>
          <div className="settings-wordmark">Goral</div>
          <div className="settings-version">{appVersion}</div>
        </div>
        {onNativeAction ? (
          <SettingsAnchor id="application-check-updates" className="settings-update-anchor">
            <button className="settings-secondary-button" type="button" onClick={action("check-updates")}>{t("app.checkUpdates")}</button>
          </SettingsAnchor>
        ) : null}
      </div>
      {onNativeAction ? <div className="settings-action-list">
        {([
          ["application-report-problem", t("app.reportProblem"), t("app.reportProblemDescription"), "report-problem"],
          ["application-community", t("app.community"), t("app.communityDescription"), "open-community"],
          ["application-github", t("app.github"), t("app.githubDescription"), "open-github"],
          ["application-whats-new", t("app.whatsNew"), t("app.whatsNewDescription"), "open-releases"],
        ] as const).map(([id, label, description, name]) => (
          <SettingsAnchor key={id} id={id}>
            <button type="button" className="settings-action-row" onClick={action(name)}>
              <span className="settings-action-mark" aria-hidden="true">{label.charAt(0)}</span>
              <span><strong>{label}</strong><small>{description}</small></span>
              <SettingsGlyph name="arrow" />
            </button>
          </SettingsAnchor>
        ))}
      </div> : null}
      <section className="settings-about-card" aria-label={t("app.about")}>
        <h2>{t("app.about")}</h2>
        <p><strong>{t("app.brandTagline")}</strong></p>
        <p>{t("app.brandStory")}</p>
        <p>{t("app.legalNotice")}</p>
        <p>{t("app.upstreamNotice")}</p>
        <p>{t("app.warranty")}</p>
        <small>{t("app.license")} · {t("app.source")}</small>
      </section>
    </div>
  );
}

function AppearancePage({ settings, patch }: PageProps) {
  const appearance = settings.appearance;
  const t = useSettingsTranslation();
  return (
    <div className="settings-page-body">
      <SectionTitle>{t("app.languageInterface")}</SectionTitle>
      <SettingsCard>
        <SettingRow id="appearance-language" description={t("settings.languageDescription")}>
          <SelectControl label={t("settings.language")} value={appearance.uiLanguage} onChange={(value) => patch((draft) => { draft.appearance.uiLanguage = value as typeof appearance.uiLanguage; })} options={[
            { value: "system", label: t("app.systemDefault") }, { value: "en-US", label: t("settings.language.en-US") }, { value: "zh-CN", label: t("settings.language.zh-CN") },
          ]} />
        </SettingRow>
        <SettingRow id="appearance-ui-font" description={t("app.interfaceFontDescription")}>
          <SelectControl label={t("app.interfaceFont")} value={appearance.uiFontFamilyId} onChange={(value) => patch((draft) => { draft.appearance.uiFontFamilyId = value; })} options={[
            { value: "inter", label: "Inter" }, { value: "system", label: t("settings.appearance.systemUi") }, { value: "menlo", label: t("settings.appearance.monospace") },
          ]} />
        </SettingRow>
      </SettingsCard>

      <SectionTitle>{t("settings.pages.appearance")}</SectionTitle>
      <SettingsCard>
        <SettingRow id="appearance-theme">
          <div className="settings-segmented" role="group" aria-label={t("app.colorMode")}>
            {(["light", "dark", "system"] as const).map((mode) => (
              <button key={mode} type="button" className={appearance.colorMode === mode ? "active" : ""} onClick={() => patch((draft) => { draft.appearance.colorMode = mode; })}>{t(`settings.appearance.color.${mode}` as MessageKey)}</button>
            ))}
          </div>
        </SettingRow>
      </SettingsCard>

      <SectionTitle>{t("settings.appearance.vault")}</SectionTitle>
      <SettingsCard>
        <SettingRow id="appearance-vault-show-sftp-tab">
          <Toggle label={settingsAnchorText(t, "appearance-vault-show-sftp-tab")} checked={appearance.showSftpTab} onChange={(checked) => patch((draft) => { draft.appearance.showSftpTab = checked; })} />
        </SettingRow>
      </SettingsCard>
    </div>
  );
}

function LocalShellSettings({
  terminal,
  patch,
  shellSource,
  chooseStartDirectory,
}: {
  terminal: RendererSafeSettings["terminal"];
  patch: PageProps["patch"];
  shellSource: PageProps["localShellSource"];
  chooseStartDirectory: PageProps["chooseLocalStartDirectory"];
}) {
  const t = useSettingsTranslation();
  const [shells, setShells] = useState<DiscoveredLocalShell[]>([]);
  const [shellLoadState, setShellLoadState] = useState<"loading" | "ready" | "error">("loading");
  const [customEditing, setCustomEditing] = useState(false);
  const [customShellDraft, setCustomShellDraft] = useState(terminal.localShell);
  const [customArgsDraft, setCustomArgsDraft] = useState(() => formatLocalShellArgs(terminal.localShellArgs));
  const [directoryError, setDirectoryError] = useState<string | null>(null);
  const [pickingDirectory, setPickingDirectory] = useState(false);

  useEffect(() => {
    let current = true;
    setShellLoadState("loading");
    void (async () => {
      try {
        const discovered = await shellSource();
        if (!current) return;
        const seen = new Set<string>();
        const safe = (Array.isArray(discovered) ? discovered : [])
          .filter((shell) => typeof shell?.id === "string"
            && shell.id.length <= 128
            && /^[a-z0-9][a-z0-9._-]*$/.test(shell.id)
            && typeof shell.name === "string"
            && !seen.has(shell.id)
            && seen.add(shell.id))
          .slice(0, 64);
        setShells(safe);
        setShellLoadState("ready");
      } catch {
        if (!current) return;
        setShells([]);
        setShellLoadState("error");
      }
    })();
    return () => { current = false; };
  }, [shellSource]);

  const knownShell = shells.some((shell) => shell.id === terminal.localShell);
  const configuredCustom = terminal.localShell.length > 0
    && shellLoadState !== "loading"
    && !knownShell;
  const showCustomEditor = customEditing || configuredCustom;
  const shellSelectValue = showCustomEditor
    ? "__custom__"
    : terminal.localShell;

  useEffect(() => {
    if (!configuredCustom || customEditing) return;
    setCustomShellDraft(terminal.localShell);
    setCustomArgsDraft(formatLocalShellArgs(terminal.localShellArgs));
  }, [configuredCustom, customEditing, terminal.localShell, terminal.localShellArgs]);

  const parsedCustomArgs = useMemo(
    () => parseLocalShellArgs(customArgsDraft),
    [customArgsDraft],
  );
  const trimmedCustomShell = customShellDraft.trim();
  const customShellValid = isRendererSafeLocalShell(trimmedCustomShell)
    && isRendererSafeLocalShellArgs(parsedCustomArgs);

  const selectShell = (value: string) => {
    if (value === "__custom__") {
      setCustomShellDraft(configuredCustom ? terminal.localShell : "");
      setCustomArgsDraft(configuredCustom ? formatLocalShellArgs(terminal.localShellArgs) : "");
      setCustomEditing(true);
      return;
    }
    setCustomEditing(false);
    patch((draft) => {
      draft.terminal.localShell = value;
      draft.terminal.localShellArgs = [];
    });
  };

  const pickStartDirectory = async () => {
    if (pickingDirectory) return;
    setPickingDirectory(true);
    setDirectoryError(null);
    try {
      const selected = await chooseStartDirectory(t("settings.localShell.chooseDirectoryTitle"));
      if (selected === null) return;
      if (!isRendererSafeLocalStartDir(selected)) {
        setDirectoryError(t("settings.localShell.directorySaveError"));
        return;
      }
      patch((draft) => { draft.terminal.localStartDir = selected; });
    } catch {
      setDirectoryError(t("settings.localShell.directoryPickerError"));
    } finally {
      setPickingDirectory(false);
    }
  };

  return (
    <SettingRow
      id="terminal-local-shell"
      description={t("settings.localShell.description")}
    >
      <div style={{ display: "flex", width: 390, maxWidth: "52vw", flexDirection: "column", alignItems: "stretch", gap: 8 }}>
        <select
          aria-label={t("settings.localShell.label")}
          className="settings-select"
          value={shellSelectValue}
          onChange={(event) => selectShell(event.target.value)}
        >
          <option value="">{t("settings.common.systemDefault")}</option>
          {shellLoadState === "loading" && terminal.localShell && !knownShell ? (
            <option value={terminal.localShell}>{t("settings.localShell.savedShell")}</option>
          ) : null}
          {shells.map((shell) => (
            <option key={shell.id} value={shell.id}>
              {shell.name}{shell.isDefault ? t("settings.localShell.defaultSuffix") : ""}
            </option>
          ))}
          <option value="__custom__">{t("settings.localShell.customCommand")}</option>
        </select>
        {shellLoadState === "loading" ? <small>{t("settings.localShell.discovering")}</small> : null}
        {shellLoadState === "error" ? <small role="alert">{t("settings.localShell.discoveryError")}</small> : null}

        {showCustomEditor ? (
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <input
              aria-label={t("settings.localShell.customCommandLabel")}
              className="settings-text-input"
              style={{ width: "100%" }}
              value={customShellDraft}
              maxLength={LOCAL_SHELL_LIMITS.commandBytes}
              spellCheck={false}
              placeholder={t("settings.localShell.commandPlaceholder")}
              onChange={(event) => setCustomShellDraft(event.target.value)}
            />
            <input
              aria-label={t("settings.localShell.argumentsLabel")}
              className="settings-text-input"
              style={{ width: "100%" }}
              value={customArgsDraft}
              maxLength={LOCAL_SHELL_LIMITS.argumentCount * LOCAL_SHELL_LIMITS.argumentBytes}
              spellCheck={false}
              placeholder={t("settings.localShell.argumentsPlaceholder")}
              onChange={(event) => setCustomArgsDraft(event.target.value)}
            />
            {!customShellValid && customShellDraft.length > 0 ? (
              <small role="alert">{t("settings.localShell.commandLimitError")}</small>
            ) : null}
            <span style={{ display: "flex", justifyContent: "flex-end", gap: 6 }}>
              <button
                type="button"
                className="settings-secondary-button"
                onClick={() => {
                  setCustomShellDraft(terminal.localShell);
                  setCustomArgsDraft(formatLocalShellArgs(terminal.localShellArgs));
                  setCustomEditing(false);
                }}
              >
                {t("settings.common.cancel")}
              </button>
              <button
                type="button"
                className="settings-secondary-button"
                disabled={!customShellValid}
                onClick={() => {
                  patch((draft) => {
                    draft.terminal.localShell = trimmedCustomShell;
                    draft.terminal.localShellArgs = parsedCustomArgs;
                  });
                  setCustomEditing(false);
                }}
              >
                {t("settings.localShell.saveCommand")}
              </button>
            </span>
          </div>
        ) : null}

        <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <input
            aria-label={t("settings.localShell.startDirectory")}
            className="settings-text-input"
            style={{ width: "100%", minWidth: 0 }}
            value={terminal.localStartDir}
            maxLength={LOCAL_SHELL_LIMITS.startDirectoryBytes}
            spellCheck={false}
            placeholder={t("settings.localShell.directoryPlaceholder")}
            onChange={(event) => {
              if (!isRendererSafeLocalStartDir(event.target.value)) {
                setDirectoryError(t("settings.localShell.directoryLimitError"));
                return;
              }
              setDirectoryError(null);
              patch((draft) => { draft.terminal.localStartDir = event.target.value; });
            }}
          />
          <button
            type="button"
            className="settings-secondary-button"
            disabled={pickingDirectory}
            onClick={() => { void pickStartDirectory(); }}
          >
            {pickingDirectory ? t("settings.localShell.choosing") : t("settings.localShell.browse")}
          </button>
          <button
            type="button"
            className="settings-secondary-button"
            disabled={!terminal.localStartDir}
            onClick={() => {
              setDirectoryError(null);
              patch((draft) => { draft.terminal.localStartDir = ""; });
            }}
          >
            {t("settings.common.clear")}
          </button>
        </span>
        {directoryError ? <small role="alert">{directoryError}</small> : null}
      </div>
    </SettingRow>
  );
}

function TerminalPage({ settings, patch, localShellSource, chooseLocalStartDirectory }: PageProps) {
  const terminal = settings.terminal;
  const t = useSettingsTranslation();
  const toggle = (id: SettingsAnchorId, key: keyof typeof terminal) => (
    <SettingRow id={id}><Toggle label={settingsAnchorText(t, id)} checked={terminal[key] as boolean} onChange={(checked) => patch((draft) => { (draft.terminal[key] as boolean) = checked; })} /></SettingRow>
  );
  return (
    <div className="settings-page-body">
      <SectionTitle>{t("settings.terminal.theme")}</SectionTitle>
      <SettingsCard>{toggle("terminal-theme-follow-app", "followAppTheme")}</SettingsCard>
      <SectionTitle>{t("settings.terminal.font")}</SectionTitle>
      <SettingsCard>
        <SettingRow id="terminal-font-family"><SelectControl label={settingsAnchorText(t, "terminal-font-family")} value={terminal.fontFamilyId} onChange={(value) => patch((draft) => { draft.terminal.fontFamilyId = value; })} options={[{ value: "menlo", label: "Menlo" }, { value: "consolas", label: "Consolas" }, { value: "monospace", label: t("settings.terminal.systemMonospace") }]} /></SettingRow>
        <SettingRow id="terminal-font-cjk"><input className="settings-text-input" aria-label={settingsAnchorText(t, "terminal-font-cjk")} value={terminal.fallbackFont} onChange={(event) => patch((draft) => { draft.terminal.fallbackFont = event.target.value; })} placeholder={t("settings.common.systemDefault")} /></SettingRow>
        <SettingRow id="terminal-font-size"><NumberControl label={settingsAnchorText(t, "terminal-font-size")} value={terminal.fontSize} min={6} max={72} onChange={(value) => patch((draft) => { draft.terminal.fontSize = value; })} suffix="px" /></SettingRow>
        <SettingRow id="terminal-font-weight"><NumberControl label={settingsAnchorText(t, "terminal-font-weight")} value={terminal.fontWeight} min={100} max={900} step={100} onChange={(value) => patch((draft) => { draft.terminal.fontWeight = value; })} /></SettingRow>
        <SettingRow id="terminal-font-weight-bold"><NumberControl label={settingsAnchorText(t, "terminal-font-weight-bold")} value={terminal.boldFontWeight} min={100} max={900} step={100} onChange={(value) => patch((draft) => { draft.terminal.boldFontWeight = value; })} /></SettingRow>
        <SettingRow id="terminal-font-line-padding"><NumberControl label={settingsAnchorText(t, "terminal-font-line-padding")} value={terminal.linePadding} min={0} max={12} onChange={(value) => patch((draft) => { draft.terminal.linePadding = value; })} suffix="px" /></SettingRow>
      </SettingsCard>
      <SectionTitle>{t("settings.terminal.cursor")}</SectionTitle>
      <SettingsCard>
        <SettingRow id="terminal-cursor-style"><SelectControl label={settingsAnchorText(t, "terminal-cursor-style")} value={terminal.cursorStyle} onChange={(value) => patch((draft) => { draft.terminal.cursorStyle = value as typeof terminal.cursorStyle; })} options={[{ value: "block", label: t("settings.terminal.cursorBlock") }, { value: "underline", label: t("settings.terminal.cursorUnderline") }, { value: "bar", label: t("settings.terminal.cursorBar") }]} /></SettingRow>
        {toggle("terminal-cursor-blink", "cursorBlink")}
      </SettingsCard>
      <SectionTitle>{t("settings.terminal.keyboardAccessibility")}</SectionTitle>
      <SettingsCard>
        <SettingRow id="terminal-min-contrast"><NumberControl label={settingsAnchorText(t, "terminal-min-contrast")} value={terminal.minimumContrastRatio} min={1} max={21} step={0.5} onChange={(value) => patch((draft) => { draft.terminal.minimumContrastRatio = value; })} /></SettingRow>
      </SettingsCard>
      <SectionTitle>{t("settings.terminal.behavior")}</SectionTitle>
      <SettingsCard>
        <SettingRow id="terminal-scrollback-rows"><NumberControl label={settingsAnchorText(t, "terminal-scrollback-rows")} value={terminal.scrollbackRows} min={100} max={1_000_000} step={100} onChange={(value) => patch((draft) => { draft.terminal.scrollbackRows = value; })} /></SettingRow>
      </SettingsCard>
      <SectionTitle>{t("settings.terminal.localShell")}</SectionTitle>
      <SettingsCard>
        <LocalShellSettings
          terminal={terminal}
          patch={patch}
          shellSource={localShellSource}
          chooseStartDirectory={chooseLocalStartDirectory}
        />
      </SettingsCard>
      <SectionTitle>{t("settings.terminal.rendering")}</SectionTitle>
      <SettingsCard>
        <SettingRow id="terminal-renderer"><SelectControl label={settingsAnchorText(t, "terminal-renderer")} value={terminal.renderer} onChange={(value) => patch((draft) => { draft.terminal.renderer = value as typeof terminal.renderer; })} options={[{ value: "auto", label: t("settings.option.auto") }, { value: "webgl", label: "WebGL" }, { value: "canvas", label: "Canvas" }, { value: "dom", label: "DOM" }]} /></SettingRow>
      </SettingsCard>
    </div>
  );
}

function NumberControl({ label, value, min, max, step = 1, suffix, onChange }: { label: string; value: number; min: number; max: number; step?: number; suffix?: string; onChange: (value: number) => void }) {
  return <label className="settings-number"><input aria-label={label} type="number" value={value} min={min} max={max} step={step} onChange={(event) => onChange(Number(event.target.value))} />{suffix ? <span>{suffix}</span> : null}</label>;
}

function SftpPage({ settings, patch }: PageProps) {
  const sftp = settings.sftp;
  const t = useSettingsTranslation();
  return <div className="settings-page-body"><SectionTitle>SFTP</SectionTitle><SettingsCard>
    <SettingRow id="sftp-show-hidden-files"><Toggle label={settingsAnchorText(t, "sftp-show-hidden-files")} checked={sftp.showHiddenFiles} onChange={(checked) => patch((draft) => { draft.sftp.showHiddenFiles = checked; })} /></SettingRow>
    <SettingRow id="sftp-auto-open-sidebar"><Toggle label={settingsAnchorText(t, "sftp-auto-open-sidebar")} checked={sftp.autoOpenSidebar} onChange={(checked) => patch((draft) => { draft.sftp.autoOpenSidebar = checked; })} /></SettingRow>
  </SettingsCard></div>;
}

const AI_VISIBLE_TAB_IDS = ["ai-providers", "ai-tools", "ai-safety"] as const;

type AiProviderKeyState = "loading" | "saved" | "missing" | "saving" | "removing" | "error";
type AiModelCatalogState =
  | "idle"
  | "loading"
  | "ready"
  | "empty"
  | "error";
type SettingsSaveOutcome = "succeeded" | "failed";

let fallbackAiProfileSequence = 0;

const createUniqueAiProfileId = (profiles: readonly AiProviderProfile[]): string => {
  const existingIds = new Set(profiles.map((profile) => profile.id));
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const entropy = typeof crypto !== "undefined" && typeof crypto.randomUUID === "function"
      ? crypto.randomUUID()
      : `${Date.now().toString(36)}-${(++fallbackAiProfileSequence).toString(36)}`;
    const candidate = `ai-${entropy}`.toLowerCase();
    if (!existingIds.has(candidate)) return candidate;
  }
  return `ai-${Date.now().toString(36)}-${(++fallbackAiProfileSequence).toString(36)}`;
};

const aiProviderLabel = (t: Translate, providerId: string): string => {
  const preset = AI_PROVIDER_PRESETS.find((candidate) => candidate.id === providerId);
  return preset
    ? t(`ai.settings.providerPreset.${preset.id}` as MessageKey)
    : providerId;
};

const normalizedAiProfileEndpoint = (
  value: string,
  protocol: AiProviderProtocol,
): string | null => {
  try {
    const endpoint = new URL(value.trim());
    if (
      (endpoint.protocol !== "https:" && endpoint.protocol !== "http:")
      || endpoint.username
      || endpoint.password
      || endpoint.hash
    ) return null;
    const path = endpoint.pathname.replace(/\/+$/u, "");
    const suffix = protocol === "anthropicMessages" ? "/messages" : "/chat/completions";
    if (!path.endsWith(suffix)) {
      endpoint.pathname = path
        ? `${path}${suffix}`
        : protocol === "anthropicMessages"
          ? "/v1/messages"
          : "/chat/completions";
    }
    return endpoint.toString();
  } catch {
    return null;
  }
};

const isLoopbackAiProfileEndpoint = (value: string): boolean => {
  try {
    const endpoint = new URL(value.trim());
    const host = endpoint.hostname.toLocaleLowerCase().replace(/^\[|\]$/gu, "");
    return host === "localhost" || host === "::1" || /^127(?:\.\d{1,3}){3}$/u.test(host);
  } catch {
    return false;
  }
};

const aiModelCatalogFailureMessage = (error: unknown, t: Translate): string => {
  if (
    hasErrorCode(error, "AI_STORED_KEY_NOT_FOUND")
    || hasErrorCode(error, "AI_API_KEY_REQUIRED")
  ) return t("ai.settings.modelsFailedKeyMissing");
  if (
    hasErrorCode(error, "AI_HTTP_ERROR:401")
    || hasErrorCode(error, "AI_HTTP_ERROR:403")
  ) return t("ai.settings.modelsFailedAuthentication");
  if (hasErrorCode(error, "AI_HTTP_ERROR:404")) {
    return t("ai.settings.modelsFailedEndpoint");
  }
  if (hasErrorCode(error, "AI_HTTP_ERROR:429")) {
    return t("ai.settings.modelsFailedRateLimit");
  }
  if (/^AI_HTTP_ERROR:5\d{2}(?::|$)/u.test(errorText(error).trim())) {
    return t("ai.settings.modelsFailedProvider");
  }
  if (
    hasErrorCode(error, "AI_TIMEOUT")
    || hasErrorCode(error, "AI_REQUEST_FAILED")
    || hasErrorCode(error, "AI_CLIENT_UNAVAILABLE")
  ) return t("ai.settings.modelsFailedNetwork");
  if (
    hasErrorCode(error, "AI_RESPONSE_INVALID")
    || hasErrorCode(error, "AI_RESPONSE_TOO_LARGE")
    || hasErrorCode(error, "AI_MODELS_TOO_MANY")
  ) return t("ai.settings.modelsFailedCompatibility");
  return t("ai.settings.modelsFailedWithReason", {
    reason: localizeAiError(error, t),
  });
};

function AiProviderCard({
  profile,
  active,
  canDelete,
  editing,
  editLocked,
  settingsReady,
  waitForSettingsSave,
  onEdit,
  onCancelEdit,
  onSave,
  onActivate,
  onDelete,
}: {
  profile: AiProviderProfile;
  active: boolean;
  canDelete: boolean;
  editing: boolean;
  editLocked: boolean;
  settingsReady: boolean;
  waitForSettingsSave: () => Promise<SettingsSaveOutcome>;
  onEdit: () => void;
  onCancelEdit: () => void;
  onSave: (profile: AiProviderProfile, activate: boolean) => Promise<SettingsSaveOutcome>;
  onActivate: () => void;
  onDelete: () => void;
}) {
  const t = useSettingsTranslation();
  const [draft, setDraft] = useState<AiProviderProfile>(() => structuredClone(profile));
  const [formError, setFormError] = useState("");
  const [deleteConfirming, setDeleteConfirming] = useState(false);
  const [keyDraft, setKeyDraft] = useState("");
  const [keyState, setKeyState] = useState<AiProviderKeyState>("loading");
  const [keyNotice, setKeyNotice] = useState("");
  const [modelCatalogState, setModelCatalogState] = useState<AiModelCatalogState>("idle");
  const [modelCatalogError, setModelCatalogError] = useState("");
  const [availableModels, setAvailableModels] = useState<readonly string[]>([]);
  const [operationState, setOperationState] = useState<"idle" | "connecting" | "saving">("idle");
  const operationLockRef = useRef(false);
  const keySequenceRef = useRef(0);
  const modelSequenceRef = useRef(0);

  useEffect(() => {
    if (!editing) return;
    setDraft(structuredClone(profile));
    setFormError("");
    setKeyNotice("");
  }, [editing, profile.id]);

  useEffect(() => { setDeleteConfirming(false); }, [profile.id]);

  useEffect(() => {
    modelSequenceRef.current += 1;
    setAvailableModels([]);
    setModelCatalogState("idle");
    setModelCatalogError("");
  }, [draft.baseUrl, draft.protocol, draft.providerId, profile.id]);

  useEffect(() => () => { modelSequenceRef.current += 1; }, []);

  const cancelEdit = useCallback(() => {
    keySequenceRef.current += 1;
    modelSequenceRef.current += 1;
    setDraft(structuredClone(profile));
    setKeyDraft("");
    setKeyNotice("");
    setFormError("");
    setAvailableModels([]);
    setModelCatalogState("idle");
    setModelCatalogError("");
    onCancelEdit();
  }, [onCancelEdit, profile]);

  const refreshKeyState = useCallback(async () => {
    const sequence = ++keySequenceRef.current;
    if (!settingsReady) {
      setKeyState("loading");
      return;
    }
    if (!isTauri()) {
      setKeyState("missing");
      return;
    }
    setKeyState("loading");
    try {
      const settingsSaveOutcome = await waitForSettingsSave();
      if (keySequenceRef.current !== sequence) return;
      if (settingsSaveOutcome !== "succeeded") {
        setKeyState("error");
        return;
      }
      const present = await hasSavedAiApiKey(profile.id);
      if (keySequenceRef.current === sequence) setKeyState(present ? "saved" : "missing");
    } catch {
      if (keySequenceRef.current === sequence) setKeyState("error");
    }
  }, [profile.id, settingsReady, waitForSettingsSave]);

  useEffect(() => {
    setKeyDraft("");
    setKeyNotice("");
    void refreshKeyState();
    return () => { keySequenceRef.current += 1; };
  }, [editing, refreshKeyState]);

  const removeKey = useCallback(async () => {
    const sequence = ++keySequenceRef.current;
    setKeyState("removing");
    setKeyNotice("");
    try {
      const settingsSaveOutcome = await waitForSettingsSave();
      if (keySequenceRef.current !== sequence) return;
      if (settingsSaveOutcome !== "succeeded") {
        setKeyState("error");
        setKeyNotice(t("ai.settings.keyError"));
        return;
      }
      await deleteSavedAiApiKey(profile.id);
      if (keySequenceRef.current !== sequence) return;
      setKeyDraft("");
      setKeyState("missing");
      setKeyNotice(t("ai.settings.keyRemoved"));
    } catch {
      if (keySequenceRef.current === sequence) {
        setKeyState("error");
        setKeyNotice(t("ai.settings.keyError"));
      }
    }
  }, [profile.id, t, waitForSettingsSave]);

  const deleteProfile = useCallback(async () => {
    const sequence = ++keySequenceRef.current;
    setKeyNotice("");
    try {
      const settingsSaveOutcome = await waitForSettingsSave();
      if (keySequenceRef.current !== sequence) return;
      if (settingsSaveOutcome !== "succeeded") {
        setDeleteConfirming(false);
        setKeyNotice(t("ai.settings.keyError"));
        return;
      }
      if (isTauri()) await deleteSavedAiApiKey(profile.id);
      if (keySequenceRef.current !== sequence) return;
      onDelete();
    } catch {
      if (keySequenceRef.current === sequence) {
        setDeleteConfirming(false);
        setKeyNotice(t("ai.settings.keyError"));
      }
    }
  }, [onDelete, profile.id, t, waitForSettingsSave]);

  const validatedDraft = useCallback((requireModel: boolean): AiProviderProfile | null => {
    const next = {
      ...draft,
      name: draft.name.trim(),
      baseUrl: draft.baseUrl.trim(),
      model: draft.model.trim(),
    };
    if (!next.name || !next.baseUrl || (requireModel && !next.model)) {
      setFormError(t(requireModel
        ? "ai.settings.profileFieldsRequired"
        : "ai.settings.connectionFieldsRequired"));
      return null;
    }
    const nextEndpoint = normalizedAiProfileEndpoint(next.baseUrl, next.protocol);
    if (!nextEndpoint) {
      setFormError(t("ai.settings.profileUrlInvalid"));
      return null;
    }
    const currentEndpoint = normalizedAiProfileEndpoint(profile.baseUrl, profile.protocol);
    if (
      currentEndpoint
      && nextEndpoint !== currentEndpoint
      && isTauri()
      && keyState !== "missing"
      && keyDraft.trim().length === 0
    ) {
      setFormError(t("ai.settings.removeKeyBeforeEndpointChange"));
      return null;
    }
    if (new TextEncoder().encode(next.name).byteLength > 256) {
      setFormError(t("ai.settings.profileNameTooLong"));
      return null;
    }
    setFormError("");
    return next;
  }, [draft, keyDraft, keyState, profile.baseUrl, profile.protocol, t]);

  const hasCredentialFor = useCallback((next: AiProviderProfile): boolean => (
    !isTauri()
    || (next.protocol === "openAiChatCompletions" && isLoopbackAiProfileEndpoint(next.baseUrl))
    || keyDraft.trim().length > 0
    || keyState === "saved"
  ), [keyDraft, keyState]);

  const persistDraftKey = useCallback(async (next: AiProviderProfile): Promise<boolean> => {
    if (!hasCredentialFor(next)) {
      setFormError(t("ai.settings.keyRequiredForRemote"));
      return false;
    }
    if (!keyDraft.trim()) return true;

    const sequence = ++keySequenceRef.current;
    setKeyState("saving");
    setKeyNotice("");
    try {
      await saveAiApiKey(profile.id, keyDraft);
      if (keySequenceRef.current !== sequence) return false;
      setKeyDraft("");
      setKeyState("saved");
      setKeyNotice(t("ai.settings.keySaved"));
      return true;
    } catch {
      if (keySequenceRef.current === sequence) {
        setKeyState("error");
        setKeyNotice(t("ai.settings.keyError"));
      }
      return false;
    }
  }, [hasCredentialFor, keyDraft, profile.id, t]);

  const connectAndFetchModels = useCallback(async () => {
    if (
      !settingsReady
      || operationState !== "idle"
      || operationLockRef.current
      || keyState === "loading"
    ) return;
    const next = validatedDraft(false);
    if (!next || !hasCredentialFor(next)) {
      if (next) setFormError(t("ai.settings.keyRequiredForRemote"));
      return;
    }

    operationLockRef.current = true;
    setOperationState("connecting");
    setFormError("");
    setKeyNotice("");
    setModelCatalogError("");
    try {
      const profileOutcome = await onSave(next, false);
      if (profileOutcome !== "succeeded") {
        setFormError(t("ai.settings.profileSaveFailed"));
        return;
      }
      if (!await persistDraftKey(next)) return;
      const sequence = ++modelSequenceRef.current;
      setModelCatalogState("loading");
      setAvailableModels([]);
      try {
        const models = await listAiModels(profile.id);
        if (modelSequenceRef.current !== sequence) return;
        setAvailableModels(models);
        setModelCatalogError("");
        setModelCatalogState(models.length > 0 ? "ready" : "empty");
      } catch (error) {
        if (modelSequenceRef.current !== sequence) return;
        if (hasErrorCode(error, "AI_MODELS_EMPTY")) {
          setModelCatalogError("");
          setModelCatalogState("empty");
        } else {
          setModelCatalogError(aiModelCatalogFailureMessage(error, t));
          setModelCatalogState("error");
        }
      }
    } finally {
      operationLockRef.current = false;
      setOperationState("idle");
    }
  }, [hasCredentialFor, keyState, onSave, operationState, persistDraftKey, profile.id, settingsReady, t, validatedDraft]);

  const saveAndUse = useCallback(async () => {
    if (
      !settingsReady
      || operationState !== "idle"
      || operationLockRef.current
      || keyState === "loading"
    ) return;
    const next = validatedDraft(true);
    if (!next || !hasCredentialFor(next)) {
      if (next) setFormError(t("ai.settings.keyRequiredForRemote"));
      return;
    }

    operationLockRef.current = true;
    setOperationState("saving");
    setFormError("");
    try {
      const profileOutcome = await onSave(next, false);
      if (profileOutcome !== "succeeded") {
        setFormError(t("ai.settings.profileSaveFailed"));
        return;
      }
      if (!await persistDraftKey(next)) return;
      const activationOutcome = await onSave({ ...next, enabled: true }, true);
      if (activationOutcome !== "succeeded") {
        setFormError(t("ai.settings.profileSaveFailed"));
        return;
      }
      onCancelEdit();
    } finally {
      operationLockRef.current = false;
      setOperationState("idle");
    }
  }, [hasCredentialFor, keyState, onCancelEdit, onSave, operationState, persistDraftKey, settingsReady, t, validatedDraft]);

  const keyStatus = keyState === "loading"
    ? t("ai.settings.checkingKey")
    : keyState === "saving"
      ? t("ai.settings.savingKey")
      : keyState === "removing"
        ? t("ai.settings.removingKey")
        : keyState === "saved"
          ? t("ai.settings.savedKey")
          : keyState === "missing"
            ? t("ai.settings.missingKey")
            : keyNotice || t("ai.settings.keyError");

  const modelCatalogMessage = modelCatalogState === "loading"
    ? t("ai.settings.modelsLoading")
    : modelCatalogState === "ready"
      ? t("ai.settings.modelsLoaded", { count: availableModels.length })
      : modelCatalogState === "empty"
        ? t("ai.settings.modelsEmpty")
        : modelCatalogState === "error"
          ? modelCatalogError || t("ai.settings.modelsFailed")
          : t("ai.settings.modelsDescription");

  return (
    <article className={`settings-ai-profile ${active ? "active" : ""} ${profile.enabled ? "" : "disabled"} ${editing ? "editing" : ""}`} data-provider-profile-id={profile.id}>
      <div className="settings-ai-profile-header">
        <span className="settings-ai-profile-logo" data-provider={profile.providerId} aria-hidden="true">{profile.name.trim().slice(0, 1).toLocaleUpperCase() || "AI"}</span>
        <div className="settings-ai-profile-heading">
          <div className="settings-ai-profile-title-row">
            <strong>{profile.name}</strong>
          </div>
          <div className="settings-ai-profile-statuses">
            {active ? <span className="settings-ai-badge active">{t("ai.settings.activeBadge")}</span> : null}
            {!profile.enabled ? <span className="settings-ai-badge">{t("ai.settings.disabledBadge")}</span> : null}
            <span className={`settings-ai-key-status ${keyState}`}>{keyStatus}</span>
          </div>
          <div className="settings-ai-profile-meta">
            <span>{aiProviderLabel(t, profile.providerId)} · {profile.protocol === "anthropicMessages" ? t("ai.settings.protocolAnthropicMessages") : t("ai.settings.protocolOpenAiChat")}</span>
            <span title={profile.model}>{profile.model}</span>
            <small title={profile.baseUrl}>{profile.baseUrl}</small>
          </div>
        </div>
        {!editing ? (
          <div className="settings-ai-profile-actions">
            <button type="button" className="settings-secondary-button" disabled={active || !profile.enabled || operationState !== "idle"} onClick={onActivate}>{active ? t("ai.settings.activeAction") : t("ai.settings.activateAction")}</button>
            <button type="button" className="settings-link-button" disabled={editLocked} onClick={onEdit}>{t("ai.settings.editAction")}</button>
            <button type="button" className="settings-link-button danger" disabled={!canDelete || operationState !== "idle"} onClick={() => setDeleteConfirming(true)}>{t("ai.settings.deleteAction")}</button>
          </div>
        ) : null}
      </div>

      {deleteConfirming ? (
        <div className="settings-ai-delete-confirm" role="alertdialog" aria-label={t("ai.settings.deleteConfirm", { name: profile.name })}>
          <span>{t("ai.settings.deleteConfirm", { name: profile.name })}</span>
          <div>
            <button type="button" className="settings-link-button" onClick={() => setDeleteConfirming(false)}>{t("ai.settings.cancelEdit")}</button>
            <button type="button" className="settings-secondary-button danger" onClick={() => void deleteProfile()}>{t("ai.settings.deleteAction")}</button>
          </div>
        </div>
      ) : null}

      {editing ? (
        <div className="settings-ai-profile-editor settings-ai-unified-form">
          <div className="settings-ai-editor-actions settings-ai-save-bar">
            <button type="button" className="settings-secondary-button" disabled={operationState !== "idle"} onClick={cancelEdit}>{t("ai.settings.cancelEdit")}</button>
            <button
              type="button"
              className="settings-secondary-button"
              disabled={!settingsReady || operationState !== "idle" || keyState === "loading" || keyState === "saving" || keyState === "removing"}
              onClick={() => void connectAndFetchModels()}
            >
              {operationState === "connecting"
                ? t("ai.settings.connectingAndFetching")
                : modelCatalogState === "ready"
                  ? t("ai.settings.modelsRefreshAction")
                  : t("ai.settings.connectAndFetchModels")}
            </button>
            <button
              type="button"
              className="settings-primary-button"
              disabled={!settingsReady || operationState !== "idle" || keyState === "loading" || keyState === "saving" || keyState === "removing"}
              onClick={() => void saveAndUse()}
            >
              {operationState === "saving" ? t("ai.settings.savingAndUsing") : t("ai.settings.saveAndUse")}
            </button>
          </div>

          <div className="settings-ai-compact-grid">
            <label className="settings-ai-field settings-ai-name-field">{t("ai.settings.profileName")}
              <input className="settings-text-input" value={draft.name} maxLength={256} disabled={operationState !== "idle"} onChange={(event) => setDraft((current) => ({ ...current, name: event.target.value }))} />
            </label>
            <label className="settings-ai-field settings-ai-protocol-field">{t("ai.settings.protocol")}
              <select
                className="settings-select settings-ai-protocol-select"
                value={draft.protocol}
                disabled={operationState !== "idle"}
                onChange={(event) => setDraft((current) => ({ ...current, protocol: event.target.value as AiProviderProtocol }))}
              >
                <option value="openAiChatCompletions">{t("ai.settings.protocolOpenAiChat")}</option>
                <option value="anthropicMessages">{t("ai.settings.protocolAnthropicMessages")}</option>
              </select>
            </label>

            <label className="settings-ai-field settings-ai-endpoint-field">{t("ai.baseUrl")}
              <input className="settings-text-input" value={draft.baseUrl} maxLength={2_048} disabled={operationState !== "idle"} spellCheck={false} onChange={(event) => {
                setDraft((current) => ({ ...current, baseUrl: event.target.value }));
              }} />
            </label>

            <div className="settings-ai-key-row settings-ai-field-wide">
              <label className="settings-ai-field settings-ai-key-field">{t("ai.settings.apiKeyLabel")}
                <input
                  className="settings-text-input"
                  type="password"
                  value={keyDraft}
                  maxLength={2_048}
                  autoComplete="off"
                  spellCheck={false}
                  disabled={operationState !== "idle" || keyState === "saving" || keyState === "removing"}
                  placeholder={keyState === "saved" ? t("ai.settings.keySavedKeepHint") : t("ai.settings.keyPlaceholder")}
                  onChange={(event) => setKeyDraft(event.target.value)}
                />
              </label>
              <div className="settings-ai-key-controls">
                <span className={`settings-ai-key-status ${keyState}`}>{keyStatus}</span>
                <button
                  type="button"
                  className="settings-link-button"
                  disabled={!isTauri() || operationState !== "idle" || keyState === "missing" || keyState === "loading" || keyState === "saving" || keyState === "removing"}
                  onClick={() => void removeKey()}
                >
                  {keyState === "removing" ? t("ai.settings.removingKey") : t("ai.settings.removeKey")}
                </button>
              </div>
              {keyNotice ? <p className="settings-ai-key-notice" role="status">{keyNotice}</p> : null}
            </div>

            <div className="settings-ai-model-row settings-ai-field-wide">
              <label className="settings-ai-field settings-ai-model-select-field">{t("ai.model")}
                <select
                  className="settings-select"
                  value={draft.model}
                  disabled={operationState !== "idle"}
                  onChange={(event) => setDraft((current) => ({ ...current, model: event.target.value }))}
                >
                  {!draft.model.trim() ? <option value="">{t("ai.settings.modelPlaceholder")}</option> : null}
                  {draft.model.trim() && !availableModels.includes(draft.model) ? <option value={draft.model}>{draft.model}</option> : null}
                  {availableModels.map((model) => <option key={model} value={model}>{model}</option>)}
                </select>
              </label>
              <p
                className={`settings-ai-model-status ${modelCatalogState}`}
                role={modelCatalogState === "error" ? "alert" : "status"}
              >
                {modelCatalogMessage}
              </p>
            </div>
          </div>

          <details className="settings-ai-advanced">
            <summary>{t("ai.settings.advancedOptions")}</summary>
            <div className="settings-ai-advanced-grid">
              <label className="settings-ai-field">{t("ai.settings.chooseProvider")}
                <select className="settings-select" value={draft.providerId} disabled={operationState !== "idle"} onChange={(event) => {
                  const preset = AI_PROVIDER_PRESETS.find((candidate) => candidate.id === event.target.value);
                  if (!preset) return;
                  setDraft((current) => ({
                    ...current,
                    providerId: preset.id,
                    name: preset.label,
                    baseUrl: preset.baseUrl,
                    model: preset.model,
                    protocol: preset.protocol,
                  }));
                }}>
                  {!AI_PROVIDER_PRESETS.some((preset) => preset.id === draft.providerId) ? <option value={draft.providerId}>{draft.providerId}</option> : null}
                  {AI_PROVIDER_PRESETS.map((preset) => <option key={preset.id} value={preset.id}>{aiProviderLabel(t, preset.id)}</option>)}
                </select>
              </label>
              <label className="settings-ai-field">{t("ai.settings.manualModel")}
                <input
                  className="settings-text-input"
                  value={draft.model}
                  maxLength={256}
                  disabled={operationState !== "idle"}
                  spellCheck={false}
                  placeholder={t("ai.settings.modelPlaceholder")}
                  onChange={(event) => setDraft((current) => ({ ...current, model: event.target.value }))}
                />
              </label>
              <p className="settings-ai-advanced-note settings-ai-field-wide">
                {t("ai.settings.endpointHint")} {t("ai.settings.connectionTestDescription")} {isTauri() ? t("ai.settings.keySecurityProfile") : t("ai.settings.previewOnly")}
              </p>
            </div>
          </details>

          {formError ? <p className="settings-ai-form-error" role="alert">{formError}</p> : null}
        </div>
      ) : null}
    </article>
  );
}

function AiSettingsPage({
  settings,
  patch,
  waitForSettingsSave,
  settingsReady,
  nestedTab,
  setNestedTab,
}: PageProps) {
  const t = useSettingsTranslation();
  const selected = AI_VISIBLE_TAB_IDS.includes(nestedTab as (typeof AI_VISIBLE_TAB_IDS)[number])
    ? nestedTab as (typeof AI_VISIBLE_TAB_IDS)[number]
    : "ai-providers";
  const [addingProvider, setAddingProvider] = useState(false);
  const [selectedPresetId, setSelectedPresetId] = useState(AI_PROVIDER_PRESETS[0].id);
  const [editingProviderId, setEditingProviderId] = useState<string | null>(null);

  const addProvider = (preset: AiProviderPreset) => {
    if (settings.ai.providers.length >= AI_PROVIDER_PROFILE_LIMIT || editingProviderId !== null) return;
    const id = createUniqueAiProfileId(settings.ai.providers);
    // Match the legacy workflow: a newly added profile is configured first and
    // cannot appear in the chat switcher until the user explicitly enables it.
    const profile = { ...createAiProviderProfile(preset, id), enabled: false };
    patch((draft) => { draft.ai.providers.push(profile); });
    setAddingProvider(false);
    setEditingProviderId(id);
  };

  const editProvider = (profileId: string) => {
    if (editingProviderId !== null && editingProviderId !== profileId) return;
    setAddingProvider(false);
    setEditingProviderId(profileId);
  };

  const saveProvider = (
    profile: AiProviderProfile,
    activate: boolean,
  ): Promise<SettingsSaveOutcome> => patch((draft) => {
      const index = draft.ai.providers.findIndex((candidate) => candidate.id === profile.id);
      if (index >= 0) draft.ai.providers[index] = profile;
      if (activate) draft.ai.activeProviderId = profile.id;
    });

  const deleteProvider = (profileId: string) => {
    patch((draft) => {
      if (draft.ai.providers.length <= 1) return;
      const remaining = draft.ai.providers.filter((profile) => profile.id !== profileId);
      if (draft.ai.activeProviderId === profileId) {
        const replacement = remaining.find((profile) => profile.enabled) ?? remaining[0];
        replacement.enabled = true;
        draft.ai.activeProviderId = replacement.id;
      }
      draft.ai.providers = remaining;
    });
    if (editingProviderId === profileId) setEditingProviderId(null);
  };

  const permissionControl = (id: "ai-tool-access-mode" | "ai-safety-permission-mode") => (
    <SettingsCard>
      <SettingRow id={id} label={t("ai.settings.permissionTitle")} description={t("ai.settings.permissionDescription")}>
        <SelectControl
          label={t("ai.settings.permissionTitle")}
          value={settings.ai.commandPermissionMode}
          onChange={(value) => patch((draft) => {
            draft.ai.commandPermissionMode = value as RendererSafeSettings["ai"]["commandPermissionMode"];
          })}
          options={[
            { value: "confirm", label: t("ai.settings.permissionAsk") },
            { value: "auto", label: t("ai.settings.permissionAuto") },
            { value: "observer", label: t("ai.settings.permissionDeny") },
          ]}
        />
      </SettingRow>
    </SettingsCard>
  );

  const tabLabels: Record<(typeof AI_VISIBLE_TAB_IDS)[number], string> = {
    "ai-providers": t("ai.settings.tabs.providers"),
    "ai-tools": t("ai.settings.tabs.tools"),
    "ai-safety": t("ai.settings.tabs.safety"),
  };

  return (
    <div className={`settings-page-body ${selected === "ai-providers" ? "settings-ai-provider-page" : ""}`}>
      <div className="settings-nested-tabs">
        {AI_VISIBLE_TAB_IDS.map((id) => <button type="button" key={id} className={selected === id ? "active" : ""} onClick={() => setNestedTab(id)}>{tabLabels[id]}</button>)}
      </div>
      {selected === "ai-providers" ? (
        <>
          <SectionTitle>{t("ai.settings.providerTitle")}</SectionTitle>
          <SettingsAnchor id="ai-providers">
            <div className="settings-ai-provider-toolbar">
              <div>
                <p className="settings-ai-description">{t("ai.settings.providerDescription")}</p>
                <small>{t("ai.settings.providerCount", { count: settings.ai.providers.length })}</small>
              </div>
              <button type="button" className="settings-primary-button" disabled={settings.ai.providers.length >= AI_PROVIDER_PROFILE_LIMIT || editingProviderId !== null} onClick={() => setAddingProvider((current) => !current)}>{t("ai.settings.addProvider")}</button>
            </div>
            {addingProvider ? (
              <SettingsCard className="settings-ai-add-card">
                <div>
                  <strong>{t("ai.settings.chooseProvider")}</strong>
                  <small>{t("ai.settings.chooseProviderDescription")}</small>
                </div>
                <select className="settings-select" aria-label={t("ai.settings.chooseProvider")} value={selectedPresetId} onChange={(event) => setSelectedPresetId(event.target.value)}>
                  {AI_PROVIDER_PRESETS.map((preset) => <option key={preset.id} value={preset.id}>{aiProviderLabel(t, preset.id)}</option>)}
                </select>
                <div className="settings-ai-add-preview">
                  <span>{AI_PROVIDER_PRESETS.find((preset) => preset.id === selectedPresetId)?.baseUrl}</span>
                  <span>{AI_PROVIDER_PRESETS.find((preset) => preset.id === selectedPresetId)?.model}</span>
                </div>
                <div className="settings-ai-editor-actions">
                  <button type="button" className="settings-link-button" onClick={() => setAddingProvider(false)}>{t("ai.settings.cancelEdit")}</button>
                  <button type="button" className="settings-primary-button" onClick={() => {
                    const preset = AI_PROVIDER_PRESETS.find((candidate) => candidate.id === selectedPresetId);
                    if (preset) addProvider(preset);
                  }}>{t("ai.settings.createProvider")}</button>
                </div>
              </SettingsCard>
            ) : null}
            <div className={`settings-ai-provider-list ${editingProviderId !== null ? "is-editing" : ""}`}>
              {settings.ai.providers.map((profile) => (
                <AiProviderCard
                  key={profile.id}
                  profile={profile}
                  active={profile.id === settings.ai.activeProviderId}
                  canDelete={settings.ai.providers.length > 1}
                  editing={editingProviderId === profile.id}
                  editLocked={editingProviderId !== null && editingProviderId !== profile.id}
                  settingsReady={settingsReady}
                  waitForSettingsSave={waitForSettingsSave}
                  onEdit={() => editProvider(profile.id)}
                  onCancelEdit={() => setEditingProviderId(null)}
                  onSave={saveProvider}
                  onActivate={() => patch((draft) => { draft.ai.activeProviderId = profile.id; })}
                  onDelete={() => deleteProvider(profile.id)}
                />
              ))}
            </div>
            {settings.ai.providers.length >= AI_PROVIDER_PROFILE_LIMIT ? <p className="settings-ai-unavailable-copy">{t("ai.settings.providerLimit", { count: AI_PROVIDER_PROFILE_LIMIT })}</p> : null}
          </SettingsAnchor>
        </>
      ) : selected === "ai-tools" ? (
        <>
          <SectionTitle>{tabLabels[selected]}</SectionTitle>
          {permissionControl("ai-tool-access-mode")}
          <SettingsCard>
            <SettingRow
              id="ai-terminal-execute"
              label={t("ai.settings.terminalToolTitle")}
              description={t("ai.settings.terminalToolDescription")}
            >
              <span className="settings-static-value">{t("ai.settings.terminalToolAvailable")}</span>
            </SettingRow>
          </SettingsCard>
        </>
      ) : selected === "ai-safety" ? (
        <>
          <SectionTitle>{t("ai.settings.safetyTitle")}</SectionTitle>
          {permissionControl("ai-safety-permission-mode")}
          <SettingsCard>
            <SettingRow
              id="ai-safety-response-timeout"
              description={t("ai.settings.safety.responseTimeoutDescription")}
            >
              <NumberControl
                label={settingsAnchorText(t, "ai-safety-response-timeout")}
                value={settings.ai.responseIdleTimeoutSeconds}
                min={AI_RESPONSE_IDLE_TIMEOUT_MIN_SECONDS}
                max={AI_RESPONSE_IDLE_TIMEOUT_MAX_SECONDS}
                onChange={(value) => patch((draft) => {
                  draft.ai.responseIdleTimeoutSeconds = value;
                })}
                suffix={t("ai.settings.safety.responseTimeoutUnit")}
              />
            </SettingRow>
            <SettingRow id="ai-safety-command-timeout">
              <span className="settings-static-value">{t("ai.settings.safety.timeoutValue")}</span>
            </SettingRow>
            <SettingRow id="ai-safety-blocklist">
              <span className="settings-static-value">{t("ai.settings.safety.blocklistValue")}</span>
            </SettingRow>
            <SettingRow id="ai-safety-grants">
              <span className="settings-static-value">{t("ai.settings.safety.grantsValue")}</span>
            </SettingRow>
          </SettingsCard>
          <p className="settings-ai-unavailable-copy">{t("ai.settings.safety.limitsDescription")}</p>
        </>
      ) : null}
    </div>
  );
}

function SystemPage({ settings, patch }: PageProps) {
  const system = settings.system;
  const t = useSettingsTranslation();
  return <div className="settings-page-body">
    <SectionTitle>{t("settings.system.startupSessions")}</SectionTitle>
    <SettingsCard>
      <SettingRow id="system-session-restore">
        <Toggle label={settingsAnchorText(t, "system-session-restore")} checked={system.restorePreviousSession} onChange={(checked) => patch((draft) => { draft.system.restorePreviousSession = checked; })} />
      </SettingRow>
    </SettingsCard>
  </div>;
}

function SettingsPage({ id, ...props }: PageProps & { id: SettingsPageId }) {
  switch (id) {
    case "application": return <ApplicationPage {...props} />;
    case "appearance": return <AppearancePage {...props} />;
    case "terminal": return <TerminalPage {...props} />;
    case "shortcuts": return null;
    case "file-associations": return <SftpPage {...props} />;
    case "ai": return <AiSettingsPage {...props} />;
    case "sync": return null;
    case "plugins": return null;
    case "system": return <SystemPage {...props} />;
  }
}

export function SettingsWorkspace({
  adapter,
  appVersion = "0.1.0",
  initialPage = "application",
  onClose,
  onNativeAction,
  localShellSource = defaultLocalShellSource,
  chooseLocalStartDirectory = defaultLocalStartDirectoryPicker,
}: SettingsWorkspaceProps) {
  const platform = useMemo(() => detectSettingsPlatform(), []);
  const initialWindowTarget = useMemo(() => readInitialSettingsWindowTarget(), []);
  const resolvedInitialPage: SettingsPageId = initialWindowTarget === "ai-providers"
    ? "ai"
    : isPublicSettingsPageId(initialPage)
      ? initialPage
      : "application";
  const [settings, setSettings] = useState(() => createDefaultRendererSafeSettings(platform));
  useAppColorMode(settings.appearance.colorMode);
  useUiFontFamily(settings.appearance.uiFontFamilyId);
  const settingsRef = useRef(settings);
  const locale = normalizeLocale(settings.appearance.uiLanguage);
  const { t } = useI18n(locale);
  const [activePage, setActivePage] = useState<SettingsPageId>(resolvedInitialPage);
  const [mountedPages, setMountedPages] = useState<Set<SettingsPageId>>(() => new Set([resolvedInitialPage]));
  const [nestedTab, setNestedTab] = useState<SettingsNestedTab>("ai-providers");
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchIndex, setSearchIndex] = useState(0);
  const [pendingAnchor, setPendingAnchor] = useState<SettingsAnchorId | null>(
    initialWindowTarget === "ai-providers" ? "ai-providers" : null,
  );
  const [loading, setLoading] = useState(adapter !== undefined);
  const [saveState, setSaveState] = useState<"idle" | "saving" | "saved" | "error">("idle");
  const revisionRef = useRef<unknown>(null);
  const saveQueueRef = useRef<Promise<SettingsSaveOutcome>>(Promise.resolve("succeeded"));
  const mutationSequenceRef = useRef(0);
  const loadSequenceRef = useRef(0);
  const searchInputRef = useRef<HTMLInputElement>(null);

  const focusSettingsWindowTarget = useCallback((target: SettingsWindowTarget) => {
    if (target !== "ai-providers") return;
    setMountedPages((current) => current.has("ai") ? current : new Set([...current, "ai"]));
    setActivePage("ai");
    setNestedTab("ai-providers");
    setPendingAnchor("ai-providers");
  }, []);

  useEffect(() => {
    const handleSettingsFocus = (event: Event) => {
      if (!(event instanceof CustomEvent) || !isSettingsWindowTarget(event.detail)) return;
      focusSettingsWindowTarget(event.detail);
    };
    window.addEventListener(SETTINGS_WINDOW_FOCUS_EVENT, handleSettingsFocus);
    return () => window.removeEventListener(SETTINGS_WINDOW_FOCUS_EVENT, handleSettingsFocus);
  }, [focusSettingsWindowTarget]);

  useEffect(() => {
    document.documentElement.lang = locale;
    const title = t("app.settingsWindowTitle");
    document.title = title;
    if (isTauri()) {
      void import("@tauri-apps/api/window")
        .then(({ getCurrentWindow }) => getCurrentWindow().setTitle(title))
        .catch(() => undefined);
    }
  }, [locale, t]);

  const loadSettings = useCallback(async (showLoading: boolean): Promise<void> => {
    if (!adapter) {
      setLoading(false);
      return;
    }
    const sequence = ++loadSequenceRef.current;
    if (showLoading) setLoading(true);
    try {
      const settingsSaveOutcome = await saveQueueRef.current;
      if (settingsSaveOutcome !== "succeeded") {
        if (sequence === loadSequenceRef.current) {
          setSaveState("error");
          setLoading(false);
        }
        return;
      }
      const mutationSequence = mutationSequenceRef.current;
      const snapshot = await adapter.load();
      if (
        sequence !== loadSequenceRef.current
        || mutationSequence !== mutationSequenceRef.current
      ) return;
      revisionRef.current = snapshot.inventoryRevision;
      settingsRef.current = snapshot.settings;
      setSettings(snapshot.settings);
      setSaveState("idle");
      setLoading(false);
    } catch {
      if (sequence === loadSequenceRef.current) {
        setSaveState("error");
        setLoading(false);
      }
    }
  }, [adapter]);

  useEffect(() => {
    void loadSettings(true);
    return () => { loadSequenceRef.current += 1; };
  }, [loadSettings]);

  useEffect(() => {
    if (!adapter) return;
    const reloadVisibleSettings = () => {
      if (document.visibilityState !== "hidden") void loadSettings(false);
    };
    window.addEventListener("focus", reloadVisibleSettings);
    document.addEventListener("visibilitychange", reloadVisibleSettings);
    return () => {
      window.removeEventListener("focus", reloadVisibleSettings);
      document.removeEventListener("visibilitychange", reloadVisibleSettings);
    };
  }, [adapter, loadSettings]);

  const patch = useCallback((mutator: (draft: RendererSafeSettings) => void): Promise<SettingsSaveOutcome> => {
    const next = updateRendererSafeSettings(settingsRef.current, mutator);
    const mutationSequence = ++mutationSequenceRef.current;
    settingsRef.current = next;
    loadSequenceRef.current += 1;
    setSettings(next);
    if (!adapter) return Promise.resolve("succeeded");

    setSaveState("saving");
    const queuedSave = saveQueueRef.current.then(async (): Promise<SettingsSaveOutcome> => {
      try {
        const snapshot = await adapter.replace({
          settings: next,
          expectedInventoryRevision: revisionRef.current,
        });
        revisionRef.current = snapshot.inventoryRevision;
        if (mutationSequence === mutationSequenceRef.current) {
          settingsRef.current = snapshot.settings;
          setSettings(snapshot.settings);
          setSaveState("saved");
        }
        return "succeeded";
      } catch {
        if (mutationSequence === mutationSequenceRef.current) setSaveState("error");
        return "failed";
      }
    });
    saveQueueRef.current = queuedSave;
    return queuedSave;
  }, [adapter]);

  const waitForSettingsSave = useCallback(async (): Promise<SettingsSaveOutcome> => {
    while (true) {
      const queuedSave = saveQueueRef.current;
      const outcome = await queuedSave;
      if (queuedSave === saveQueueRef.current) return outcome;
    }
  }, []);

  const visiblePages = SETTINGS_PUBLIC_PAGES;
  const hits = useMemo(
    () => findLocalizedSettingsSearchHits(searchQuery, t),
    [searchQuery, t],
  );

  const showPage = useCallback((page: SettingsPageId) => {
    setActivePage(page);
    setMountedPages((current) => current.has(page) ? current : new Set([...current, page]));
    setPendingAnchor(null);
  }, []);

  const chooseSearchHit = useCallback((index: number) => {
    const hit = hits[index];
    if (!hit) return;
    setMountedPages((current) => current.has(hit.page) ? current : new Set([...current, hit.page]));
    setActivePage(hit.page);
    if (hit.nestedTab) setNestedTab(hit.nestedTab);
    setPendingAnchor(hit.id);
    setSearchOpen(false);
    setSearchQuery("");
  }, [hits]);

  useEffect(() => {
    if (!pendingAnchor) return;
    let cancelled = false;
    let attempt = 0;
    const focus = () => {
      if (cancelled) return;
      const target = document.getElementById(pendingAnchor);
      if (!target && attempt++ < 24) {
        window.setTimeout(focus, 40);
        return;
      }
      if (!target) return;
      target.scrollIntoView({ block: "center", behavior: "smooth" });
      target.focus({ preventScroll: true });
      target.classList.add("settings-anchor-highlight");
      window.setTimeout(() => target.classList.remove("settings-anchor-highlight"), 1_600);
      setPendingAnchor(null);
    };
    window.setTimeout(focus, 30);
    return () => { cancelled = true; };
  }, [pendingAnchor, activePage, nestedTab]);

  useEffect(() => {
    const keydown = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "f") {
        event.preventDefault();
        setSearchOpen(true);
        window.requestAnimationFrame(() => searchInputRef.current?.focus());
      }
      if (event.key === "Escape" && searchOpen) {
        setSearchOpen(false);
        setSearchQuery("");
      }
    };
    window.addEventListener("keydown", keydown);
    return () => window.removeEventListener("keydown", keydown);
  }, [searchOpen]);

  useEffect(() => { setSearchIndex(0); }, [searchQuery]);

  return (
    <SettingsTranslationContext.Provider value={t}>
      <div className="settings-workspace" data-platform={platform} aria-busy={loading}>
      <header className="settings-titlebar" data-tauri-drag-region>
        {platform === "mac" ? <span className="settings-mac-titlebar-space" /> : null}
        <h1>{t("app.settings")}</h1>
        {saveState !== "idle" ? <span className={`settings-save-state ${saveState}`}>{saveState === "saving" ? t("app.saving") : saveState === "saved" ? t("app.saved") : t("app.saveError")}</span> : null}
        {platform !== "mac" ? <button type="button" className="settings-close" aria-label={t("app.closeSettings")} title={t("app.closeSettings")} onClick={onClose}><SettingsGlyph name="close" /></button> : null}
      </header>
      <div className="settings-layout">
        <aside className="settings-sidebar">
          <div className={`settings-search ${searchOpen ? "open" : ""}`}>
            {searchOpen ? (
              <>
                <SettingsGlyph name="search" />
                <input
                  ref={searchInputRef}
                  value={searchQuery}
                  onChange={(event) => setSearchQuery(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.nativeEvent.isComposing) return;
                    if (event.key === "ArrowDown" && hits.length) { event.preventDefault(); setSearchIndex((searchIndex + 1) % hits.length); }
                    if (event.key === "ArrowUp" && hits.length) { event.preventDefault(); setSearchIndex((searchIndex - 1 + hits.length) % hits.length); }
                    if (event.key === "Enter") { event.preventDefault(); chooseSearchHit(searchIndex); }
                  }}
                  placeholder={t("app.searchSettingsPlaceholder")}
                  aria-label={t("app.searchSettingsPlaceholder")}
                  role="combobox"
                  aria-expanded="true"
                />
                <button type="button" aria-label={t("app.closeSearch")} onClick={() => { setSearchOpen(false); setSearchQuery(""); }}><SettingsGlyph name="close" /></button>
                {searchQuery ? <div className="settings-search-results" role="listbox">{hits.length ? hits.map((hit, index) => <button type="button" role="option" aria-selected={index === searchIndex} className={index === searchIndex ? "active" : ""} key={hit.id} onMouseEnter={() => setSearchIndex(index)} onClick={() => chooseSearchHit(index)}><strong>{hit.label}</strong><small>{hit.pageLabel}</small></button>) : <p>{t("app.noSettingsFound")}</p>}</div> : null}
              </>
            ) : <button type="button" className="settings-search-opener" onClick={() => { setSearchOpen(true); window.requestAnimationFrame(() => searchInputRef.current?.focus()); }}><SettingsGlyph name="search" /><span>{t("app.searchSettings")}</span><kbd>{platform === "mac" ? "⌘F" : "Ctrl F"}</kbd></button>}
          </div>
          <nav aria-label={t("settings.navLabel")}>
            {visiblePages.map((page) => <button type="button" key={page.id} className={activePage === page.id ? "active" : ""} aria-current={activePage === page.id ? "page" : undefined} onClick={() => showPage(page.id)}><SettingsGlyph name={page.glyph} /><span>{t(`settings.pages.${page.id}` as MessageKey)}</span></button>)}
          </nav>
        </aside>
        <main className="settings-content">
          {loading ? <div className="settings-loading">{t("app.loadingSettings")}</div> : null}
          {visiblePages.map((page) => mountedPages.has(page.id) ? (
            <section key={page.id} className="settings-page" aria-label={t(`settings.pages.${page.id}` as MessageKey)} hidden={activePage !== page.id}>
              <SettingsPage
                id={page.id}
                settings={settings}
                patch={patch}
                waitForSettingsSave={waitForSettingsSave}
                settingsReady={!loading}
                onNativeAction={onNativeAction}
                nestedTab={nestedTab}
                setNestedTab={setNestedTab}
                appVersion={appVersion}
                localShellSource={localShellSource}
                chooseLocalStartDirectory={chooseLocalStartDirectory}
              />
            </section>
          ) : null)}
        </main>
      </div>
      </div>
    </SettingsTranslationContext.Provider>
  );
}
