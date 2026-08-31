import { useEffect, useMemo, useState } from "react";

import type { Translate } from "../i18n";
import AiPopupMenu from "./AiPopupMenu";
import type { AiThinkingEffort } from "./AiThinkingMenu";

export type AiProviderMenuProfile = Readonly<{
  id: string;
  providerId: string;
  name: string;
  model: string;
  enabled: boolean;
}>;

export type AiProviderMenuModel = Readonly<{
  id: string;
  label?: string;
}>;

export type AiProviderMenuProps = Readonly<{
  value: string;
  profiles: ReadonlyArray<AiProviderMenuProfile>;
  modelValue?: string;
  models?: ReadonlyArray<AiProviderMenuModel>;
  modelsLoading?: boolean;
  modelsError?: string;
  thinking?: Readonly<{
    value: AiThinkingEffort;
    onSelect: (value: AiThinkingEffort) => void;
  }>;
  disabled?: boolean;
  t: Translate;
  onSelect: (profileId: string) => void;
  onSelectModel?: (modelId: string) => void;
  onRetryModels?: () => void;
  onOpenSettings?: () => void;
}>;

const ProviderMark = ({ profile }: Readonly<{ profile: AiProviderMenuProfile | null }>) => (
  <span className="ai-provider-menu-mark" data-provider={profile?.providerId ?? "none"} aria-hidden="true">
    {profile?.name.trim().slice(0, 1).toLocaleUpperCase() || "AI"}
  </span>
);

const Chevron = () => (
  <svg className="ai-popup-chevron" viewBox="0 0 16 16" aria-hidden="true"><path d="m4 6 4 4 4-4" /></svg>
);

export default function AiProviderMenu({
  value,
  profiles,
  modelValue,
  models,
  modelsLoading = false,
  modelsError,
  thinking,
  disabled = false,
  t,
  onSelect,
  onSelectModel,
  onRetryModels,
  onOpenSettings,
}: AiProviderMenuProps) {
  const [modelQuery, setModelQuery] = useState("");
  const selected = profiles.find((profile) => profile.id === value && profile.enabled)
    ?? profiles.find((profile) => profile.enabled)
    ?? null;
  const enabledProfiles = profiles.filter((profile) => profile.enabled);
  const disabledProfiles = profiles.filter((profile) => !profile.enabled);
  const modelCatalogAvailable = models !== undefined && onSelectModel !== undefined;
  const selectedModel = modelValue ?? selected?.model ?? "";
  const thinkingChoices: ReadonlyArray<Readonly<{
    value: AiThinkingEffort;
    label: string;
    description: string;
  }>> = [
    { value: "off", label: t("ai.thinking.off"), description: t("ai.thinking.offDescription") },
    { value: "low", label: t("ai.thinking.low"), description: t("ai.thinking.lowDescription") },
    { value: "medium", label: t("ai.thinking.medium"), description: t("ai.thinking.mediumDescription") },
    { value: "high", label: t("ai.thinking.high"), description: t("ai.thinking.highDescription") },
  ];
  const visibleModels = useMemo(() => {
    const normalizedQuery = modelQuery.normalize("NFKC").trim().toLocaleLowerCase();
    if (!models || !normalizedQuery) return models ?? [];
    return models.filter((model) => (model.label ?? model.id)
      .normalize("NFKC")
      .toLocaleLowerCase()
      .includes(normalizedQuery));
  }, [modelQuery, models]);

  useEffect(() => setModelQuery(""), [value]);

  const select = (profileId: string, close: () => void) => {
    onSelect(profileId);
    close();
  };

  const selectModel = (modelId: string, close: () => void) => {
    onSelectModel?.(modelId);
    setModelQuery("");
    close();
  };

  const profileItem = (profile: AiProviderMenuProfile, close: () => void) => (
    <button
      key={profile.id}
      type="button"
      role="menuitemradio"
      aria-checked={selected?.id === profile.id}
      aria-disabled={!profile.enabled}
      tabIndex={-1}
      title={`${profile.name} · ${profile.model} · ${selected?.id === profile.id
        ? t("ai.menu.provider.current")
        : profile.enabled
          ? t("ai.menu.provider.enabled")
          : t("ai.menu.provider.disabled")}`}
      onClick={(event) => {
        if (!profile.enabled) {
          event.preventDefault();
          return;
        }
        select(profile.id, close);
      }}
    >
      <ProviderMark profile={profile} />
      <span className="ai-popup-item-copy">
        <strong>{profile.name}</strong>
        <small>{profile.model}</small>
      </span>
      <span className={`ai-popup-status ${profile.enabled ? "is-ready" : "is-disabled"}`}>
        {selected?.id === profile.id
          ? t("ai.menu.provider.current")
          : profile.enabled
            ? t("ai.menu.provider.enabled")
            : t("ai.menu.provider.disabled")}
      </span>
    </button>
  );

  return (
    <AiPopupMenu
      label={t("ai.selectProviderModel")}
      disabled={disabled}
      placement="top-start"
      rootClassName="ai-provider-menu"
      triggerClassName="ai-provider-menu-trigger"
      triggerTitle={selected
        ? `${selected.name} · ${selectedModel}`
        : `${t("ai.noProvider")} · ${t("ai.menu.provider.addInSettings")}`}
      trigger={(
        <>
          <ProviderMark profile={selected} />
          <span className="ai-popup-trigger-copy">
            <strong>{selectedModel || selected?.name || t("ai.noProvider")}</strong>
          </span>
          <Chevron />
        </>
      )}
    >
      {(close) => (
        <>
          {thinking && !modelQuery ? (
            <div className="ai-provider-thinking" role="group" aria-label={t("ai.thinking.menuLabel")}>
              <span className="ai-popup-group-label">{t("ai.thinking.menuLabel")}</span>
              <div className="ai-provider-thinking-options">
                {thinkingChoices.map((choice) => (
                  <button
                    key={choice.value}
                    type="button"
                    role="menuitemradio"
                    aria-checked={thinking.value === choice.value}
                    tabIndex={-1}
                    title={`${choice.label} · ${choice.description}`}
                    onClick={() => {
                      thinking.onSelect(choice.value);
                      close();
                    }}
                  >
                    <span className={`ai-thinking-mark is-${choice.value}`} aria-hidden="true" />
                    <span>{choice.label}</span>
                  </button>
                ))}
              </div>
            </div>
          ) : null}
          {modelCatalogAvailable ? (
            <>
              <div className="ai-model-search">
                <svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="7" cy="7" r="4" /><path d="m10 10 3 3" /></svg>
                <input
                  type="search"
                  role="searchbox"
                  value={modelQuery}
                  aria-label={t("ai.menu.provider.searchModels")}
                  placeholder={t("ai.menu.provider.searchModels")}
                  onChange={(event) => setModelQuery(event.target.value)}
                  onKeyDown={(event) => {
                    if (["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) {
                      event.stopPropagation();
                    }
                  }}
                />
              </div>
              {modelsLoading ? (
                <p className="ai-model-catalog-status" role="status">{t("ai.menu.provider.loadingModels")}</p>
              ) : null}
              {modelsError ? (
                <div className="ai-model-catalog-error" role="status">
                  <span>{modelsError}</span>
                  {onRetryModels ? (
                    <button type="button" role="menuitem" tabIndex={-1} onClick={onRetryModels}>
                      {t("ai.menu.provider.retryModels")}
                    </button>
                  ) : null}
                </div>
              ) : null}
              {visibleModels.length > 0 ? (
                <div className="ai-popup-group" role="group" aria-label={t("ai.menu.provider.modelsGroup")}>
                  <span className="ai-popup-group-label">{t("ai.menu.provider.modelsGroup")}</span>
                  {visibleModels.map((model) => (
                    <button
                      key={model.id}
                      type="button"
                      role="menuitemradio"
                      aria-checked={selectedModel === model.id}
                      tabIndex={-1}
                      title={model.label ?? model.id}
                      onClick={() => selectModel(model.id, close)}
                    >
                      <span className="ai-model-option-mark" aria-hidden="true" />
                      <span className="ai-popup-item-copy">
                        <strong>{model.label ?? model.id}</strong>
                        {model.label && model.label !== model.id ? <small>{model.id}</small> : null}
                      </span>
                      {selectedModel === model.id ? <span className="ai-popup-check" aria-hidden="true">✓</span> : null}
                    </button>
                  ))}
                </div>
              ) : (
                <p className="ai-popup-empty" role="status">{t("ai.menu.provider.noMatchingModels")}</p>
              )}
            </>
          ) : null}
          {enabledProfiles.length > 0 && !modelQuery ? (
            <div className="ai-popup-group" role="group" aria-label={t("ai.menu.provider.availableGroup")}>
              <span className="ai-popup-group-label">{t("ai.menu.provider.availableGroup")}</span>
              {enabledProfiles.map((profile) => profileItem(profile, close))}
            </div>
          ) : !modelCatalogAvailable ? (
            <p className="ai-popup-empty">{t("ai.menu.provider.empty")}</p>
          ) : null}
          {disabledProfiles.length > 0 && !modelQuery ? (
            <div className="ai-popup-group" role="group" aria-label={t("ai.menu.provider.disabledGroup")}>
              <span className="ai-popup-group-label">{t("ai.menu.provider.disabledGroup")}</span>
              {disabledProfiles.map((profile) => profileItem(profile, close))}
            </div>
          ) : null}
          {onOpenSettings ? (
            <div className="ai-popup-footer">
              <button type="button" role="menuitem" tabIndex={-1} onClick={() => { close(false); onOpenSettings(); }}>
                <span className="ai-popup-settings-icon" aria-hidden="true">⚙</span>
                <span>{t("ai.menu.provider.manage")}</span>
              </button>
            </div>
          ) : null}
        </>
      )}
    </AiPopupMenu>
  );
}
