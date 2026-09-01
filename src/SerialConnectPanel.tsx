import {
  type FormEvent,
  type ReactNode,
  useCallback,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
} from "react";

import {
  listSerialPorts,
  type SavedHost,
  type SavedHostDraft,
  type SerialBackspaceBehavior,
  type SerialConfig,
  type SerialFlowControl,
  type SerialParity,
  type SerialPortInfo,
} from "./backend";
import { type Locale, type Translate, useI18n } from "./i18n";
import { WindowControlGlyph } from "./WindowControlGlyph";
import "./serial.css";

export const SERIAL_BAUD_RATES = [
  300,
  1200,
  2400,
  4800,
  9600,
  19_200,
  38_400,
  57_600,
  115_200,
  230_400,
  460_800,
  921_600,
] as const;

export const SERIAL_DATA_BITS = [5, 6, 7, 8] as const;
export const SERIAL_STOP_BITS = [1, 1.5, 2] as const;
export const SERIAL_PARITY_OPTIONS: readonly SerialParity[] = [
  "none",
  "even",
  "odd",
  "mark",
  "space",
];
export const SERIAL_FLOW_CONTROL_OPTIONS: readonly SerialFlowControl[] = [
  "none",
  "xon/xoff",
  "rts/cts",
];

const DEFAULT_CHARSET = "UTF-8";
const MAX_SERIAL_PATH_BYTES = 1_024;
const MAX_CHARSET_BYTES = 32;
const MAX_U32 = 4_294_967_295;
const utf8ByteLength = (value: string): number => new TextEncoder().encode(value).length;

type SerialFormState = {
  label: string;
  group: string;
  tags: string;
  path: string;
  baudRate: string;
  dataBits: 5 | 6 | 7 | 8;
  stopBits: 1 | 1.5 | 2;
  parity: SerialParity;
  flowControl: SerialFlowControl;
  charset: string;
  localEcho: boolean;
  lineMode: boolean;
  backspaceBehavior: SerialBackspaceBehavior;
};

type SerialConnectPanelCommonProps = {
  className?: string;
  disabled?: boolean;
  layout?: "card" | "aside";
  locale?: Locale;
  /** Defaults to the typed Tauri `listSerialPorts` command. */
  portSource?: () => Promise<SerialPortInfo[]>;
  /** Defaults to true so opening either panel mirrors the legacy refresh behavior. */
  autoRefreshPorts?: boolean;
  onCancel?: () => void;
};

export type QuickSerialConnectSubmission = {
  config: SerialConfig;
  charset: string;
};

export type SavedSerialEditSubmission = {
  id: string;
  expectedRevision: number;
  draft: SavedHostDraft;
};

export type SavedSerialCreateSubmission = {
  draft: SavedHostDraft;
};

export type QuickSerialConnectPanelProps = SerialConnectPanelCommonProps & {
  mode?: "quick";
  initialConfig?: Partial<SerialConfig>;
  initialCharset?: string;
  onConnect: (submission: QuickSerialConnectSubmission) => void | Promise<void>;
  savedHost?: never;
  onSave?: never;
  groups?: never;
  availableTags?: never;
};

export type SavedSerialConnectPanelProps = SerialConnectPanelCommonProps & {
  mode: "saved";
  savedHost: SavedHost;
  groups?: readonly string[];
  availableTags?: readonly string[];
  onSave: (submission: SavedSerialEditSubmission) => void | Promise<void>;
  onConnect?: never;
  initialConfig?: never;
  initialCharset?: never;
};

export type CreateSavedSerialConnectPanelProps = SerialConnectPanelCommonProps & {
  mode: "create";
  initialConfig?: Partial<SerialConfig>;
  initialCharset?: string;
  initialLabel?: string;
  initialGroup?: string;
  initialTags?: readonly string[];
  groups?: readonly string[];
  availableTags?: readonly string[];
  onSave: (submission: SavedSerialCreateSubmission) => void | Promise<void>;
  savedHost?: never;
  onConnect?: never;
};

export type SerialConnectPanelProps =
  | QuickSerialConnectPanelProps
  | SavedSerialConnectPanelProps
  | CreateSavedSerialConnectPanelProps;

const defaultFormState = (): SerialFormState => ({
  label: "",
  group: "",
  tags: "serial",
  path: "",
  baudRate: "115200",
  dataBits: 8,
  stopBits: 1,
  parity: "none",
  flowControl: "none",
  charset: DEFAULT_CHARSET,
  localEcho: false,
  lineMode: false,
  backspaceBehavior: "default",
});

const mergeConfigIntoState = (
  base: SerialFormState,
  config: Partial<SerialConfig> | null | undefined,
): SerialFormState => ({
  ...base,
  path: config?.path ?? base.path,
  baudRate: config?.baudRate === undefined ? base.baudRate : String(config.baudRate),
  dataBits: config?.dataBits ?? base.dataBits,
  stopBits: config?.stopBits ?? base.stopBits,
  parity: config?.parity ?? base.parity,
  flowControl: config?.flowControl ?? base.flowControl,
  localEcho: config?.localEcho ?? base.localEcho,
  lineMode: config?.lineMode ?? base.lineMode,
  backspaceBehavior: config?.backspaceBehavior ?? base.backspaceBehavior,
});

const stateFromProps = (props: SerialConnectPanelProps): SerialFormState => {
  const empty = defaultFormState();
  if (props.mode === "create") {
    return {
      ...mergeConfigIntoState(empty, props.initialConfig),
      label: props.initialLabel ?? "",
      group: props.initialGroup ?? "",
      tags: (props.initialTags ?? ["serial"]).join(", "),
      charset: props.initialCharset?.trim() || DEFAULT_CHARSET,
    };
  }
  if (props.mode !== "saved") {
    return {
      ...mergeConfigIntoState(empty, props.initialConfig),
      charset: props.initialCharset?.trim() || DEFAULT_CHARSET,
    };
  }

  const { savedHost } = props;
  const effective = mergeConfigIntoState(empty, savedHost.effectiveSerialConfig);
  const direct = mergeConfigIntoState(effective, savedHost.serialConfig);
  return {
    ...direct,
    label: savedHost.label,
    group: savedHost.group ?? "",
    tags: savedHost.tags.join(", "),
    path: savedHost.serialConfig?.path || savedHost.hostname || direct.path,
    baudRate: String(savedHost.serialConfig?.baudRate || savedHost.port || 115_200),
    charset: savedHost.charset?.trim() || DEFAULT_CHARSET,
  };
};

const trimAndDedupe = (value: string): string[] => {
  const seen = new Set<string>();
  const values: string[] = [];
  for (const item of value.split(",")) {
    const tag = item.trim();
    if (!tag || seen.has(tag)) continue;
    seen.add(tag);
    values.push(tag);
  }
  return values;
};

const serialPortName = (path: string): string => {
  const normalized = path.replaceAll("\\", "/");
  return normalized.split("/").filter(Boolean).at(-1) || path;
};

export const isValidSerialPath = (value: string): boolean => {
  const path = value.trim();
  return path.length > 0
    && utf8ByteLength(path) <= MAX_SERIAL_PATH_BYTES
    && !/[\u0000-\u001f\u007f]/u.test(path);
};

export const parseSerialBaudRate = (value: string): number | null => {
  const normalized = value.trim();
  if (!/^[0-9]+$/u.test(normalized)) return null;
  const baudRate = Number(normalized);
  return Number.isSafeInteger(baudRate) && baudRate > 0 && baudRate <= MAX_U32
    ? baudRate
    : null;
};

const isValidCharset = (value: string): boolean => {
  const charset = value.trim();
  return charset.length > 0
    && utf8ByteLength(charset) <= MAX_CHARSET_BYTES
    && !/[\u0000-\u001f\u007f]/u.test(charset);
};

const displayPortDetails = (port: SerialPortInfo, t: Translate): string => {
  const details = [
    port.manufacturer,
    port.serialNumber ? `S/N ${port.serialNumber}` : "",
    port.vendorId && port.productId ? `${port.vendorId}:${port.productId}` : "",
  ].filter(Boolean);
  if (details.length > 0) return details.join(" · ");
  if (port.type === "pseudo") return t("serial.port.pseudo");
  if (port.type === "custom") return t("serial.port.custom");
  return t("serial.port.hardware");
};

const UsbGlyph = () => (
  <svg
    aria-hidden="true"
    className="serial-glyph"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.8"
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    <path d="M12 3v12m0-12-2.4 2.4M12 3l2.4 2.4M12 15l-3-3m3 3 3-3M9 12H6V8m9 4h3V8m-2-2h4v4h-4M4 6h4v4H4m8 5v3" />
    <circle cx="12" cy="20" r="1.5" />
  </svg>
);

const RefreshGlyph = () => (
  <svg
    aria-hidden="true"
    className="serial-small-glyph"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.9"
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    <path d="M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7" />
  </svg>
);

type FieldProps = {
  label: string;
  htmlFor: string;
  hint?: string;
  children: ReactNode;
};

const SerialField = ({ label, htmlFor, hint, children }: FieldProps) => (
  <label className="serial-field" htmlFor={htmlFor}>
    <span className="serial-field-label">{label}</span>
    {children}
    {hint && <small>{hint}</small>}
  </label>
);

/**
 * Reusable Serial form for both legacy-style Quick Connect and SavedHost edit.
 *
 * Quick wiring:
 * `onConnect({ config, charset })` can be merged with a live TerminalSize and
 * passed to `startSerialSession`.
 *
 * Saved wiring:
 * `onSave({ id, expectedRevision, draft })` can be passed to `updateSavedHost`
 * together with `credentialMutation: { action: "keep" }`.
 */
export const SerialConnectPanel = (props: SerialConnectPanelProps) => {
  const { t } = useI18n(props.locale);
  const mode = props.mode === "saved" ? "saved" : props.mode === "create" ? "create" : "quick";
  const [form, setForm] = useState<SerialFormState>(() => stateFromProps(props));
  const [ports, setPorts] = useState<SerialPortInfo[]>([]);
  const [loadingPorts, setLoadingPorts] = useState(false);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState<{ type: "error" | "notice"; text: string } | null>(null);
  const [backspaceChanged, setBackspaceChanged] = useState(false);
  const [charsetChanged, setCharsetChanged] = useState(false);
  const refreshSequence = useRef(0);
  const mounted = useRef(true);
  const panelId = useId().replaceAll(":", "");
  const portListId = `${panelId}-serial-ports`;
  const baudListId = `${panelId}-serial-baud-rates`;
  const fieldId = (name: string) => `${panelId}-${name}`;
  const disabled = Boolean(props.disabled || submitting);
  const portSource = props.portSource ?? listSerialPorts;
  const autoRefreshPorts = props.autoRefreshPorts !== false;

  const resetKey = props.mode === "saved"
    ? `${props.savedHost.id}:${props.savedHost.revision}`
    : props.mode;

  useEffect(() => {
    setForm(stateFromProps(props));
    setBackspaceChanged(false);
    setCharsetChanged(false);
    setMessage(null);
  // The saved form must reset only when a different Vault revision is opened.
  // Quick initial values are intentionally one-shot defaults.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [resetKey]);

  const refreshPorts = useCallback(async (): Promise<void> => {
    const sequence = ++refreshSequence.current;
    setLoadingPorts(true);
    setMessage(null);
    try {
      const result = await portSource();
      if (!mounted.current || sequence !== refreshSequence.current) return;
      setPorts(result);
      if (mode === "quick" && result.length > 0) {
        setForm((current) => current.path.trim()
          ? current
          : { ...current, path: result[0].path });
      }
    } catch {
      if (!mounted.current || sequence !== refreshSequence.current) return;
      setMessage({
        type: "error",
        text: t("serial.error.portList"),
      });
    } finally {
      if (mounted.current && sequence === refreshSequence.current) setLoadingPorts(false);
    }
  }, [mode, portSource, t]);

  useEffect(() => {
    mounted.current = true;
    if (autoRefreshPorts) void refreshPorts();
    return () => {
      mounted.current = false;
      refreshSequence.current += 1;
    };
  }, [autoRefreshPorts, refreshPorts]);

  const selectedPort = useMemo(
    () => ports.find((port) => port.path === form.path.trim()) ?? null,
    [form.path, ports],
  );
  const customBaudRate = useMemo(() => {
    const rate = parseSerialBaudRate(form.baudRate);
    return rate !== null && !SERIAL_BAUD_RATES.includes(rate as (typeof SERIAL_BAUD_RATES)[number]);
  }, [form.baudRate]);
  const portValid = isValidSerialPath(form.path);
  const baudRate = parseSerialBaudRate(form.baudRate);
  const charsetValid = isValidCharset(form.charset);
  const formValid = portValid && baudRate !== null && charsetValid;

  const updateForm = <Key extends keyof SerialFormState>(
    key: Key,
    value: SerialFormState[Key],
  ) => setForm((current) => ({ ...current, [key]: value }));

  const buildSerialConfig = (normalizedPath: string, normalizedBaudRate: number): SerialConfig => {
    const config: SerialConfig = {
      path: normalizedPath,
      baudRate: normalizedBaudRate,
      dataBits: form.dataBits,
      stopBits: form.stopBits,
      parity: form.parity,
      flowControl: form.flowControl,
      localEcho: form.localEcho,
      lineMode: form.lineMode,
    };
    if (
      mode === "quick"
      || backspaceChanged
      || (props.mode === "saved" && props.savedHost.hasExplicitSerialBackspaceBehavior)
    ) {
      config.backspaceBehavior = form.backspaceBehavior;
    }
    return config;
  };

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (disabled) return;
    const normalizedPath = form.path.trim();
    const normalizedBaudRate = parseSerialBaudRate(form.baudRate);
    if (!isValidSerialPath(normalizedPath)) {
      setMessage({ type: "error", text: t("serial.error.pathRequired") });
      return;
    }
    if (normalizedBaudRate === null) {
      setMessage({ type: "error", text: t("serial.error.baudInvalid") });
      return;
    }
    if (!isValidCharset(form.charset)) {
      setMessage({ type: "error", text: t("serial.error.charsetInvalid") });
      return;
    }

    const config = buildSerialConfig(normalizedPath, normalizedBaudRate);
    const charset = form.charset.trim();
    setSubmitting(true);
    setMessage(null);
    try {
      if (props.mode === "saved" || props.mode === "create") {
        const label = form.label.trim() || t("serial.defaultLabel", {
          port: serialPortName(normalizedPath),
        });
        const draft: SavedHostDraft = {
          label,
          hostname: normalizedPath,
          port: normalizedBaudRate,
          username: "",
          protocol: "serial",
          serialConfig: config,
          ...(props.mode === "create"
            || props.savedHost.hasExplicitCharset
            || charsetChanged ? { charset } : {}),
          ...(form.group.trim() ? { group: form.group.trim() } : {}),
          tags: trimAndDedupe(form.tags),
        };
        if (props.mode === "saved") {
          await props.onSave({
            id: props.savedHost.id,
            expectedRevision: props.savedHost.revision,
            draft,
          });
        } else {
          await props.onSave({ draft });
        }
        if (mounted.current) setMessage({ type: "notice", text: t("serial.notice.saved") });
      } else {
        await props.onConnect({ config, charset });
      }
    } catch {
      if (mounted.current) {
        setMessage({
          type: "error",
          text: t(mode === "quick" ? "serial.error.connectFailed" : "serial.error.saveFailed"),
        });
      }
    } finally {
      if (mounted.current) setSubmitting(false);
    }
  };

  const title = t(mode === "saved"
    ? "serial.title.settings"
    : mode === "create" ? "serial.title.create" : "serial.title.connect");
  const subtitle = props.mode === "saved"
    ? props.savedHost.label
    : t(mode === "create" ? "serial.subtitle.create" : "serial.subtitle.connect");
  const className = [
    "serial-connect-panel",
    `serial-connect-panel-${props.layout ?? "card"}`,
    `serial-connect-panel-${mode}`,
    props.className,
  ].filter(Boolean).join(" ");

  return (
    <section className={className} data-mode={mode} aria-labelledby={`${panelId}-title`}>
      <header className="serial-panel-header">
        <span className="serial-panel-icon"><UsbGlyph /></span>
        <span className="serial-panel-heading">
          <strong id={`${panelId}-title`}>{title}</strong>
          <small>{subtitle}</small>
        </span>
        {props.onCancel && (
          <button
            type="button"
            className="serial-icon-button serial-close-button"
            aria-label={t("serial.closePanel")}
            disabled={submitting}
            onClick={props.onCancel}
          >
            <WindowControlGlyph name="close" />
          </button>
        )}
      </header>

      {message && (
        <div
          className={`serial-message ${message.type}`}
          role={message.type === "error" ? "alert" : "status"}
          aria-live="polite"
        >
          {message.text}
        </div>
      )}

      <form className="serial-form" onSubmit={submit} noValidate>
        <div className="serial-form-scroll">
          {(props.mode === "saved" || props.mode === "create") && (
            <div className="serial-saved-fields">
              <SerialField label={t("serial.configName")} htmlFor={fieldId("label")}>
                <input
                  id={fieldId("label")}
                  name="label"
                  value={form.label}
                  disabled={disabled}
                  placeholder={t("serial.configNamePlaceholder")}
                  onChange={(event) => updateForm("label", event.target.value)}
                />
              </SerialField>
              <div className="serial-field-grid">
                <SerialField label={t("serial.group")} htmlFor={fieldId("group")}>
                  <input
                    id={fieldId("group")}
                    name="group"
                    value={form.group}
                    disabled={disabled}
                    list={`${panelId}-serial-groups`}
                    placeholder={t("serial.rootGroup")}
                    onChange={(event) => updateForm("group", event.target.value)}
                  />
                  <datalist id={`${panelId}-serial-groups`}>
                    {(props.groups ?? []).map((group) => <option key={group} value={group} />)}
                  </datalist>
                </SerialField>
                <SerialField
                  label={t("serial.tags")}
                  htmlFor={fieldId("tags")}
                  hint={t("serial.tagsHint")}
                >
                  <input
                    id={fieldId("tags")}
                    name="tags"
                    value={form.tags}
                    disabled={disabled}
                    list={`${panelId}-serial-tags`}
                    placeholder={t("serial.tagsPlaceholder")}
                    onChange={(event) => updateForm("tags", event.target.value)}
                  />
                  <datalist id={`${panelId}-serial-tags`}>
                    {(props.availableTags ?? []).map((tag) => <option key={tag} value={tag} />)}
                  </datalist>
                </SerialField>
              </div>
              <div className="serial-section-divider" />
            </div>
          )}

          <div className="serial-field serial-port-field">
            <span className="serial-field-heading-row">
              <label className="serial-field-label" htmlFor={fieldId("path")}>
                {t("serial.port")}
              </label>
              <button
                type="button"
                className="serial-refresh-button"
                disabled={disabled || loadingPorts}
                onClick={() => void refreshPorts()}
              >
                <RefreshGlyph />
                {t(loadingPorts ? "serial.refreshing" : "serial.refresh")}
              </button>
            </span>
            <span className="serial-input-with-icon">
              <UsbGlyph />
              <input
                id={fieldId("path")}
                name="path"
                value={form.path}
                disabled={disabled}
                list={portListId}
                placeholder={t("serial.portPlaceholder")}
                autoComplete="off"
                aria-invalid={Boolean(form.path) && !portValid}
                onChange={(event) => updateForm("path", event.target.value)}
              />
            </span>
            <datalist id={portListId}>
              {ports.map((port) => (
                <option key={port.path} value={port.path}>{displayPortDetails(port, t)}</option>
              ))}
            </datalist>
            {selectedPort && (
              <small className="serial-port-details">{displayPortDetails(selectedPort, t)}</small>
            )}
            {!loadingPorts && ports.length === 0 && (
              <small>{t("serial.noPorts")}</small>
            )}
            {Boolean(form.path) && !portValid && (
              <small className="serial-field-error">{t("serial.pathError")}</small>
            )}
          </div>

          <SerialField
            label={t("serial.baudRate")}
            htmlFor={fieldId("baud-rate")}
            hint={customBaudRate ? t("serial.customBaudRate") : undefined}
          >
            <input
              id={fieldId("baud-rate")}
              name="baudRate"
              value={form.baudRate}
              disabled={disabled}
              inputMode="numeric"
              list={baudListId}
              placeholder={t("serial.baudRatePlaceholder")}
              aria-invalid={Boolean(form.baudRate) && baudRate === null}
              onChange={(event) => updateForm("baudRate", event.target.value)}
            />
            <datalist id={baudListId}>
              {SERIAL_BAUD_RATES.map((rate) => <option key={rate} value={rate} />)}
            </datalist>
          </SerialField>

          <button
            type="button"
            className="serial-advanced-trigger"
            aria-expanded={advancedOpen}
            aria-controls={`${panelId}-advanced`}
            onClick={() => setAdvancedOpen((current) => !current)}
          >
            <span>{t("serial.advancedOptions")}</span>
            <span aria-hidden="true" className="serial-chevron">⌄</span>
          </button>

          <div id={`${panelId}-advanced`} className="serial-advanced" hidden={!advancedOpen}>
            <div className="serial-field-grid serial-parameter-grid">
              <SerialField label={t("serial.dataBits")} htmlFor={fieldId("data-bits")}>
                <select
                  id={fieldId("data-bits")}
                  name="dataBits"
                  value={form.dataBits}
                  disabled={disabled}
                  onChange={(event) => updateForm("dataBits", Number(event.target.value) as 5 | 6 | 7 | 8)}
                >
                  {SERIAL_DATA_BITS.map((bits) => <option key={bits} value={bits}>{bits}</option>)}
                </select>
              </SerialField>
              <SerialField
                label={t("serial.stopBits")}
                htmlFor={fieldId("stop-bits")}
                hint={form.stopBits === 1.5 ? t("serial.stopBitsWarning") : undefined}
              >
                <select
                  id={fieldId("stop-bits")}
                  name="stopBits"
                  value={form.stopBits}
                  disabled={disabled}
                  onChange={(event) => updateForm("stopBits", Number(event.target.value) as 1 | 1.5 | 2)}
                >
                  {SERIAL_STOP_BITS.map((bits) => <option key={bits} value={bits}>{bits}</option>)}
                </select>
              </SerialField>
              <SerialField label={t("serial.parity")} htmlFor={fieldId("parity")}>
                <select
                  id={fieldId("parity")}
                  name="parity"
                  value={form.parity}
                  disabled={disabled}
                  onChange={(event) => updateForm("parity", event.target.value as SerialParity)}
                >
                  <option value="none">{t("serial.parity.none")}</option>
                  <option value="even">{t("serial.parity.even")}</option>
                  <option value="odd">{t("serial.parity.odd")}</option>
                  <option value="mark">{t("serial.parity.mark")}</option>
                  <option value="space">{t("serial.parity.space")}</option>
                </select>
              </SerialField>
              <SerialField label={t("serial.flowControl")} htmlFor={fieldId("flow-control")}>
                <select
                  id={fieldId("flow-control")}
                  name="flowControl"
                  value={form.flowControl}
                  disabled={disabled}
                  onChange={(event) => updateForm("flowControl", event.target.value as SerialFlowControl)}
                >
                  <option value="none">{t("serial.flow.none")}</option>
                  <option value="xon/xoff">{t("serial.flow.software")}</option>
                  <option value="rts/cts">{t("serial.flow.hardware")}</option>
                </select>
              </SerialField>
            </div>

            <div className="serial-section-divider" />
            <SerialField
              label={t("serial.backspace")}
              htmlFor={fieldId("backspace")}
              hint={t("serial.backspaceHint")}
            >
              <select
                id={fieldId("backspace")}
                name="backspaceBehavior"
                value={form.backspaceBehavior}
                disabled={disabled}
                onChange={(event) => {
                  updateForm("backspaceBehavior", event.target.value as SerialBackspaceBehavior);
                  setBackspaceChanged(true);
                }}
              >
                <option value="default">{t("serial.backspace.default")}</option>
                <option value="ctrl-h">{t("serial.backspace.ctrlH")}</option>
              </select>
            </SerialField>

            <label className="serial-switch-row" htmlFor={fieldId("local-echo")}>
              <span>
                <strong>{t("serial.localEcho")}</strong>
                <small>{t("serial.localEchoHint")}</small>
              </span>
              <input
                id={fieldId("local-echo")}
                name="localEcho"
                type="checkbox"
                role="switch"
                checked={form.localEcho}
                disabled={disabled}
                onChange={(event) => updateForm("localEcho", event.target.checked)}
              />
            </label>

            <label className="serial-switch-row" htmlFor={fieldId("line-mode")}>
              <span>
                <strong>{t("serial.lineMode")}</strong>
                <small>{t("serial.lineModeHint")}</small>
              </span>
              <input
                id={fieldId("line-mode")}
                name="lineMode"
                type="checkbox"
                role="switch"
                checked={form.lineMode}
                disabled={disabled}
                onChange={(event) => updateForm("lineMode", event.target.checked)}
              />
            </label>

            <SerialField label={t("serial.charset")} htmlFor={fieldId("charset")}>
              <input
                id={fieldId("charset")}
                name="charset"
                value={form.charset}
                disabled={disabled}
                placeholder="UTF-8"
                spellCheck={false}
                aria-invalid={Boolean(form.charset) && !charsetValid}
                onChange={(event) => {
                  updateForm("charset", event.target.value);
                  setCharsetChanged(true);
                }}
              />
            </SerialField>
          </div>
        </div>

        <footer className="serial-panel-footer">
          {props.onCancel && (
            <button
              type="button"
              className="serial-button serial-button-secondary"
              disabled={submitting}
              onClick={props.onCancel}
            >
              {t("serial.cancel")}
            </button>
          )}
          <button
            type="submit"
            className="serial-button serial-button-primary"
            disabled={disabled || !formValid}
          >
            <UsbGlyph />
            {submitting
              ? t(mode === "quick" ? "serial.connecting" : "serial.saving")
              : t(mode === "quick" ? "serial.connect" : "serial.save")}
          </button>
        </footer>
      </form>
    </section>
  );
};

export default SerialConnectPanel;
