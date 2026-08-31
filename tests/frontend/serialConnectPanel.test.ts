import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const panelUrl = new URL("../../src/SerialConnectPanel.tsx", import.meta.url);
const cssUrl = new URL("../../src/serial.css", import.meta.url);

test("SerialConnectPanel exposes one typed Quick and Saved Serial form boundary", async () => {
  const panel = await readFile(panelUrl, "utf8");

  assert.match(panel, /listSerialPorts/);
  assert.match(panel, /type SerialConfig/);
  assert.match(panel, /type SerialPortInfo/);
  assert.match(panel, /type SavedHostDraft/);
  assert.match(panel, /locale\?: Locale/);
  assert.match(panel, /useI18n\(props\.locale\)/);
  assert.match(panel, /mode\?: "quick"/);
  assert.match(panel, /mode: "saved"/);
  assert.match(panel, /mode: "create"/);
  assert.match(panel, /onConnect: \(submission: QuickSerialConnectSubmission\)/);
  assert.match(panel, /onSave: \(submission: SavedSerialEditSubmission\)/);
  assert.match(panel, /portSource\?: \(\) => Promise<SerialPortInfo\[\]>/);
});

test("Quick Serial preserves the complete legacy connection controls", async () => {
  const panel = await readFile(panelUrl, "utf8");

  for (const field of [
    "path",
    "baudRate",
    "dataBits",
    "stopBits",
    "parity",
    "flowControl",
    "backspaceBehavior",
    "localEcho",
    "lineMode",
    "charset",
  ]) {
    assert.match(panel, new RegExp(`name="${field}"`));
  }
  assert.match(panel, /300,[\s\S]*?921_600/);
  assert.match(panel, /SERIAL_DATA_BITS = \[5, 6, 7, 8\]/);
  assert.match(panel, /SERIAL_STOP_BITS = \[1, 1\.5, 2\]/);
  assert.match(panel, /MAX_SERIAL_PATH_BYTES = 1_024/);
  assert.match(panel, /MAX_CHARSET_BYTES = 32/);
  assert.match(panel, /"none",[\s\S]*?"even",[\s\S]*?"odd",[\s\S]*?"mark",[\s\S]*?"space"/);
  assert.match(panel, /"none",[\s\S]*?"xon\/xoff",[\s\S]*?"rts\/cts"/);
  assert.match(panel, /await props\.onConnect\(\{ config, charset \}\)/);
  assert.match(panel, /serial\.error\.portList/);
  assert.doesNotMatch(panel, /toErrorMessage/);
  assert.doesNotMatch(panel, /[\p{Script=Han}]/u);
});

test("Saved Serial submission is directly compatible with SavedHost update wiring", async () => {
  const panel = await readFile(panelUrl, "utf8");

  const savedSubmit = panel.slice(
    panel.indexOf("const draft: SavedHostDraft"),
    panel.indexOf("await props.onConnect"),
  );
  assert.match(savedSubmit, /hostname: normalizedPath/);
  assert.match(savedSubmit, /port: normalizedBaudRate/);
  assert.match(savedSubmit, /username: ""/);
  assert.match(savedSubmit, /protocol: "serial"/);
  assert.match(savedSubmit, /serialConfig: config/);
  assert.match(savedSubmit, /props\.mode === "create"[\s\S]*?props\.savedHost\.hasExplicitCharset[\s\S]*?charsetChanged \? \{ charset \} : \{\}/);
  assert.match(savedSubmit, /tags: trimAndDedupe\(form\.tags\)/);
  assert.match(panel, /props\.savedHost\.hasExplicitSerialBackspaceBehavior/);
  assert.match(savedSubmit, /id: props\.savedHost\.id/);
  assert.match(savedSubmit, /expectedRevision: props\.savedHost\.revision/);
  assert.doesNotMatch(savedSubmit, /password|proxy|managedSshKey|hostChain/);
});

test("Serial panel carries its own original-aligned responsive styling", async () => {
  const [panel, css] = await Promise.all([
    readFile(panelUrl, "utf8"),
    readFile(cssUrl, "utf8"),
  ]);

  assert.match(panel, /import "\.\/serial\.css"/);
  assert.match(css, /\.serial-connect-panel \{/);
  assert.ok(css.includes("font-family: var(--ld-font-ui)"));
  // Same contract as the other standalone workspaces: palette by token,
  // which is what gives this panel a working dark mode.
  assert.ok(css.includes("--serial-accent: var(--ld-accent)"));
  assert.match(css, /\.serial-connect-panel-aside/);
  assert.match(css, /@media \(max-width: 520px\)/);
  assert.match(css, /\.serial-connect-panel \[hidden\]/);
});
