import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const backendUrl = new URL("../../src/backend.ts", import.meta.url);

test("Serial renderer boundary exposes typed config, enumeration, and raw session input", async () => {
  const backend = await readFile(backendUrl, "utf8");
  assert.match(backend, /export type SerialParity = "none" \| "even" \| "odd" \| "mark" \| "space"/);
  assert.match(backend, /export type SerialFlowControl = "none" \| "xon\/xoff" \| "rts\/cts"/);
  assert.match(backend, /dataBits\?: 5 \| 6 \| 7 \| 8/);
  assert.match(backend, /stopBits\?: 1 \| 1\.5 \| 2/);
  assert.match(
    backend,
    /export type SerialPortInfo = \{[\s\S]*?manufacturer: string;[\s\S]*?serialNumber: string;[\s\S]*?vendorId: string;[\s\S]*?productId: string;[\s\S]*?pnpId: string;[\s\S]*?type: SerialPortKind;/,
  );
  assert.match(backend, /invoke<SerialPortInfo\[\]>\("list_serial_ports"\)/);
  assert.match(backend, /"start_serial_session"/);
  assert.match(backend, /"start_saved_serial_session"/);
  assert.match(backend, /"serial_session_input_raw"/);
  assert.match(backend, /"resize_serial_session"/);
  assert.match(backend, /"close_serial_session"/);
  assert.match(backend, /"cancel_serial_session"/);

  const quickRequest = backend.slice(
    backend.indexOf("export type StartSerialSessionRequest"),
    backend.indexOf("export type StartSavedSerialSessionRequest"),
  );
  assert.match(quickRequest, /config: SerialConfig/);
  assert.match(quickRequest, /size: TerminalSize/);
  assert.doesNotMatch(quickRequest, /password|credentialReference/);
});

test("SavedHost DTO can carry a canonical Serial config without activating credentials", async () => {
  const backend = await readFile(backendUrl, "utf8");
  assert.match(backend, /protocol\?: "ssh" \| "telnet" \| "serial"/);
  assert.match(backend, /serialConfig: SerialConfig \| null/);
  assert.match(backend, /hasExplicitSerialBackspaceBehavior: boolean/);
  assert.match(backend, /hasExplicitCharset: boolean/);
  assert.match(backend, /serialConfig\?: SerialConfig/);
  assert.match(backend, /export type StartSavedSerialSessionRequest[\s\S]*?hostId: string[\s\S]*?expectedRevision: number/);
});
