import assert from "node:assert/strict";
import test from "node:test";

import {
  formatTelnetLocalEcho,
  resolveQuickConnectProtocolPort,
} from "../../src/telnetLocalEcho.ts";

test("Quick Connect changes only untouched SSH and Telnet default ports", () => {
  assert.equal(resolveQuickConnectProtocolPort("22", "ssh", "telnet"), "23");
  assert.equal(resolveQuickConnectProtocolPort("23", "telnet", "ssh"), "22");
  assert.equal(resolveQuickConnectProtocolPort("2222", "ssh", "telnet"), "2222");
  assert.equal(resolveQuickConnectProtocolPort("2323", "telnet", "ssh"), "2323");
  assert.equal(resolveQuickConnectProtocolPort("", "ssh", "telnet"), "");
  assert.equal(resolveQuickConnectProtocolPort("22", "ssh", "ssh"), "22");
});

test("Telnet local echo preserves printable text and normalizes line endings", () => {
  assert.equal(formatTelnetLocalEcho("show version\r"), "show version\r\n");
  assert.equal(formatTelnetLocalEcho("one\ntwo"), "one\r\ntwo");
  assert.equal(formatTelnetLocalEcho("one\r\ntwo"), "one\r\ntwo");
});

test("Telnet local echo renders editing keys without leaking escape input", () => {
  assert.equal(formatTelnetLocalEcho("\x7f"), "\b \b");
  assert.equal(formatTelnetLocalEcho("\b"), "\b \b");
  assert.equal(formatTelnetLocalEcho("\x03"), "^C");
  assert.equal(formatTelnetLocalEcho("\x1b[A"), "");
  assert.equal(formatTelnetLocalEcho("\x1bOP"), "");
  assert.equal(formatTelnetLocalEcho("\x1bb"), "");
});
