import assert from "node:assert/strict";
import test from "node:test";

import {
  AI_COMMANDS,
  createNativeAiChatTransport,
  type AiChatEventChannel,
  type NativeAiChatRequest,
} from "../../src/aiApi.ts";

test("native AI transport forwards the path-free image content-part contract unchanged", async () => {
  const calls: Array<{ command: string; args?: Record<string, unknown> }> = [];
  const channel: AiChatEventChannel = { onmessage: () => undefined };
  const transport = createNativeAiChatTransport(
    async <T>(command: string, args?: Record<string, unknown>): Promise<T> => {
      calls.push({ command, args });
      return { content: "vision answer" } as T;
    },
    () => channel,
  );
  const request: NativeAiChatRequest = {
    providerProfileId: "vision-profile",
    messages: [{
      role: "user",
      content: "Describe this image.",
      contentParts: [{
        type: "image",
        mimeType: "image/png",
        data: "iVBORw0KGgo=",
      }],
    }],
  };

  assert.equal(
    await transport(request, new AbortController().signal),
    "vision answer",
  );
  assert.equal(calls.length, 1);
  assert.equal(calls[0]?.command, AI_COMMANDS.stream);
  const nativeRequest = calls[0]?.args?.request as Record<string, unknown>;
  assert.deepEqual(nativeRequest.messages, request.messages);
  assert.equal("path" in nativeRequest, false);
  assert.equal("url" in nativeRequest, false);
});
