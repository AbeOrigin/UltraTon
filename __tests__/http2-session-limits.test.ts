import { describe, it, mock } from "node:test";
import assert from "node:assert/strict";
import dnsPromises from "node:dns/promises";
import type {
  ClientHttp2Session,
  SecureClientSessionOptions,
  connect,
} from "node:http2";
import { Http2SessionManager } from "../src/classes/http-session-mannager.ts";
import {
  MAX_HEADER_LIST_PAIRS,
  MAX_HEADER_LIST_SIZE,
  MAX_SESSION_MEMORY_MB,
} from "../src/constants/limits.ts";

/**
 * Interface that mirrors what Http2SessionManager sends to http2.connect.
 */
interface ExtendedConnectOptions extends SecureClientSessionOptions {
  maxHeaderListPairs?: number;
  settings: NonNullable<SecureClientSessionOptions["settings"]>;
}

/**
 * Type for the mocked connect function to ensure type-safe argument access in tests.
 */
type MockConnectFn = (
  url: string | URL,
  options?: ExtendedConnectOptions,
) => ClientHttp2Session;

describe("Sprint 7 – Native Configuration Hardening", () => {
  it("passes paranoid limits to http2.connect", async (t) => {
    t.mock.method(dnsPromises, "lookup", async () => ({
      address: "1.2.3.4",
      family: 4,
    }));

    const mockSession = {
      on: mock.fn(),
      setTimeout: mock.fn(),
      closed: false,
      destroyed: false,
    } as unknown as ClientHttp2Session;

    // By providing the generic type to mock.fn, call.arguments becomes type-safe
    const mockConnect = mock.fn<MockConnectFn>(() => mockSession);

    const manager = new Http2SessionManager(
      {},
      mockConnect as unknown as typeof connect,
    );

    await manager.getSession("https://example.com");

    assert.strictEqual(mockConnect.mock.callCount(), 1);

    const call = mockConnect.mock.calls[0];
    const options = call.arguments[1];

    assert.ok(options, "Options should be provided");
    assert.strictEqual(
      options.settings.maxHeaderListSize,
      MAX_HEADER_LIST_SIZE,
    );
    assert.strictEqual(options.maxSessionMemory, MAX_SESSION_MEMORY_MB);
    assert.strictEqual(options.maxHeaderListPairs, MAX_HEADER_LIST_PAIRS);
  });

  it("allows overriding paranoid limits via overrideOptions", async (t) => {
    t.mock.method(dnsPromises, "lookup", async () => ({
      address: "1.2.3.4",
      family: 4,
    }));

    const mockSession = {
      on: mock.fn(),
      setTimeout: mock.fn(),
      closed: false,
      destroyed: false,
    } as unknown as ClientHttp2Session;

    const mockConnect = mock.fn<MockConnectFn>(() => mockSession);
    const manager = new Http2SessionManager(
      {},
      mockConnect as unknown as typeof connect,
    );

    await manager.getSession("https://example.com", {
      maxSessionMemory: 10,
      settings: {
        maxHeaderListSize: 99999,
      },
    });

    const call = mockConnect.mock.calls[0];
    const options = call.arguments[1];

    assert.ok(options, "Options should be provided");
    assert.strictEqual(options.settings.maxHeaderListSize, 99999);
    assert.strictEqual(options.maxSessionMemory, 10);
    assert.strictEqual(options.maxHeaderListPairs, MAX_HEADER_LIST_PAIRS);
  });
});
