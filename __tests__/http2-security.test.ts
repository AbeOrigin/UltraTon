/**
 * HTTP/2 requests go through the same validation firewall as HTTP/1
 * (buildSafeRequestOptions). Invalid input must fail BEFORE a session is
 * requested, so none of these tests needs a server: the injected connectFn
 * records any attempt to connect and the assertions prove there was none.
 */
import { describe, it, mock } from "node:test";
import assert from "node:assert/strict";
import dnsPromises from "node:dns/promises";
import { Http2SessionManager } from "../src/classes/http-session-mannager.ts";
import { UltraTonHTTP2 } from "../src/http2-client.ts";

const buildClient = (t: { mock: { method: typeof mock.method } }) => {
  t.mock.method(dnsPromises, "lookup", async () => ({
    address: "93.184.216.34",
    family: 4,
  }));

  const connect = mock.fn(() => {
    throw new Error("connectFn must not be reached");
  });
  const manager = new Http2SessionManager({}, connect as any);

  return { client: new UltraTonHTTP2({}, manager), connect };
};

describe("HTTP/2 validation firewall", () => {
  it("rejects CRLF in a header value before connecting", async (t) => {
    const { client, connect } = buildClient(t);

    await assert.rejects(
      client.get("https://example.com/", {
        headers: { "x-a": "v\r\nx-b: 1" },
      }),
      TypeError,
    );
    assert.strictEqual(connect.mock.callCount(), 0);
  });

  it("rejects caller-supplied pseudo-headers", async (t) => {
    const { client, connect } = buildClient(t);

    await assert.rejects(
      client.get("https://example.com/", {
        headers: { ":authority": "evil.example" },
      }),
      (err: unknown) => {
        assert.ok(err instanceof TypeError);
        assert.match(err.message, /pseudo-header/);
        return true;
      },
    );
    assert.strictEqual(connect.mock.callCount(), 0);
  });

  it("rejects a non-number maxBodySize", async (t) => {
    const { client, connect } = buildClient(t);

    await assert.rejects(
      client.get("https://example.com/", { maxBodySize: "5" as any }),
      (err: unknown) => {
        assert.ok(err instanceof TypeError);
        assert.match(err.message, /Expected 'maxBodySize' to be a number/);
        return true;
      },
    );
    assert.strictEqual(connect.mock.callCount(), 0);
  });
});
