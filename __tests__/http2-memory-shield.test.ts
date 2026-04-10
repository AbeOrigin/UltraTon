/**
 * Sprint 6: Surgical Memory Shield
 * Verifies that the maxBodySize guard:
 *   1. Rejects with UltraTonMemoryError on overflow.
 *   2. Closes only the affected stream with NGHTTP2_CANCEL (code 8).
 *   3. Leaves the parent session alive (session survival guarantee).
 *   4. Allows a second stream on the same session to succeed (multiplexing continuity).
 *
 * Strategy: inject a mock Http2SessionManager through the internal DI seam
 * (2nd constructor parameter of UltraTonHTTP2) and a mock connectFn into
 * Http2SessionManager. DNS lookup is mocked to return a safe public IP so
 * the pinner passes without hitting the network.
 */
import { describe, it, mock } from "node:test";
import assert from "node:assert/strict";
import EventEmitter from "node:events";
import dnsPromises from "node:dns/promises";
import http2 from "node:http2";
import { Http2SessionManager } from "../src/classes/http-session-mannager.ts";
import { UltraTonHTTP2 } from "../src/http2-client.ts";
import { UltraTonMemoryError } from "../src/exceptions/out-of-memory.error.ts";

// ---------------------------------------------------------------------------
// Mock factories
// ---------------------------------------------------------------------------

interface MockStream extends EventEmitter {
  closeArgs: (number | undefined)[];
  close(code?: number): void;
  end(): void;
  write(data: unknown): boolean;
}

interface MockSession extends EventEmitter {
  closed: boolean;
  destroyed: boolean;
  close(): void;
  destroy(): void;
  setTimeout(ms: number): void;
  request(_headers: unknown): MockStream;
}

const createMockStream = (): MockStream => {
  const stream = new EventEmitter() as MockStream;
  stream.closeArgs = [];
  stream.close = (code?: number) => {
    stream.closeArgs.push(code);
    stream.emit("close");
  };
  stream.end = () => {};
  stream.write = () => true;
  return stream;
};

const createMockSession = (streamFactory: () => MockStream): MockSession => {
  const session = new EventEmitter() as MockSession;
  session.closed = false;
  session.destroyed = false;
  session.close = () => {
    session.closed = true;
    session.emit("close");
  };
  session.destroy = () => {
    session.destroyed = true;
  };
  session.setTimeout = () => {};
  session.request = () => streamFactory();
  return session;
};

/**
 * Builds an isolated UltraTonHTTP2 client using the DI constructor seam.
 * The injected Http2SessionManager uses a mock connectFn so no TCP socket
 * is ever opened. DNS lookup is mocked to emit a safe public IP.
 */
const buildTestClient = (
  streamFactory: () => MockStream,
  maxBodySize: number,
  t: { mock: { method: typeof mock.method } },
): { client: UltraTonHTTP2; session: MockSession } => {
  // Bypass the DNS pinner with a safe public IP (non-reserved)
  t.mock.method(dnsPromises, "lookup", async () => ({
    address: "93.184.216.34", // example.com public IP
    family: 4,
  }));

  const session = createMockSession(streamFactory);

  // Mock connectFn returns the pre-built mock session
  const mockConnect = mock.fn(() => session as any);

  // Build manager with DI connectFn — same pattern as http2-session-manager.test.ts
  const manager = new Http2SessionManager({}, mockConnect as any);

  // Inject manager via the internal second constructor parameter
  const client = new UltraTonHTTP2({ maxBodySize }, manager);

  return { client, session };
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("Sprint 6 – Surgical Memory Shield", () => {
  it(
    "OOM Kill: rejects with UltraTonMemoryError when body exceeds maxBodySize",
    async (t) => {
      const LIMIT = 10;
      const stream = createMockStream();
      const { client } = buildTestClient(() => stream, LIMIT, t);

      const requestPromise = client.get<unknown>("https://example.com/");

      // Yield to allow #executeStream to register its event listeners
      await new Promise((r) => setImmediate(r));

      stream.emit("response", { ":status": 200, "content-type": "text/plain" });
      stream.emit("data", Buffer.alloc(LIMIT + 1, "x")); // 11 bytes > 10-byte limit

      await assert.rejects(requestPromise, (err: unknown) => {
        assert.ok(
          err instanceof UltraTonMemoryError,
          `Expected UltraTonMemoryError, got: ${(err as Error).constructor.name}`,
        );
        assert.match((err as Error).message, /exceeded the maximum allowed size/);
        return true;
      });
    },
  );

  it(
    "Surgical Kill: stream.close is called with NGHTTP2_CANCEL (code 8) on OOM",
    async (t) => {
      const LIMIT = 10;
      const stream = createMockStream();
      const { client } = buildTestClient(() => stream, LIMIT, t);

      const requestPromise = client.get<unknown>("https://example.com/");
      await new Promise((r) => setImmediate(r));

      stream.emit("response", { ":status": 200, "content-type": "text/plain" });
      stream.emit("data", Buffer.alloc(LIMIT + 1, "x"));

      await requestPromise.catch(() => {
        /* expected rejection */
      });

      assert.equal(
        stream.closeArgs.length,
        1,
        "stream.close must be called exactly once",
      );
      assert.equal(
        stream.closeArgs[0],
        http2.constants.NGHTTP2_CANCEL,
        `Expected NGHTTP2_CANCEL (${http2.constants.NGHTTP2_CANCEL}), got: ${stream.closeArgs[0]}`,
      );
    },
  );

  it(
    "Session Survival: the parent session is NOT destroyed or closed after a stream OOM",
    async (t) => {
      const LIMIT = 10;
      const stream = createMockStream();
      const { client, session } = buildTestClient(() => stream, LIMIT, t);

      const requestPromise = client.get<unknown>("https://example.com/");
      await new Promise((r) => setImmediate(r));

      stream.emit("response", { ":status": 200, "content-type": "text/plain" });
      stream.emit("data", Buffer.alloc(LIMIT + 1, "x"));

      await requestPromise.catch(() => {
        /* expected rejection */
      });

      assert.equal(
        session.closed,
        false,
        "session.closed must remain false — only the stream was killed",
      );
      assert.equal(
        session.destroyed,
        false,
        "session.destroyed must remain false — only the stream was killed",
      );
    },
  );

  it(
    "Multiplexing Continuity: a second request on the same session succeeds after an OOM kill",
    async (t) => {
      const LIMIT = 10;
      const badStream = createMockStream();
      const goodStream = createMockStream();
      const GOOD_BODY = Buffer.from("hello");

      let callCount = 0;
      const { client, session } = buildTestClient(() => {
        callCount++;
        return callCount === 1 ? badStream : goodStream;
      }, LIMIT, t);

      // --- First request: triggers OOM ---
      const firstRequest = client.get<unknown>("https://example.com/");
      await new Promise((r) => setImmediate(r));

      badStream.emit("response", { ":status": 200, "content-type": "text/plain" });
      badStream.emit("data", Buffer.alloc(LIMIT + 1, "x"));
      await firstRequest.catch(() => {
        /* expected rejection */
      });

      // Session must still be alive for the second request to reuse it
      assert.equal(session.closed, false, "Session must survive OOM");
      assert.equal(session.destroyed, false, "Session must survive OOM");

      // --- Second request: clean response on the same session ---
      const secondRequest = client.get<unknown>("https://example.com/health");
      await new Promise((r) => setImmediate(r));

      goodStream.emit("response", { ":status": 200, "content-type": "text/plain" });
      goodStream.emit("data", GOOD_BODY);
      goodStream.emit("end");

      const response = await secondRequest;
      assert.equal(
        response.statusCode,
        200,
        "Second request must resolve cleanly with 200",
      );
    },
  );
});
