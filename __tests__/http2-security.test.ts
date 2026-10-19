/**
 * HTTP/2 requests go through the same validation firewall as HTTP/1
 * (buildSafeRequestOptions, parseSafeUrl, reserved-IP enforcement). Invalid
 * input must fail BEFORE a session is requested. The option-validation tests
 * need no server: the injected connectFn records any attempt to connect and
 * the assertions prove there was none. The URL and reserved-IP tests use a
 * real h2c server on 127.0.0.1 whose `session` counter proves whether a
 * connection was ever opened.
 */
import {
  afterEach,
  beforeEach,
  describe,
  it,
  mock,
  type TestContext,
} from "node:test";
import assert from "node:assert/strict";
import EventEmitter from "node:events";
import dnsPromises from "node:dns/promises";
import {
  createServer,
  type Http2Server,
  type IncomingHttpHeaders,
  type ServerHttp2Stream,
} from "node:http2";
import { type AddressInfo, isIP } from "node:net";
import { Http2SessionManager } from "../src/classes/http-session-mannager.ts";
import {
  SecureHttpError,
  UltraTonNetworkTimeoutError,
} from "../src/errors.ts";
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

const RESERVED = /prohibited internal\/reserved/;

/**
 * Cleartext HTTP/2 server on 127.0.0.1 plus a client wired to its own session
 * manager. `sessionCount()` is how many connections the server ever accepted.
 * Cleanup is registered on the test context so the process always exits.
 */
const startFixture = async (t: TestContext) => {
  let sessions = 0;
  const server = createServer();
  server.on("session", () => {
    sessions++;
  });
  server.on("stream", (stream, headers) => {
    if (headers[":path"] === "/redirect") {
      stream.respond({ ":status": 302, location: "http://example.com/" });
      stream.end();
      return;
    }
    stream.respond({ ":status": 200, "content-type": "text/plain" });
    stream.end("H2-INTERNAL");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;

  const manager = new Http2SessionManager();
  t.after(async () => {
    manager.closeAll();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  return {
    port,
    url: `http://127.0.0.1:${port}/`,
    client: new UltraTonHTTP2({}, manager),
    sessionCount: () => sessions,
  };
};

const fakeSession = () =>
  Object.assign(new EventEmitter(), {
    closed: false,
    destroyed: false,
    setTimeout: () => {},
    close() {
      this.closed = true;
      this.emit("close");
    },
    destroy() {
      this.destroyed = true;
    },
  });

// No test using this may reach a real resolver: IP literals are echoed back,
// any other hostname fails fast instead of touching the network.
const mockIpLiteralDns = () => {
  mock.method(dnsPromises, "lookup", async (host: string) => {
    const family = isIP(host);
    if (family === 0) {
      throw Object.assign(new Error("no resolver in tests"), {
        code: "ENOTFOUND",
      });
    }
    return { address: host, family };
  });
};

describe("HTTP/2 safe URLs and reserved-IP enforcement", () => {
  beforeEach(mockIpLiteralDns);
  afterEach(() => mock.restoreAll());

  it("blocks reserved IP literals by default without opening a session", async (t) => {
    const { client, port, sessionCount } = await startFixture(t);

    for (const url of [
      `http://127.0.0.1:${port}/`,
      `http://2130706433:${port}/`,
      `https://[::ffff:127.0.0.1]:${port}/`,
      "https://[64:ff9b::a00:5]/",
    ]) {
      await assert.rejects(client.get(url), (err: unknown) => {
        assert.ok(err instanceof SecureHttpError, url);
        assert.match(err.message, RESERVED, url);
        return true;
      });
    }
    assert.strictEqual(sessionCount(), 0);
  });

  it("connects to a reserved IP when permitReservedIps is true", async (t) => {
    const { client, url } = await startFixture(t);

    const res = await client.get(url, { permitReservedIps: true });

    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(String(res.body), "H2-INTERNAL");
  });

  it("does not reuse a pooled session for a request that forbids reserved IPs", async (t) => {
    const { client, url, sessionCount } = await startFixture(t);

    const allowed = await client.get(url, { permitReservedIps: true });
    assert.strictEqual(allowed.statusCode, 200);

    await assert.rejects(
      client.get(url, { permitReservedIps: false }),
      RESERVED,
    );
    assert.strictEqual(sessionCount(), 1);
  });

  it("does not share a pending connection across permit flags", async (t) => {
    const { client, url, sessionCount } = await startFixture(t);

    const [permitted, forbidden] = await Promise.allSettled([
      client.get(url, { permitReservedIps: true }),
      client.get(url, { permitReservedIps: false }),
    ]);

    assert.strictEqual(permitted.status, "fulfilled");
    assert.strictEqual(forbidden.status, "rejected");
    assert.match((forbidden as PromiseRejectedResult).reason.message, RESERVED);
    assert.strictEqual(sessionCount(), 1);
  });

  it("does not fail a permitted request because a concurrent forbidden one failed", async (t) => {
    const { client, url, sessionCount } = await startFixture(t);

    const [forbidden, permitted] = await Promise.allSettled([
      client.get(url, { permitReservedIps: false }),
      client.get(url, { permitReservedIps: true }),
    ]);

    assert.strictEqual(forbidden.status, "rejected");
    assert.match((forbidden as PromiseRejectedResult).reason.message, RESERVED);
    assert.strictEqual(permitted.status, "fulfilled");
    assert.strictEqual(sessionCount(), 1);
  });

  it("rejects credentials in the URL", async (t) => {
    const { client, port, sessionCount } = await startFixture(t);

    await assert.rejects(
      client.get(`http://u:p@127.0.0.1:${port}/`, {
        permitReservedIps: true,
      }),
      /Credentials in URL/,
    );
    assert.strictEqual(sessionCount(), 0);
  });

  it("rejects a redirect that downgrades to http on a non-local host", async (t) => {
    const { client, port } = await startFixture(t);

    await assert.rejects(
      client.get(`http://127.0.0.1:${port}/redirect`, {
        permitReservedIps: true,
        maxRedirects: 1,
      }),
      /Unsupported protocol/,
    );
  });

  it("brackets IPv6 pinned addresses in the connect URL", async () => {
    const connect = mock.fn((_url: string, _options: unknown) => fakeSession());
    const manager = new Http2SessionManager({}, connect as any);

    await manager.getSession("https://[::1]:8443", undefined, true);

    assert.strictEqual(connect.mock.callCount(), 1);
    const [url, options] = connect.mock.calls[0].arguments;
    assert.strictEqual(url, "https://[::1]:8443");
    assert.strictEqual((options as any).servername, "::1");
  });
});

type OnStream = (stream: ServerHttp2Stream, headers: IncomingHttpHeaders) => void;
type Echo = {
  method: string;
  headers: Record<string, string | undefined>;
  body: string;
};

/** Answers 200 with the method, headers and body this server actually received. */
const echo: OnStream = (stream, headers) => {
  const chunks: Buffer[] = [];
  stream.on("data", (chunk: Buffer) => chunks.push(chunk));
  stream.on("end", () => {
    stream.respond({ ":status": 200, "content-type": "application/json" });
    stream.end(
      JSON.stringify({
        method: headers[":method"],
        headers,
        body: Buffer.concat(chunks).toString(),
      }),
    );
  });
};

const redirect = (stream: ServerHttp2Stream, status: number, location: string) => {
  stream.resume();
  stream.respond({ ":status": status, location });
  stream.end();
};

/**
 * Any number of h2c servers on 127.0.0.1 (one `listen` each, resolving to its
 * port) and one client over a private session pool. Sessions are closed before
 * the servers so the process always exits.
 */
const startServers = (t: TestContext) => {
  const manager = new Http2SessionManager();
  const servers: Http2Server[] = [];
  t.after(async () => {
    manager.closeAll();
    await Promise.all(
      servers.map((s) => new Promise<void>((resolve) => s.close(() => resolve()))),
    );
  });

  return {
    client: new UltraTonHTTP2({}, manager),
    listen: async (onStream: OnStream) => {
      const server = createServer();
      server.on("stream", onStream);
      servers.push(server);
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      return (server.address() as AddressInfo).port;
    },
  };
};

describe("HTTP/2 redirect hygiene and timeout budget", () => {
  beforeEach(mockIpLiteralDns);
  afterEach(() => mock.restoreAll());

  it("drops credentials on a cross-origin redirect and keeps them on same-origin", async (t) => {
    const { client, listen } = startServers(t);
    const portB = await listen(echo);
    const portA = await listen((stream, headers) => {
      switch (headers[":path"]) {
        case "/cross":
          return redirect(stream, 302, `http://127.0.0.1:${portB}/echo`);
        case "/cross-303":
          return redirect(stream, 303, `http://127.0.0.1:${portB}/echo`);
        case "/same":
          return redirect(stream, 302, "/echo");
        default:
          return echo(stream, headers);
      }
    });
    // Mixed case on purpose: stripping must not depend on how the caller spelled the key.
    const headers = {
      Authorization: "Bearer secret",
      Cookie: "sid=1",
      "Proxy-Authorization": "Basic c2VjcmV0",
      "X-Safe": "keep",
    };
    const options = { permitReservedIps: true, maxRedirects: 1, headers };

    const cross = await client
      .get<Echo>(`http://127.0.0.1:${portA}/cross`, options)
      .then((res) => res.json());
    assert.strictEqual(cross.headers[":authority"], `127.0.0.1:${portB}`);
    assert.strictEqual(cross.headers["authorization"], undefined);
    assert.strictEqual(cross.headers["cookie"], undefined);
    assert.strictEqual(cross.headers["proxy-authorization"], undefined);
    assert.strictEqual(cross.headers["x-safe"], "keep");

    const same = await client
      .get<Echo>(`http://127.0.0.1:${portA}/same`, options)
      .then((res) => res.json());
    assert.strictEqual(same.headers[":authority"], `127.0.0.1:${portA}`);
    assert.strictEqual(same.headers["authorization"], "Bearer secret");
    assert.strictEqual(same.headers["cookie"], "sid=1");
    assert.strictEqual(same.headers["proxy-authorization"], "Basic c2VjcmV0");
    assert.strictEqual(same.headers["x-safe"], "keep");

    // A 303 turns the POST into a GET: the rebuilt method and headers are what goes on the wire.
    const downgraded = await client
      .post<Echo>(`http://127.0.0.1:${portA}/cross-303`, {
        ...options,
        body: '{"a":1}',
        headers: { ...headers, "Content-Type": "application/json" },
      })
      .then((res) => res.json());
    assert.strictEqual(downgraded.headers[":authority"], `127.0.0.1:${portB}`);
    assert.strictEqual(downgraded.method, "GET");
    assert.strictEqual(downgraded.body, "");
    assert.strictEqual(downgraded.headers["content-type"], undefined);
    assert.strictEqual(downgraded.headers["content-length"], undefined);
    assert.strictEqual(downgraded.headers["authorization"], undefined);
    assert.strictEqual(downgraded.headers["x-safe"], "keep");
  });

  it("shares one absolute timeout budget across redirect hops", async (t) => {
    const { client, listen } = startServers(t);
    // Each hop takes 150ms: 250ms is enough for either one, not for both.
    const port = await listen((stream, headers) => {
      const timer = setTimeout(() => {
        if (stream.destroyed) return;
        if (headers[":path"] === "/slow") {
          stream.respond({ ":status": 200, "content-type": "text/plain" });
          stream.end("done");
        } else {
          redirect(stream, 302, "/slow");
        }
      }, 150);
      stream.on("close", () => clearTimeout(timer));
    });
    const url = `http://127.0.0.1:${port}/`;
    const options = { permitReservedIps: true, maxRedirects: 1 };

    const roomy = await client.get(url, { ...options, timeoutMs: 1000 });
    assert.strictEqual(String(roomy.body), "done");

    await assert.rejects(client.get(url, { ...options, timeoutMs: 250 }), (err: unknown) => {
      assert.ok(err instanceof UltraTonNetworkTimeoutError);
      assert.match(err.message, /Absolute execution time of 250ms exceeded/);
      return true;
    });
  });

  it("refuses to start a hop once the budget is spent", async (t) => {
    const { client, listen } = startServers(t);
    // The clock jumps 1s while the first hop is answered, so hop 2 starts with a negative budget.
    const realNow = Date.now;
    let skewMs = 0;
    t.mock.method(Date, "now", () => realNow() + skewMs);
    const paths: string[] = [];
    const port = await listen((stream, headers) => {
      paths.push(String(headers[":path"]));
      skewMs = 1000;
      redirect(stream, 302, "/second");
    });

    await assert.rejects(
      client.get(`http://127.0.0.1:${port}/first`, {
        permitReservedIps: true,
        maxRedirects: 1,
        timeoutMs: 250,
      }),
      UltraTonNetworkTimeoutError,
    );
    assert.deepStrictEqual(paths, ["/first"]);
  });
});
