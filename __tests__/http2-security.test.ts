/**
 * HTTP/2 requests go through the same validation firewall as HTTP/1
 * (buildSafeRequestOptions, parseSafeUrl, reserved-IP enforcement). Invalid
 * input must fail BEFORE a session is requested. The option-validation tests
 * need no server: the injected connectFn records any attempt to connect and
 * the assertions prove there was none. The URL and reserved-IP tests use a
 * real h2c server on 127.0.0.1, but count connections on the client side: the
 * connectFn is a spy around the real http2.connect, so "no connection" holds for
 * any port (a server-side counter is racy and blind to everything but its own port).
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
  type ClientHttp2Session,
  connect as nativeConnect,
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

  it("rejects a caller-supplied host header on HTTP/2", async (t) => {
    const { client, connect } = buildClient(t);

    // Mixed case on purpose: the check must not depend on how the caller spelled the key.
    await assert.rejects(
      client.get("https://example.com/", { headers: { Host: "evil.example" } }),
      (err: unknown) => {
        assert.ok(err instanceof TypeError);
        assert.match(err.message, /'host' header cannot be set on HTTP\/2 requests/);
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

/** Polls instead of sleeping a fixed time: resolves as soon as `condition` holds, or after `ms`. */
const until = async (condition: () => boolean, ms = 1000) => {
  for (const deadline = Date.now() + ms; !condition() && Date.now() < deadline; ) {
    await new Promise<void>((resolve) => setTimeout(resolve, 10));
  }
};

/**
 * Cleartext HTTP/2 server on 127.0.0.1 plus a client wired to its own session
 * manager. `connect` is a spy around the real http2.connect: its call count is
 * how many connections the client opened. The server-side `accepted()` and
 * `openSessions()` only say what has arrived by now, so they are never used to
 * prove that nothing was opened. Cleanup is registered on the test context so
 * the process always exits.
 */
const startFixture = async (t: TestContext) => {
  let accepted = 0;
  let open = 0;
  const server = createServer();
  server.on("session", (session) => {
    accepted++;
    open++;
    session.on("close", () => {
      open--;
    });
  });
  server.on("stream", (stream, headers) => {
    if (headers[":path"] === "/redirect") {
      stream.respond({ ":status": 302, location: "http://example.com/" });
      stream.end();
      return;
    }
    if (headers[":path"] === "/to-literal") {
      stream.respond({ ":status": 302, location: `http://127.0.0.1:${port}/x` });
      stream.end();
      return;
    }
    stream.respond({ ":status": 200, "content-type": "text/plain" });
    stream.end("H2-INTERNAL");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;

  const connect = t.mock.fn(nativeConnect);
  const manager = new Http2SessionManager({}, connect);
  t.after(async () => {
    manager.closeAll();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  return {
    port,
    url: `http://127.0.0.1:${port}/`,
    client: new UltraTonHTTP2({}, manager),
    manager,
    connect,
    accepted: () => accepted,
    openSessions: () => open,
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
    const { client, port, connect } = await startFixture(t);

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
    assert.strictEqual(connect.mock.callCount(), 0);
  });

  it("connects to a reserved IP when permitReservedIps is true", async (t) => {
    const { client, url } = await startFixture(t);

    const res = await client.get(url, { permitReservedIps: true });

    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(String(res.body), "H2-INTERNAL");
  });

  it("connects to a reserved IP covered by a CIDR allowlist", async (t) => {
    const { client, url, connect } = await startFixture(t);

    const res = await client.get(url, { permitReservedIps: ["127.0.0.0/8"] });

    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(String(res.body), "H2-INTERNAL");
    assert.strictEqual(connect.mock.callCount(), 1);
  });

  it("rejects a reserved IP outside the allowlist without connecting", async (t) => {
    const { client, url, connect } = await startFixture(t);

    await assert.rejects(client.get(url, { permitReservedIps: ["10.0.0.0/8"] }), (err: unknown) => {
      assert.ok(err instanceof SecureHttpError);
      assert.match(err.message, RESERVED);
      assert.doesNotMatch(err.message, /127\.0\.0\.1/);
      return true;
    });
    assert.strictEqual(connect.mock.callCount(), 0);
  });

  it("applies the client-wide allowlist when a request sets none", async (t) => {
    const { manager, url, connect } = await startFixture(t);
    const client = new UltraTonHTTP2({ permitReservedIps: ["127.0.0.0/8"] }, manager);

    const res = await client.get(url);

    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(connect.mock.callCount(), 1);
  });

  it("keeps sessions of different allowlists apart in the pool", async (t) => {
    const { manager, port, connect } = await startFixture(t);
    const origin = `http://127.0.0.1:${port}`;

    const wide = await manager.getSession(origin, undefined, ["127.0.0.0/8"]);
    const same = await manager.getSession(origin, undefined, ["127.0.0.0/8"]);
    const narrow = await manager.getSession(origin, undefined, ["127.0.0.1"]);
    const all = await manager.getSession(origin, undefined, true);
    await assert.rejects(manager.getSession(origin, undefined, ["10.0.0.0/8"]), RESERVED);

    assert.strictEqual(wide, same);
    assert.notStrictEqual(wide, narrow);
    assert.notStrictEqual(wide, all);
    assert.strictEqual(connect.mock.callCount(), 3);
  });

  it("does not reuse a pooled session for a request that forbids reserved IPs", async (t) => {
    const { client, url, connect } = await startFixture(t);

    const allowed = await client.get(url, { permitReservedIps: true });
    assert.strictEqual(allowed.statusCode, 200);

    await assert.rejects(
      client.get(url, { permitReservedIps: false }),
      RESERVED,
    );
    assert.strictEqual(connect.mock.callCount(), 1);
  });

  it("does not share a pending connection across permit flags", async (t) => {
    const { client, url, connect } = await startFixture(t);

    const [permitted, forbidden] = await Promise.allSettled([
      client.get(url, { permitReservedIps: true }),
      client.get(url, { permitReservedIps: false }),
    ]);

    assert.strictEqual(permitted.status, "fulfilled");
    assert.strictEqual(forbidden.status, "rejected");
    assert.match((forbidden as PromiseRejectedResult).reason.message, RESERVED);
    assert.strictEqual(connect.mock.callCount(), 1);
  });

  it("does not fail a permitted request because a concurrent forbidden one failed", async (t) => {
    const { client, url, connect } = await startFixture(t);

    const [forbidden, permitted] = await Promise.allSettled([
      client.get(url, { permitReservedIps: false }),
      client.get(url, { permitReservedIps: true }),
    ]);

    assert.strictEqual(forbidden.status, "rejected");
    assert.match((forbidden as PromiseRejectedResult).reason.message, RESERVED);
    assert.strictEqual(permitted.status, "fulfilled");
    assert.strictEqual(connect.mock.callCount(), 1);
  });

  it("dedupes concurrent permissive requests into one connection", async (t) => {
    const { manager, port, connect, accepted, openSessions } = await startFixture(t);
    const origin = `http://127.0.0.1:${port}`;

    // The strict request starts first: the permissive ones must not wait for, or retry after, its failure.
    const [strict, ...permissive] = await Promise.allSettled([
      manager.getSession(origin, undefined, false),
      ...Array.from({ length: 5 }, () => manager.getSession(origin, undefined, true)),
    ]);

    assert.strictEqual(strict.status, "rejected");
    assert.match((strict as PromiseRejectedResult).reason.message, RESERVED);
    const sessions = permissive.map((result) => {
      assert.strictEqual(result.status, "fulfilled");
      return (result as PromiseFulfilledResult<ClientHttp2Session>).value;
    });
    assert.strictEqual(connect.mock.callCount(), 1);
    assert.ok(sessions.every((session) => session === sessions[0]));

    // Wait for the server to see every connection first, or "0 open" below would hold vacuously.
    await until(() => accepted() === connect.mock.callCount());
    manager.closeAll();
    await until(() => openSessions() === 0);
    assert.strictEqual(openSessions(), 0);
  });

  it("closeSession closes the origin's sessions under both permit modes", async () => {
    const opened: ReturnType<typeof fakeSession>[] = [];
    const connect = mock.fn(() => {
      opened.push(fakeSession());
      return opened[opened.length - 1];
    });
    const manager = new Http2SessionManager({}, connect as any);
    const origin = "https://8.8.8.8";

    const strict = await manager.getSession(origin, undefined, false);
    const permissive = await manager.getSession(origin, undefined, true);
    assert.notStrictEqual(strict, permissive);
    assert.strictEqual(connect.mock.callCount(), 2);

    manager.closeSession(origin);

    assert.ok(opened.every((session) => session.closed && session.destroyed));
    // Nothing is left in the pool: the next caller of either mode connects afresh.
    await manager.getSession(origin, undefined, true);
    assert.strictEqual(connect.mock.callCount(), 3);
  });

  it("rejects credentials in the URL", async (t) => {
    const { client, port, connect } = await startFixture(t);

    await assert.rejects(
      client.get(`http://u:p@127.0.0.1:${port}/`, {
        permitReservedIps: true,
      }),
      /Credentials in URL/,
    );
    assert.strictEqual(connect.mock.callCount(), 0);
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

describe("HTTP/2 hostname entries in permitReservedIps", () => {
  // "localhost" resolves to the fixture's loopback address; any other host is echoed, as for IP literals.
  const mockLocalhostDns = (t: TestContext) =>
    t.mock.method(dnsPromises, "lookup", async (host: string) => ({
      address: host === "localhost" ? "127.0.0.1" : host,
      family: 4,
    }));

  it("reaches a reserved IP through the hostname the allowlist names", async (t) => {
    mockLocalhostDns(t);
    const { client, port, connect } = await startFixture(t);

    const res = await client.get(`http://localhost:${port}/`, { permitReservedIps: ["localhost"] });

    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(String(res.body), "H2-INTERNAL");
    // The connection went to the pinned address, not to the name.
    assert.strictEqual(connect.mock.callCount(), 1);
    assert.strictEqual(connect.mock.calls[0].arguments[0], `http://127.0.0.1:${port}`);
  });

  it("blocks a redirect from the allowed hostname to a reserved IP literal without connecting", async (t) => {
    const lookup = mockLocalhostDns(t);
    const { client, port, connect } = await startFixture(t);

    await assert.rejects(
      client.get(`http://localhost:${port}/to-literal`, {
        permitReservedIps: ["localhost"],
        maxRedirects: 1,
      }),
      (err: unknown) => {
        assert.ok(err instanceof SecureHttpError);
        assert.match(err.message, RESERVED);
        return true;
      },
    );
    // The second hop was resolved and judged as the literal it is, and no connection was opened for it.
    assert.deepStrictEqual(
      lookup.mock.calls.map((call) => call.arguments[0]),
      ["localhost", "127.0.0.1"],
    );
    assert.strictEqual(connect.mock.callCount(), 1, "only the first hop connected");
  });
});

describe("HTTP/2 redirects never downgrade from https to http", () => {
  it("rejects an https to http redirect even with permitReservedIps, before opening another stream", async (t) => {
    // The first hop's hostname must resolve without touching the network.
    t.mock.method(dnsPromises, "lookup", async () => ({
      address: "93.184.216.34",
      family: 4,
    }));

    // A session whose every stream answers 302 to a plaintext loopback service.
    const authorities: unknown[] = [];
    const session = Object.assign(fakeSession(), {
      request(headers: Record<string, unknown>) {
        authorities.push(headers[":authority"]);
        const stream = new EventEmitter() as EventEmitter & Record<string, unknown>;
        stream.write = () => true;
        stream.close = () => {};
        stream.end = () => {
          setImmediate(() => {
            stream.emit("response", {
              ":status": 302,
              location: "http://127.0.0.1:1/x",
            });
            stream.emit("end");
          });
        };
        return stream;
      },
    });
    const connect = t.mock.fn(() => session);
    const manager = new Http2SessionManager({}, connect as any);
    t.after(() => manager.closeAll());
    const client = new UltraTonHTTP2({}, manager);

    await assert.rejects(
      client.get("https://example.com/downgrade", {
        permitReservedIps: true,
        maxRedirects: 1,
      }),
      (err: unknown) =>
        err instanceof SecureHttpError &&
        /Redirect from https to http is not allowed/.test(err.message),
    );
    // Only the original https hop ever reached a session; nothing was asked of 127.0.0.1:1.
    assert.deepStrictEqual(authorities, ["example.com"]);
    assert.strictEqual(connect.mock.callCount(), 1);
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

/**
 * DNS runs inside the request's timeout budget. `hang.test` never gets an answer from
 * its nameserver (a lookup promise that never settles); the injected connectFn is a spy
 * that fails on purpose, so nothing here touches the network. Every test carries its own
 * `timeout` so a regression is reported as a failure instead of hanging the run.
 */
describe("HTTP/2 DNS resolution timeout budget", () => {
  const PUBLIC_IP = { address: "93.184.216.34", family: 4 };
  const neverResolves = () => new Promise<never>(() => {});

  const buildHangingDns = (t: TestContext) => {
    const lookup = t.mock.method(dnsPromises, "lookup", neverResolves as any);
    const connect = t.mock.fn(() => {
      throw new Error("connect refused on purpose");
    });
    const manager = new Http2SessionManager({}, connect as any);
    return { lookup, connect, manager, client: new UltraTonHTTP2({}, manager) };
  };

  /** Rejects with the error and when it did, so a request that wrongly succeeds fails the test. */
  const failsAfter = async (request: Promise<unknown>, start: number) => {
    try {
      await request;
    } catch (error) {
      return { error, ms: Date.now() - start };
    }
    throw new Error("expected the request to reject");
  };

  it("bounds DNS resolution by timeoutMs", { timeout: 5000 }, async (t) => {
    const { client, connect } = buildHangingDns(t);
    const start = Date.now();

    await assert.rejects(client.get("https://hang.test/", { timeoutMs: 300 }), (err: unknown) => {
      assert.ok(err instanceof UltraTonNetworkTimeoutError);
      assert.strictEqual(err.message, "UltraTon: Absolute execution time of 300ms exceeded.");
      return true;
    });

    assert.ok(Date.now() - start < 1000, "rejected within the budget plus a small margin");
    assert.strictEqual(connect.mock.callCount(), 0);
  });

  it("does not poison the pool when DNS hangs", { timeout: 5000 }, async (t) => {
    const { client, lookup, connect } = buildHangingDns(t);

    await assert.rejects(
      client.get("https://hang.test/", { timeoutMs: 200 }),
      UltraTonNetworkTimeoutError,
    );
    assert.strictEqual(lookup.mock.callCount(), 1);

    // The nameserver recovers: the next request must ask it again instead of joining the hung lookup.
    lookup.mock.mockImplementation((async () => PUBLIC_IP) as any);
    await assert.rejects(
      client.get("https://hang.test/", { timeoutMs: 2000 }),
      (err: unknown) => {
        assert.ok(err instanceof SecureHttpError);
        assert.match(err.message, /Failed to establish HTTP\/2 connection/);
        assert.doesNotMatch(err.message, /hang\.test/, "the hostname must not be echoed into the message");
        return true;
      },
    );

    assert.strictEqual(lookup.mock.callCount(), 2);
    assert.strictEqual(connect.mock.callCount(), 1);
  });

  it("applies each caller budget to a shared pending connection", { timeout: 5000 }, async (t) => {
    const { client, lookup } = buildHangingDns(t);
    const start = Date.now();

    // Same origin and policy, issued in the same tick: the 200ms request opens the lookup, the 600ms one joins it.
    const [short, long] = await Promise.all([
      failsAfter(client.get("https://hang.test/", { timeoutMs: 200 }), start),
      failsAfter(client.get("https://hang.test/", { timeoutMs: 600 }), start),
    ]);

    assert.strictEqual(lookup.mock.callCount(), 1, "the second request joined the pending lookup");
    for (const [outcome, limit] of [[short, 200], [long, 600]] as const) {
      assert.ok(outcome.error instanceof UltraTonNetworkTimeoutError);
      assert.strictEqual(
        outcome.error.message,
        `UltraTon: Absolute execution time of ${limit}ms exceeded.`,
      );
      assert.ok(outcome.ms >= limit - 50, `${limit}ms request rejected too early (${outcome.ms}ms)`);
      assert.ok(outcome.ms < limit + 300, `${limit}ms request rejected too late (${outcome.ms}ms)`);
    }
  });

  it("lets a joined caller outlive the request that opened the lookup", { timeout: 5000 }, async (t) => {
    const { client, lookup } = buildHangingDns(t);
    const start = Date.now();

    // Reverse order: the long request opens the lookup, the short one joins it and gives up first.
    const [long, short] = await Promise.all([
      failsAfter(client.get("https://hang.test/", { timeoutMs: 600 }), start),
      failsAfter(client.get("https://hang.test/", { timeoutMs: 200 }), start),
    ]);

    assert.strictEqual(lookup.mock.callCount(), 1);
    assert.ok(short.ms < 500, `the joined 200ms request rejected at ${short.ms}ms`);
    assert.ok(long.ms >= 550 && long.ms < 900, `the 600ms request rejected at ${long.ms}ms`);
    assert.ok(short.error instanceof UltraTonNetworkTimeoutError);
    assert.ok(long.error instanceof UltraTonNetworkTimeoutError);
  });

  it("keeps timeoutMs: 0 as no timeout for a slow DNS answer", { timeout: 5000 }, async (t) => {
    const { client, lookup, connect } = buildHangingDns(t);
    lookup.mock.mockImplementation(
      (() => new Promise((resolve) => setTimeout(() => resolve(PUBLIC_IP), 300))) as any,
    );

    await assert.rejects(
      client.get("https://slow.test/", { timeoutMs: 0 }),
      (err: unknown) => {
        // Reaching the connect step proves the slow lookup was waited for, not timed out.
        assert.ok(err instanceof SecureHttpError);
        assert.match(err.message, /Failed to establish HTTP\/2 connection/);
        return true;
      },
    );
    assert.strictEqual(connect.mock.callCount(), 1);
  });

  it("opens no connection when the lookup answers after every caller gave up", { timeout: 5000 }, async (t) => {
    const { client, lookup, connect } = buildHangingDns(t);
    let answer!: (value: unknown) => void;
    lookup.mock.mockImplementation((() => new Promise((resolve) => { answer = resolve; })) as any);

    await assert.rejects(
      client.get("https://late.test/", { timeoutMs: 100 }),
      UltraTonNetworkTimeoutError,
    );
    answer(PUBLIC_IP);
    await new Promise<void>((resolve) => setTimeout(resolve, 50));

    assert.strictEqual(connect.mock.callCount(), 0);
  });

  it("hands a late lookup answer to a caller that is still within budget", { timeout: 5000 }, async (t) => {
    const { manager, lookup, connect } = buildHangingDns(t);
    let answer!: (value: unknown) => void;
    lookup.mock.mockImplementation((() => new Promise((resolve) => { answer = resolve; })) as any);
    const session = fakeSession();
    connect.mock.mockImplementation((() => session) as any);
    const origin = "https://late.test";

    // The caller that opened the lookup gives up at 100ms; the second one joined it with no deadline.
    const gaveUp = manager.getSession(origin, undefined, false, AbortSignal.timeout(100));
    const patient = manager.getSession(origin, undefined, false);
    await assert.rejects(gaveUp, { name: "TimeoutError" });
    answer(PUBLIC_IP);

    assert.strictEqual(await patient, session);
    // The session is pooled under the policy and origin it was resolved for: no second lookup, no second connection.
    assert.strictEqual(await manager.getSession(origin, undefined, false), session);
    assert.strictEqual(lookup.mock.callCount(), 1);
    assert.strictEqual(connect.mock.callCount(), 1);
  });

  it("charges a redirect hop's DNS to the shared timeout budget", { timeout: 5000 }, async (t) => {
    // Hop 1 resolves at once and is answered with a 302 after 250ms; the redirect target's nameserver never answers.
    t.mock.method(dnsPromises, "lookup", (async (host: string) =>
      host === "hang.test" ? neverResolves() : PUBLIC_IP) as any);
    const session = Object.assign(fakeSession(), {
      request() {
        const stream = new EventEmitter() as EventEmitter & Record<string, unknown>;
        stream.write = () => true;
        stream.close = () => {};
        stream.end = () => {
          setTimeout(() => {
            stream.emit("response", { ":status": 302, location: "https://hang.test/" });
            stream.emit("end");
          }, 250);
        };
        return stream;
      },
    });
    const connect = t.mock.fn(() => session);
    const manager = new Http2SessionManager({}, connect as any);
    t.after(() => manager.closeAll());
    const client = new UltraTonHTTP2({}, manager);
    const start = Date.now();

    // 150ms of the 400ms budget is left for hop 2. A hop that got the full budget again would wait until ~650ms.
    const { error, ms } = await failsAfter(
      client.get("https://slow.test/", { timeoutMs: 400, maxRedirects: 2 }),
      start,
    );

    assert.ok(error instanceof UltraTonNetworkTimeoutError);
    assert.strictEqual(error.message, "UltraTon: Absolute execution time of 400ms exceeded.");
    assert.ok(ms >= 350, `rejected before the budget could be spent (${ms}ms)`);
    assert.ok(ms < 550, `the redirect hop got more than the remaining budget (${ms}ms)`);
    assert.strictEqual(connect.mock.callCount(), 1, "only the first hop reached the connect step");
  });
});

/**
 * A caller that gives up on a lookup it opened leaves the pending map at once, so a later request
 * starts a second attempt while a joiner is still waiting on the first. Both lookups can then answer.
 */
describe("HTTP/2 concurrent connection attempts for one pool key", () => {
  it("never opens a second session for a key when a concurrent attempt already pooled one", { timeout: 5000 }, async (t) => {
    const { manager, port, connect, accepted, openSessions } = await startFixture(t);
    // Every lookup stays pending until the test answers it, so the order of the answers is the test's to choose.
    const answers: Array<() => void> = [];
    t.mock.method(dnsPromises, "lookup", (() =>
      new Promise((resolve) => {
        answers.push(() => resolve({ address: "127.0.0.1", family: 4 }));
      })) as any);
    const origin = `http://race.test:${port}`;
    const giveUp = new AbortController();

    // First attempt: the caller that opened it and a joiner with no deadline wait on one lookup.
    const opener = manager.getSession(origin, undefined, true, giveUp.signal);
    const joiner = manager.getSession(origin, undefined, true);
    giveUp.abort(new Error("budget spent"));
    await assert.rejects(opener, /budget spent/);

    // The opener left the pending map, so this request starts a second attempt beside the first.
    const newcomer = manager.getSession(origin, undefined, true);
    assert.strictEqual(answers.length, 2);

    // The second attempt answers and pools its session first; the first one's late answer must reuse it.
    answers[1]();
    const pooled = await newcomer;
    answers[0]();
    const joined = await joiner;

    assert.strictEqual(connect.mock.callCount(), 1, "the late attempt opened a second connection");
    assert.strictEqual(joined, pooled);

    // The pooled session is the only one, so closeAll() must leave nothing open on the server.
    await until(() => accepted() === connect.mock.callCount());
    manager.closeAll();
    await until(() => openSessions() === 0);
    assert.strictEqual(openSessions(), 0, "a session survived closeAll()");
  });
});
