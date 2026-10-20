/**
 * AbortSignal and idle behaviour, on both engines, with real sockets:
 * - a caller abort rejects with `signal.reason` (a DOMException AbortError when none was given) in every phase:
 *   before connecting, while connecting and mid-body;
 * - HTTP/2 closes the stream with NGHTTP2_CANCEL, so the server sees it cancelled;
 * - `socketTimeoutMs` is a per-stream idle timeout on HTTP/2 too;
 * - an HTTP/2 session with no active stream does not keep the process alive.
 */
import { afterEach, describe, it, mock, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import dnsPromises from 'node:dns/promises';
import { spawn } from 'node:child_process';
import { constants, createServer as createH2Server, type ServerHttp2Stream } from 'node:http2';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { pathToFileURL } from 'node:url';
import { Http2SessionManager } from '../src/engines/http2-session-manager.ts';
import { UltraTonNetworkTimeoutError } from '../src/errors.ts';
import { UltraTonClient } from '../src/http-client.ts';
import { kSessionManager } from '../src/internal.ts';

type Engine = 'http1' | 'http2';
const ENGINES: Engine[] = ['http1', 'http2'];

/** A loopback server for the engine under test; `onRequest` receives the raw request side. */
interface Handlers {
  /** Called for every request; for HTTP/1 `res` is the response, for HTTP/2 the stream. */
  respond: (res: http.ServerResponse | ServerHttp2Stream) => void;
  /** HTTP/2 only: told when the client cancels a stream. */
  onCancel?: (rstCode: number) => void;
}

const startServer = async (t: TestContext, engine: Engine, handlers: Handlers) => {
  const sockets = new Set<import('node:net').Socket>();
  let url: string;
  let close: () => Promise<void>;
  if (engine === 'http1') {
    const server = http.createServer((_req, res) => handlers.respond(res));
    server.on('connection', (s) => sockets.add(s));
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
    close = () => new Promise<void>((r) => { sockets.forEach((s) => s.destroy()); server.close(() => r()); });
  } else {
    const server = createH2Server();
    server.on('connection', (s) => sockets.add(s));
    server.on('session', (session) => session.on('error', () => {}));
    server.on('stream', (stream) => {
      stream.on('error', () => {});
      stream.on('close', () => handlers.onCancel?.(stream.rstCode));
      handlers.respond(stream);
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
    close = () => new Promise<void>((r) => { sockets.forEach((s) => s.destroy()); server.close(() => r()); });
  }
  const manager = new Http2SessionManager();
  const client = new UltraTonClient({ http2: engine === 'http2', permitReservedIps: true, [kSessionManager]: manager } as any);
  t.after(async () => {
    manager.closeAll();
    await client.close();
    await close();
  });
  return { url, client };
};

/** Writes headers and a first chunk, then says nothing more. */
const respondPartially = (res: http.ServerResponse | ServerHttp2Stream) => {
  if ('respond' in res) {
    res.respond({ ':status': 200, 'content-type': 'text/plain' });
    res.write('partial');
  } else {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.write('partial');
  }
};

const abortIn = (ms: number, reason?: unknown) => {
  const controller = new AbortController();
  setTimeout(() => (reason === undefined ? controller.abort() : controller.abort(reason)), ms);
  return controller.signal;
};

describe('AbortSignal rejects with the signal reason on both engines', () => {
  afterEach(() => mock.restoreAll());

  for (const engine of ENGINES) {
    describe(engine, () => {
      it('a pre-aborted signal rejects with the reason and never connects', { timeout: 5000 }, async (t) => {
        let reached = 0;
        const { url, client } = await startServer(t, engine, { respond: () => { reached++; } });
        const reason = new Error('stop before connecting');
        const controller = new AbortController();
        controller.abort(reason);

        await assert.rejects(client.get(url, { signal: controller.signal }), (err: unknown) => err === reason);

        const noReason = new AbortController();
        noReason.abort();
        await assert.rejects(client.get(url, { signal: noReason.signal }), (err: unknown) => {
          assert.ok(err instanceof DOMException);
          assert.equal(err.name, 'AbortError');
          return true;
        });
        await new Promise((r) => setTimeout(r, 50));
        assert.equal(reached, 0, 'the server saw no request');
      });

      it('aborting while connecting (DNS never answers) rejects with the reason', { timeout: 5000 }, async (t) => {
        t.mock.method(dnsPromises, 'lookup', () => new Promise(() => { /* never answers */ }));
        const client = new UltraTonClient({ http2: engine === 'http2' });
        const reason = new Error('gave up on DNS');
        const started = Date.now();
        await assert.rejects(client.get('https://example.test/', { signal: abortIn(80, reason), timeoutMs: 0 }), (err: unknown) => err === reason);
        assert.ok(Date.now() - started < 1000);
        // Without a reason it is the DOMException AbortError.
        await assert.rejects(client.get('https://example.test/', { signal: abortIn(50), timeoutMs: 0 }), (err: unknown) => {
          assert.ok(err instanceof DOMException);
          assert.equal(err.name, 'AbortError');
          return true;
        });
        await client.close();
      });

      it('aborting during a slow response (no headers yet) rejects fast with the reason', { timeout: 5000 }, async (t) => {
        let cancelCode: number | undefined;
        const { url, client } = await startServer(t, engine, {
          respond: () => { /* never answers */ },
          onCancel: (code) => { cancelCode = code; },
        });
        const reason = new Error('too slow');
        const started = Date.now();
        await assert.rejects(client.get(url, { signal: abortIn(100, reason) }), (err: unknown) => err === reason);
        assert.ok(Date.now() - started < 300, `rejected in ${Date.now() - started}ms`);
        if (engine === 'http2') {
          await new Promise((r) => setTimeout(r, 100));
          assert.equal(cancelCode, constants.NGHTTP2_CANCEL, 'the server saw the stream cancelled');
        }
      });

      it('aborting mid-body rejects with the reason, not a network error', { timeout: 5000 }, async (t) => {
        const { url, client } = await startServer(t, engine, { respond: respondPartially });
        const reason = new Error('mid-body stop');
        await assert.rejects(client.get(url, { signal: abortIn(150, reason) }), (err: unknown) => err === reason);

        await assert.rejects(client.get(url, { signal: abortIn(150) }), (err: unknown) => {
          assert.ok(err instanceof DOMException);
          assert.equal(err.name, 'AbortError');
          return true;
        });
      });

      it('an abort after the response settled changes nothing', { timeout: 5000 }, async (t) => {
        const { url, client } = await startServer(t, engine, {
          respond: (res) => ('respond' in res ? (res.respond({ ':status': 200 }), res.end('ok')) : res.end('ok')),
        });
        const controller = new AbortController();
        const response = await client.get(url, { signal: controller.signal });
        controller.abort();
        assert.equal(response.text(), 'ok');
      });
    });
  }
});

describe('HTTP/2 abort', () => {
  it('a pre-aborted signal on HTTP/2 does not even call connect', { timeout: 5000 }, async () => {
    const connect = mock.fn(() => { throw new Error('connect must not be reached'); });
    const client = new UltraTonClient({ http2: true, [kSessionManager]: new Http2SessionManager({}, connect as any) } as any);
    const reason = new Error('nope');
    await assert.rejects(
      client.get('http://127.0.0.1:1/', { permitReservedIps: true, signal: AbortSignal.abort(reason) }),
      (err: unknown) => err === reason,
    );
    assert.equal(connect.mock.callCount(), 0);
  });
});

describe('HTTP/2 socketTimeoutMs is a per-stream idle timeout', () => {
  /** An h2c server whose stream handler is supplied by the test. */
  const serveH2 = async (t: TestContext, onStream: (stream: ServerHttp2Stream) => void) => {
    const server = createH2Server();
    server.on('session', (session) => session.on('error', () => {}));
    server.on('stream', (stream) => { stream.on('error', () => {}); onStream(stream); });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const manager = new Http2SessionManager();
    const client = new UltraTonClient({ http2: true, permitReservedIps: true, [kSessionManager]: manager } as any);
    t.after(async () => {
      manager.closeAll();
      server.closeAllConnections?.();
      await new Promise<void>((r) => server.close(() => r()));
    });
    return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/`, client };
  };

  it('headers followed by silence rejects with UltraTonNetworkTimeoutError', { timeout: 5000 }, async (t) => {
    let cancelCode: number | undefined;
    const { url, client } = await serveH2(t, (stream) => {
      stream.on('close', () => { cancelCode = stream.rstCode; });
      stream.respond({ ':status': 200 });
      stream.write('first');
    });
    const started = Date.now();
    await assert.rejects(client.get(url, { socketTimeoutMs: 200, timeoutMs: 0 }), (err: unknown) => {
      assert.ok(err instanceof UltraTonNetworkTimeoutError);
      assert.match(err.message, /idle for 200ms/);
      return true;
    });
    assert.ok(Date.now() - started < 1500);
    await new Promise((r) => setTimeout(r, 100));
    assert.equal(cancelCode, constants.NGHTTP2_CANCEL, 'the stream was closed with CANCEL');
  });

  it('a server that never answers also times out', { timeout: 5000 }, async (t) => {
    const { url, client } = await serveH2(t, () => { /* silence */ });
    await assert.rejects(client.get(url, { socketTimeoutMs: 150, timeoutMs: 0 }), UltraTonNetworkTimeoutError);
  });

  it('bytes keep resetting the timer: a slow but live body completes', { timeout: 5000 }, async (t) => {
    const { url, client } = await serveH2(t, (stream) => {
      stream.respond({ ':status': 200 });
      let sent = 0;
      const tick = setInterval(() => {
        stream.write('x');
        if (++sent === 6) { clearInterval(tick); stream.end(); }
      }, 100);
      stream.on('close', () => clearInterval(tick));
    });
    const response = await client.get(url, { socketTimeoutMs: 250, timeoutMs: 0 });
    assert.equal(response.text(), 'xxxxxx');
  });

  it('0 disables it', { timeout: 5000 }, async (t) => {
    const { url, client } = await serveH2(t, (stream) => {
      setTimeout(() => { stream.respond({ ':status': 200 }); stream.end('late'); }, 400);
    });
    const response = await client.get(url, { socketTimeoutMs: 0, timeoutMs: 0 });
    assert.equal(response.text(), 'late');
  });
});

describe('HTTP/2 sessions do not keep the process alive while idle', () => {
  /**
   * Runs `script` in a child node. `afterOutputMs` is how long the child took to exit once it had printed its result:
   * the idle wait is what is measured, so a busy machine's slow node startup cannot fail the test.
   */
  const runChild = (script: string) =>
    new Promise<{ stdout: string; afterOutputMs: number; code: number | null }>((resolve, reject) => {
      const child = spawn(process.execPath, ['--input-type=module', '-e', script], { stdio: ['ignore', 'pipe', 'inherit'] });
      let stdout = '';
      let printedAt = 0;
      const killer = setTimeout(() => { child.kill(); reject(new Error(`child still running after 20s; stdout: ${stdout}`)); }, 20_000);
      child.stdout.on('data', (chunk: Buffer) => {
        if (!printedAt) printedAt = Date.now();
        stdout += chunk;
      });
      child.on('error', (err) => { clearTimeout(killer); reject(err); });
      child.on('close', (code) => {
        clearTimeout(killer);
        resolve({ stdout, afterOutputMs: Date.now() - printedAt, code });
      });
    });

  const indexUrl = pathToFileURL(new URL('../src/index.ts', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')).href;
  const scriptFor = (url: string, options: string) => `
    import { UltraTonClient } from ${JSON.stringify(indexUrl)};
    const client = new UltraTonClient({ http2: true, permitReservedIps: true });
    const response = await client.get(${JSON.stringify(url)}, ${options});
    console.log('status=' + response.statusCode + ' body=' + response.text());
  `;

  const serve = async (t: TestContext, delayMs: number) => {
    const server = createH2Server();
    server.on('session', (session) => session.on('error', () => {}));
    server.on('stream', (stream) => {
      stream.on('error', () => {});
      setTimeout(() => { stream.respond({ ':status': 200 }); stream.end('done'); }, delayMs);
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    t.after(async () => {
      server.closeAllConnections?.();
      await new Promise<void>((r) => server.close(() => r()));
    });
    return `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
  };

  it('a script that makes one request and never calls close() exits promptly', { timeout: 30_000 }, async (t) => {
    const url = await serve(t, 0);
    const { stdout, afterOutputMs, code } = await runChild(scriptFor(url, '{}'));
    assert.match(stdout, /status=200 body=done/);
    assert.equal(code, 0);
    assert.ok(afterOutputMs < 2000, `child took ${afterOutputMs}ms to exit after its request finished`);
  });

  it('a request with timeoutMs: 0 still holds the process until it completes', { timeout: 30_000 }, async (t) => {
    const url = await serve(t, 800);
    const { stdout } = await runChild(scriptFor(url, '{ timeoutMs: 0 }'));
    assert.match(stdout, /status=200 body=done/, 'the child waited for the late response');
  });
});
