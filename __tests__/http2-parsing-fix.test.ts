import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert';
import { createServer } from 'node:http2';
import type { AddressInfo } from 'node:net';
import { Http2SessionManager } from '../src/classes/http-session-mannager.ts';
import { UltraTonParseError } from '../src/errors.ts';
import { UltraTonHTTP2 } from '../src/http2-client.ts';

/**
 * Real h2c server on 127.0.0.1 that answers every request with `application/json`
 * and the given raw body. An IP literal never reaches a resolver, so no DNS mock is needed.
 */
const serveJson = async (t: TestContext, body: string) => {
  const server = createServer();
  server.on('stream', (stream) => {
    stream.resume();
    stream.respond({ ':status': 200, 'content-type': 'application/json' });
    stream.end(body);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;

  const manager = new Http2SessionManager();
  t.after(async () => {
    manager.closeAll();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  return {
    client: new UltraTonHTTP2({}, manager),
    url: `http://127.0.0.1:${port}/`,
  };
};

describe('UltraTonHTTP2 - JSON Parsing Fix Validation', () => {
  it('resolves a malformed application/json body and json() throws UltraTonParseError instead of crashing', { timeout: 5000 }, async (t) => {
    const { client, url } = await serveJson(t, '{not json');

    const uncaught: unknown[] = [];
    const onUncaught = (err: unknown) => { uncaught.push(err); };
    process.on('uncaughtException', onUncaught);
    try {
      const res = await client.get(url, { permitReservedIps: true });
      assert.strictEqual(res.statusCode, 200);
      assert.throws(() => res.json(), UltraTonParseError);
      // A throw from a stream listener surfaces as an uncaught exception on a later tick.
      await new Promise<void>((resolve) => setImmediate(resolve));
      assert.deepStrictEqual(uncaught, []);
    } finally {
      process.removeListener('uncaughtException', onUncaught);
    }
  });

  it('json() parses a valid application/json body and strips __proto__', { timeout: 5000 }, async (t) => {
    const { client, url } = await serveJson(t, '{"a":1,"__proto__":{"polluted":true}}');

    const res = await client.get(url, { permitReservedIps: true });

    assert.deepStrictEqual(res.json(), { a: 1 });
    assert.strictEqual(({} as { polluted?: boolean }).polluted, undefined);
  });
});
