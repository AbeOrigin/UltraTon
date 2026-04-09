import { describe, it } from "node:test";
import assert from "node:assert";
import { EventEmitter } from "node:events";
import { UltraTonClient } from "../src/http-client.ts";
import { UltraTonParseError } from "../src/exceptions/parse.error.ts";

describe("UltraTonClient - JSON Parsing Fix Validation", () => {
  // Helper to generate a fake https.request implementation
  const createMockTransport = (
    mockResponseData: any,
    expectedMethod: string,
    statusCode = 200,
    contentType = "application/json",
  ) => {
    return (urlObj: any, options: any, callback?: any) => {
      const req = new EventEmitter();
      const reqBody: Buffer[] = [];

      (req as any).write = (chunk: any) => {
        reqBody.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      };

      (req as any).destroy = () => {};

      (req as any).end = () => {
        const res = new EventEmitter();
        (res as any).statusCode = statusCode;
        (res as any).headers = {
          "x-method-used": options.method,
          "content-type": contentType,
        };

        if (callback) callback(res);
        req.emit("response", res);

        setImmediate(() => {
          let dataBuffer: Buffer;
          if (Buffer.isBuffer(mockResponseData)) {
            dataBuffer = mockResponseData;
          } else if (typeof mockResponseData === "string") {
            dataBuffer = Buffer.from(mockResponseData);
          } else {
            dataBuffer = Buffer.from(JSON.stringify(mockResponseData));
          }

          if (dataBuffer.length > 0) res.emit("data", dataBuffer);
          res.emit("end");
        });
      };
      return req as any;
    };
  };

  it("Should correctly handle JSON parsing when body is already parsed", async () => {
    const fakeTransport = createMockTransport(
      { user: "abe", role: "architect" },
      "GET",
    );
    const client = new UltraTonClient(fakeTransport as any);

    interface UserShape {
      user: string;
      role: string;
    }

    const res = await client.get<UserShape>("https://example.com/json");

    // Assert native response shape is unharmed
    assert.strictEqual(res.statusCode, 200);
    assert.ok(!Buffer.isBuffer(res.body)); // Auto parsing kicked in

    // Test that json() method works correctly
    const parsedData = res.json();
    assert.strictEqual(parsedData.user, "abe");
    assert.strictEqual(parsedData.role, "architect");
  });

  it("Should correctly handle JSON parsing when body is raw buffer", async () => {
    const fakeTransport = createMockTransport(
      { message: "hello world" },
      "GET",
    );
    const client = new UltraTonClient(fakeTransport as any);

    interface MessageShape {
      message: string;
    }

    const res = await client.get<MessageShape>("https://example.com/json");

    // Verify that we can get the parsed data via json() method
    const parsedData = res.json();
    assert.strictEqual(parsedData.message, "hello world");
  });

  it("Should correctly handle non-JSON content types", async () => {
    const fakeTransport = createMockTransport(
      "plain text response",
      "GET",
      200,
      "text/plain",
    );
    const client = new UltraTonClient(fakeTransport as any);

    const res = await client.get<string>("https://example.com/text");

    // For non-JSON content, body should be a Buffer
    assert.ok(Buffer.isBuffer(res.body));
    assert.strictEqual(res.body.toString(), "plain text response");

    // For text content, json() should throw a JSON parsing error
    assert.throws(
      () => {
        res.json();
      },
      (err: any) => {
        return (
          err instanceof UltraTonParseError &&
          err.message.includes("Failed to parse JSON")
        );
      },
    );
  });

  it("Should handle empty responses gracefully", async () => {
    const fakeTransport = createMockTransport(
      "",
      "GET",
      204,
      "application/json",
    );
    const client = new UltraTonClient(fakeTransport as any);

    interface EmptyResponse {
      // Empty interface for testing
    }

    const res = await client.get<EmptyResponse>("https://example.com/empty");

    // Verify body is parsed correctly
    const parsedData = res.json();
    // Empty JSON should return an empty object {}
    assert.deepStrictEqual(parsedData, {});
  });

  it("Should correctly handle mixed content scenarios", async () => {
    const fakeTransport = createMockTransport({ data: [1, 2, 3] }, "GET");
    const client = new UltraTonClient(fakeTransport as any);

    interface DataShape {
      data: number[];
    }

    const res = await client.get<DataShape>("https://example.com/data");

    // Test that both direct body access and json() work consistently
    assert.ok(!Buffer.isBuffer(res.body)); // Should be parsed
    const parsedViaJson = res.json();
    assert.deepStrictEqual(parsedViaJson.data, [1, 2, 3]);
  });

  it("Should protect against prototype injection in json() method", async () => {
    // Simulate a response with malicious JSON
    const maliciousJson = '{"user": "admin", "__proto__": {"polluted": true}}';
    const fakeTransport = createMockTransport(
      maliciousJson,
      "GET",
      200,
      "text/plain",
    ); // Use text/plain to force raw Buffer body
    const client = new UltraTonClient(fakeTransport as any);

    const res = await client.get<any>("https://example.com/malicious");

    // Verify body is a Buffer
    assert.ok(Buffer.isBuffer(res.body));

    // Parse via json()
    const parsed = res.json();

    // Verify the malicious key was stripped
    assert.strictEqual(parsed.user, "admin");
    // Depending on the Node version, __proto__ might be a null-prototype object or undefined,
    // but the key should definitely not have the "polluted" value.
    assert.notStrictEqual(parsed.__proto__, { polluted: true });
    assert.strictEqual((Object.prototype as any).polluted, undefined);
  });
});
