import http2 from "node:http2";

// We use createServer (not createSecureServer) for h2c (no certs)
const server = http2.createServer();

server.on("session", (session) => {
  console.log(`\n[SESSION] New connection: ${JSON.stringify(session)}`);

  session.on("settings", (settings) => {
    console.log("[SETTINGS] Client sent settings:", settings);
  });

  session.on("close", () => {
    console.log("[SESSION] Connection closed.");
  });
});

server.on("stream", (stream, headers) => {
  const streamId = stream.id;
  const method = headers[":method"];
  const path = headers[":path"];

  console.log("\n-----------------------------------------------------");
  console.log(`[STREAM ${streamId}] Request: ${method} ${path}`);
  console.log("[HEADERS]", JSON.stringify(headers, null, 2));

  let body = "";

  // Listen for incoming data chunks (DATA frames)
  stream.on("data", (chunk) => {
    const chunkStr = chunk.toString();
    console.log(`[STREAM ${streamId}] Received Data: ${chunkStr}`);
    body += chunkStr;
  });

  stream.on("end", () => {
    console.log(`[STREAM ${streamId}] Stream ended. Full Body: "${body}"`);

    // Prepare the response
    // In Node.js http2, stream.respond takes the headers object directly.
    // Pseudo-headers like :status must be included in this object.
    stream.respond({
      ":status": 200,
      "content-type": "text/plain",
      "x-server-type": "h2c-cleartext",
    });

    stream.end(`Success! You sent: ${body}`);
  });

  stream.on("error", (err) => {
    console.error(`[STREAM ${streamId}] Error:`, err.message);
  });
});

server.listen(8080, () => {
  console.log(
    "🚀 HTTP/2 (h2c) Cleartext Server running at http://localhost:8080",
  );
  console.log("No TLS/Certs required. Use http:// (not https)");
});
