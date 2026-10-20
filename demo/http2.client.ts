import { UltraTonClient } from "../src/http-client.ts";

// The h2c server from demo/http2.server.ts (run `npm run demo:http2:server` first).
// Loopback is a reserved address: the SSRF guard blocks it unless the client opts in.
const client = new UltraTonClient({
  http2: true,
  baseUrl: "http://127.0.0.1:8080",
  permitReservedIps: true,
});

async function makeGet(path: string, id: number) {
  console.log(`[CLIENT] Starting request ${id} to ${path}`);
  const response = await client.get(path);
  console.log(`[CLIENT] Request ${id} finished. Status: ${response.statusCode}`);
  return response;
}

async function main() {
  console.log("🚀 Starting multiplexing test...");

  // We create an array of promises. 
  // Note: We are NOT 'awaiting' them inside the loop, so they all start nearly simultaneously.
  const requestCount = 5;
  const requests = [];

  for (let i = 1; i <= requestCount; i++) {
    requests.push(makeGet(`/item/${i}`, i));
  }

  // Promise.all waits for all concurrent requests to complete.
  // This is where the HTTP/2 multiplexing happens over the same session.
  const results = await Promise.all(requests);

  console.log(`\n✅ All ${results.length} requests completed successfully.`);
}

main()
  .catch((err) => {
    console.error("❌ Test failed:", err);
  })
  .finally(() => client.close()); // closes the client's HTTP/2 session so the process can exit
