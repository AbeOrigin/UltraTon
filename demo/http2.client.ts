import { UltraTonHTTP2 } from "../src/http2-client.ts";

const client = new UltraTonHTTP2({
  permitReservedIps: true,
});
const url = "http://127.0.0.1:8080";

async function makeGet(url: string, id: number) {
  console.log(`[CLIENT] Starting request ${id} to ${url}`);
  const response = await client.get(url, { permitReservedIps: true });
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
    requests.push(makeGet(url, i));
  }

  // Promise.all waits for all concurrent requests to complete.
  // This is where the HTTP/2 multiplexing happens over the same session.
  const results = await Promise.all(requests);

  console.log(`\n✅ All ${results.length} requests completed successfully.`);
}

main().catch((err) => {
  console.error("❌ Test failed:", err);
});
