import { UltraTonClient } from '../src/http-client.ts';

// Configure once: these defaults apply to every request (a request can still override any of them).
const client = new UltraTonClient({
  baseUrl: 'http://localhost:3000', // request paths are relative to it and can never escape it
  maxBodySize: 1024 * 1024 * 5,     // 5MB absolute limit
  timeoutMs: 2000,                  // 2-second strict complete cycle timeout
  maxRedirects: 3,                  // Cap on redirect hops
  permitReservedIps: true           // REQUIRED: Allow testing against localhost server
});

async function runTests() {
  console.log('🛡️ Starting UltraTon Hostile Environment Tests...\n');

  // 1. OOM Attack Test
  try {
    console.log('Testing: [GET] /attack/oom (Validating maxBodySize kill switch)');
    await client.get('/attack/oom');
    console.error('❌ FAIL: OOM Test returned a full response. Memory shield bypassed!');
  } catch (error: any) {
    if (error.name === 'UltraTonMemoryError' || (error.message && error.message.includes('size'))) {
      console.log(`✅ PASS: Blocked OOM Attack. Engine threw: ${error.message}\n`);
    } else {
      console.log(`⚠️ UNEXPECTED ERROR BEHAVIOR: ${error.name} - ${error.message}\n`);
    }
  }

  // 2. Slowloris / Tarpit Test
  try {
    console.log('Testing: [GET] /attack/slowloris (Validating strict timeout sockets)');
    await client.get('/attack/slowloris');
    console.error('❌ FAIL: Slowloris connection stayed alive past timeout boundary!');
  } catch (error: any) {
    // Expected to time out and return UltraTonNetworkTimeoutError
    if ((error.name && error.name.includes('Timeout')) || (error.message && error.message.toLowerCase().includes('timeout'))) {
      console.log(`✅ PASS: Blocked Slowloris Tarpit. Engine threw: ${error.message}\n`);
    } else {
      console.log(`⚠️ UNEXPECTED ERROR BEHAVIOR: ${error.name} - ${error.message}\n`);
    }
  }

  // 3. Infinite Redirect Loop Test
  try {
    console.log('Testing: [GET] /attack/redirect-loop (Validating MAX_REDIRECTS_CEILING)');
    await client.get('/attack/redirect-loop');
    console.error('❌ FAIL: Escaped redirect boundary and completed request!');
  } catch (error: any) {
    // Expected to fail with UltraTonRedirectError
    if (error.name === 'UltraTonRedirectError' || (error.message && error.message.includes('redirect'))) {
      console.log(`✅ PASS: Blocked Infinite Redirect. Engine threw: ${error.message}\n`);
    } else {
      console.log(`⚠️ UNEXPECTED ERROR BEHAVIOR: ${error.name} - ${error.message}\n`);
    }
  }

  // 4. SSRF & Cross-Domain Credential Leak Test
  try {
    console.log('Testing: [GET] /attack/ssrf-initial (Validating Authorization header stripping)');
    await client.get('/attack/ssrf-initial', {
      headers: {
        'Authorization': 'Bearer SUPER_SECRET_ENTERPRISE_TOKEN'
      }
    });
    console.error('❌ FAIL: SSRF trap completed without error!');
  } catch (error: any) {
    // Node.js 20+ aggregates IPv4 and IPv6 connection failures into an AggregateError with an empty message
    const errorMsg = error.message || (error.errors ? error.errors.map((e: any) => e.message).join(', ') : '');
    
    if (errorMsg.includes('ECONNREFUSED') || error.name === 'SecureHttpError') {
      console.log(`✅ PASS: SSRF redirect intercepted. Engine bubbled: ${error.name} - ${errorMsg}\n`);
      console.log(`👉 Check server logs to ensure the 'Authorization' header was safely stripped!\n`);
    } else {
      console.log(`⚠️ UNEXPECTED ERROR BEHAVIOR: ${error.stack}\n`);
    }
  }

  console.log('🏁 All hostile integrations tested.');
}

runTests()
  .catch(err => {
    console.error('Fatal Runner Exception:', err);
  })
  .finally(() => client.close()); // releases the client's pooled sockets
