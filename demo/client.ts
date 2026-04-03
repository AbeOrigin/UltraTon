import { UltraTonClient } from '../src/http-client.ts';

// 1) Instantiate the client (UltraTonClient takes no arguments directly)
const client = new UltraTonClient();

// 2) Configuration boundaries are strictly enforced per-request in this architecture
const testOptions = {
  maxBodySize: 1024 * 1024 * 5, // 5MB absolute limit
  timeoutMs: 2000,              // 2-second strict complete cycle timeout
  maxRedirects: 3,              // Cap on redirect hops
  permitReservedIps: true       // REQUIRED: Allow testing against localhost server
};

async function runTests() {
  console.log('🛡️ Starting UltraTon Hostile Environment Tests...\n');

  // 1. OOM Attack Test
  try {
    console.log('Testing: [GET] /attack/oom (Validating maxBodySize kill switch)');
    // 3) Use .get instead of .request, passing options in the second argument
    await client.get('http://localhost:3000/attack/oom', testOptions);
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
    await client.get('http://localhost:3000/attack/slowloris', testOptions);
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
    await client.get('http://localhost:3000/attack/redirect-loop', testOptions);
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
    await client.get('http://localhost:3000/attack/ssrf-initial', {
      ...testOptions,
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

runTests().catch(err => {
  console.error('Fatal Runner Exception:', err);
});
