import * as http from 'node:http';

const PORT = 3000;

// Allocate once and reuse to prevent server-side GC thrashing and OOM.
const OOM_CHUNK = Buffer.alloc(1024 * 1024, 'A'); 

const server = http.createServer((req, res) => {
  console.log(`\n[HostileServer] Connection received: ${req.method} ${req.url}`);

  if (req.url === '/attack/oom') {
    // 1. Out-Of-Memory Trap: Lie about Content-Length and blast infinite chunks
    res.writeHead(200, {
        'Content-Type': 'application/octet-stream',
        'Content-Length': '1000000000'
    });

    const blast = () => {
        if (res.writableEnded || res.destroyed) return;
        
        // Write the chunk. If the internal buffer is full, pause and wait to prevent self-OOM.
        const canContinue = res.write(OOM_CHUNK);
        if (canContinue) {
            setImmediate(blast);
        } else {
            res.once('drain', blast);
        }
    };
    blast();

    req.socket.on('close', () => {
        console.log('[HostileServer] /attack/oom -> Socket forcefully destroyed by client (Expected).');
    });
    return;
  }

  if (req.url === '/attack/slowloris') {
    // 2. Slowloris Trap: Send 1 byte every 10 seconds
    res.writeHead(200, {
        'Content-Type': 'text/plain',
        'Content-Length': '100'
    });

    const interval = setInterval(() => {
        if (!res.destroyed) {
            res.write('X');
        }
    }, 10000);

    req.socket.on('close', () => {
        console.log('[HostileServer] /attack/slowloris -> Socket destroyed by client (Expected).');
        clearInterval(interval); // Prevent server-side memory leak
    });
    return;
  }

  if (req.url === '/attack/redirect-loop') {
    // 3. Infinite Redirect Trap: Point back to itself
    res.writeHead(302, {
        'Location': '/attack/redirect-loop'
    });
    res.end();
    return;
  }

  if (req.url === '/attack/ssrf-initial') {
    // Acts as the trusted 1st-party server. Redirects to a DIFFERENT origin (127.0.0.1) to trigger credential stripping!
    res.writeHead(302, {
        'Location': 'http://127.0.0.1:3000/attack/ssrf-trap'
    });
    res.end();
    return;
  }

  if (req.url === '/attack/ssrf-trap') {
    // 4. SSRF & Credential Trap: Log sensitive headers and redirect to a dead port
    if (req.headers['authorization']) {
        console.error(`[HostileServer] 🚨 VULNERABILITY! /attack/ssrf-trap received credentials: ${req.headers['authorization']}`);
    } else {
        console.log(`[HostileServer] /attack/ssrf-trap -> Credentials safely stripped (Expected).`);
    }

    res.writeHead(302, {
        'Location': 'http://localhost:9999/dead-end'
    });
    res.end();
    return;
  }

  res.writeHead(404);
  res.end('Not Found\n');
});

server.listen(PORT, () => {
  console.log(`[HostileServer] 💀 Listening on http://localhost:${PORT}`);
});
