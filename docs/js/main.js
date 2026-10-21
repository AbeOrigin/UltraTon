// Utility for copy button
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        const btn = document.querySelector('.copy-btn');
        const originalHTML = btn.innerHTML;
        
        // Show checkmark
        btn.innerHTML = `<svg viewBox="0 0 24 24" width="16" height="16" stroke="#00ffa8" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>`;
        
        setTimeout(() => {
            btn.innerHTML = originalHTML;
        }, 2000);
    }).catch(err => {
        console.error('Failed to copy text: ', err);
    });
}

// Simple particle background simulation
document.addEventListener('DOMContentLoaded', () => {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    const container = document.getElementById('particles');
    
    container.appendChild(canvas);
    
    let width, height;
    let particles = [];
    
    function resize() {
        width = window.innerWidth;
        height = window.innerHeight;
        canvas.width = width;
        canvas.height = height;
    }
    
    window.addEventListener('resize', resize);
    resize();
    
    class Particle {
        constructor() {
            this.x = Math.random() * width;
            this.y = Math.random() * height;
            this.vx = (Math.random() - 0.5) * 0.5;
            this.vy = (Math.random() - 0.5) * 0.5;
            this.size = Math.random() * 2;
            this.alpha = Math.random() * 0.5 + 0.1;
        }
        
        update() {
            this.x += this.vx;
            this.y += this.vy;
            
            if (this.x < 0) this.x = width;
            if (this.x > width) this.x = 0;
            if (this.y < 0) this.y = height;
            if (this.y > height) this.y = 0;
        }
        
        draw() {
            ctx.fillStyle = `rgba(0, 255, 168, ${this.alpha})`;
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
            ctx.fill();
        }
    }
    
    // Create particles
    const particleCount = Math.min(window.innerWidth / 10, 100);
    for (let i = 0; i < particleCount; i++) {
        particles.push(new Particle());
    }
    
    function animate() {
        ctx.clearRect(0, 0, width, height);
        
        particles.forEach(p => {
            p.update();
            p.draw();
        });
        
        requestAnimationFrame(animate);
    }
    
    animate();
});

// Smooth scrolling for anchor links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});

// Request/response simulator. Replays what UltraTon checks on a few attacks; the error classes, codes and messages
// are the library's own. Plays on its own while visible, until a scenario is picked.
(() => {
    const root = document.getElementById('in-action');
    if (!root) return;

    const OUT = ['Options & headers', 'URL & baseUrl', 'IP literal', 'DNS answer, pinned', 'TLS certificate'];
    const IN = ['Redirect policy', 'Body ≤ maxBodySize', 'timeoutMs / socketTimeoutMs', 'Length = content-length', 'json() sanitized'];

    const SCENARIOS = [
        {
            label: 'Normal request',
            call: "await api.get('users/7')",
            server: 'api.example.com → 200, {"id":7,"name":"Ada"}',
            result: { title: '200 OK', detail: "res.json() → { id: 7, name: 'Ada' }", note: 'Every check passed, on the way out and on the way back.' },
        },
        {
            label: 'Cloud metadata',
            call: "await client.get('https://169.254.169.254/latest/meta-data/')",
            fail: ['out', 2],
            result: {
                title: 'SecureHttpError · ERR_ULTRATON_RESERVED_IP',
                detail: 'UltraTon: Target resolves to a prohibited internal/reserved network IP.',
                note: 'Link-local cloud metadata. Refused in every spelling (0xA9FEA9FE, [::ffff:169.254.169.254], …) before a socket opens.',
            },
        },
        {
            label: 'DNS rebinding',
            call: "await client.get('https://rebind.attacker.example/')",
            dns: 'DNS → 93.184.216.34, 10.0.0.5',
            fail: ['out', 3],
            result: {
                title: 'SecureHttpError · ERR_ULTRATON_RESERVED_IP',
                detail: 'UltraTon: Target resolves to a prohibited internal/reserved network IP.',
                note: 'Every address in the answer is checked, and one private address fails the whole request. The socket is pinned to validated addresses, so a second lookup cannot swap them.',
            },
        },
        {
            label: 'Header injection',
            call: "await client.get(url, { headers: { 'x-id': '7\\r\\nHost: internal' } })",
            fail: ['out', 0],
            result: {
                title: 'TypeError',
                detail: "UltraTon: Header value for 'x-id' contains invalid CRLF characters.",
                note: 'CRLF and NUL in headers are rejected before connecting, so a request can never be split or smuggled.',
            },
        },
        {
            label: 'Path traversal',
            call: "await api.get('..%2fadmin')",
            fail: ['out', 1],
            result: {
                title: 'TypeError',
                detail: 'UltraTon: Request path escapes baseUrl.',
                note: 'The path is decoded the way lenient servers read it (%2f, %252e, ..;/, fullwidth dots), and it can never leave baseUrl.',
            },
        },
        {
            label: 'https → http redirect',
            call: "await client.get('https://shop.example/pay', { maxRedirects: 3 })",
            server: 'server → 302 Location: http://shop.example/pay',
            fail: ['in', 0],
            result: {
                title: 'SecureHttpError · ERR_ULTRATON_DOWNGRADE',
                detail: 'UltraTon: Redirect from https to http is not allowed.',
                note: 'A downgrade is never followed. On a cross-origin hop, authorization, cookie and auth are dropped.',
            },
        },
        {
            label: 'Memory bomb',
            call: "await client.get('https://files.example/report.json')",
            server: 'server → 200, 5 GB body',
            fail: ['in', 1],
            result: {
                title: 'UltraTonMemoryError',
                detail: 'UltraTon: Body size exceeded the maximum allowed size of 2097152 bytes',
                note: 'Reading stops at 2 MB and the response is aborted; nothing more is buffered.',
            },
        },
        {
            label: 'Slowloris',
            call: "await client.get('https://slow.example/feed')",
            server: 'server → 200, one byte every 9 s…',
            fail: ['in', 2],
            result: {
                title: 'UltraTonNetworkTimeoutError',
                detail: 'UltraTon: Absolute execution time of 30000ms exceeded.',
                note: 'Dripping bytes keeps a connection from going idle, but not past the absolute timeoutMs budget, which includes DNS and every hop.',
            },
        },
        {
            label: 'Through a proxy',
            call: "new UltraTonClient({ proxy: 'http://egress.corp:3128' }).get('https://api.example.com/')",
            dns: 'DNS → 93.184.216.34 · CONNECT 93.184.216.34:443 (the IP, never the name)',
            server: 'proxy → 200 Connection established · api.example.com → 200',
            result: {
                title: '200 OK',
                detail: 'Tunnelled through the proxy, certificate checked for api.example.com',
                note: 'The proxy gets the IP UltraTon validated, so it cannot resolve the name to an internal address. SOCKS5 proxies work the same way.',
            },
        },
        {
            label: 'Flaky upstream',
            call: "await api.get('reports', { retry: 2 })",
            server: 'server → 503 Retry-After: 1 · after 1 s → 200',
            result: {
                title: '200 OK',
                detail: 'Second attempt succeeded, after the 1 s the server asked for',
                note: 'Opt-in, idempotent methods only, and all attempts share one timeoutMs budget. Each attempt is a full request, with DNS validated again.',
            },
        },
        {
            label: 'Prototype pollution',
            call: "await client.get('https://api.example/profile')",
            server: 'server → 200, {"__proto__":{"isAdmin":true}}',
            result: {
                title: '200 OK',
                detail: 'res.json() → {}',
                note: '__proto__, constructor and prototype keys are stripped at every depth, so isAdmin never reaches your objects.',
            },
        },
    ];

    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const TRAVEL = 700, CHECK = 380, HOLD = 4200;
    const STOP = Symbol('stop');

    const $ = id => document.getElementById(id);
    const tabs = $('sim-tabs'), call = $('sim-call'), track = $('sim-track'), packet = $('sim-packet');
    const wire = $('sim-wire'), result = $('sim-result'), shield = track.querySelector('[data-node="shield"]');
    const node = name => track.querySelector(`[data-node="${name}"]`);

    const list = (id, labels) => labels.map(label => {
        const li = document.createElement('li');
        li.className = 'sim-check';
        li.textContent = label;
        $(id).appendChild(li);
        return li;
    });
    const checks = { out: list('sim-out', OUT), in: list('sim-in', IN) };

    const buttons = SCENARIOS.map((s, i) => {
        const b = document.createElement('button');
        b.type = 'button';
        b.className = 'sim-tab';
        b.textContent = s.label;
        b.addEventListener('click', () => { auto = false; play(i); });
        tabs.appendChild(b);
        return b;
    });

    let run = 0, current = 0, auto = !reduce, visible = false, looping = false;

    const sleep = (ms, id) => new Promise((resolve, reject) =>
        setTimeout(() => (id === run ? resolve() : reject(STOP)), reduce ? 0 : ms));

    function moveTo(name, id) {
        const box = node(name).getBoundingClientRect(), base = track.getBoundingClientRect();
        const to = `translateX(${box.left - base.left + box.width / 2 - packet.offsetWidth / 2}px)`;
        if (reduce) { packet.style.transform = to; return Promise.resolve(); }
        const anim = packet.animate([{ transform: packet.style.transform || 'translateX(0)' }, { transform: to }],
            { duration: TRAVEL, easing: 'ease-in-out', fill: 'forwards' });
        return anim.finished.then(() => {
            packet.style.transform = to;
            anim.cancel();
            if (id !== run) throw STOP;
        });
    }

    function show(s, blocked) {
        result.className = `sim-result ${blocked ? 'is-blocked' : 'is-ok'}`;
        result.replaceChildren(...[['title', (blocked ? '✕ ' : '✓ ') + s.result.title], ['detail', s.result.detail], ['note', s.result.note]]
            .map(([part, text]) => { const p = document.createElement('p'); p.className = `sim-result-${part}`; p.textContent = text; return p; }));
    }

    // Runs one direction's checks; returns false when the scenario fails at one of them.
    async function inspect(s, dir, id) {
        shield.classList.add('is-checking');
        const failAt = s.fail && s.fail[0] === dir ? s.fail[1] : -1;
        for (const [i, li] of checks[dir].entries()) {
            li.className = 'sim-check is-checking';
            if (dir === 'out' && i === 3 && s.dns) wire.textContent = s.dns;
            await sleep(CHECK, id);
            if (i === failAt) {
                li.className = 'sim-check is-fail';
                checks[dir].slice(i + 1).forEach(next => { next.className = 'sim-check is-skip'; });
                if (dir === 'out') checks.in.forEach(next => { next.className = 'sim-check is-skip'; });
                shield.classList.replace('is-checking', 'is-blocked');
                packet.classList.add('is-blocked');
                return false;
            }
            li.className = 'sim-check is-pass';
        }
        shield.classList.remove('is-checking');
        return true;
    }

    async function steps(s, id) {
        packet.classList.add('is-visible');
        await moveTo('shield', id);
        if (!(await inspect(s, 'out', id))) return show(s, true);
        await moveTo('net', id);
        wire.textContent = s.server;
        packet.classList.add('is-response');
        await sleep(CHECK, id);
        await moveTo('shield', id);
        if (!(await inspect(s, 'in', id))) return show(s, true);
        await moveTo('app', id);
        show(s, false);
    }

    function reset(i) {
        buttons.forEach((b, j) => b.setAttribute('aria-pressed', String(i === j)));
        call.textContent = SCENARIOS[i].call;
        wire.textContent = '';
        result.className = 'sim-result';
        result.replaceChildren();
        shield.classList.remove('is-checking', 'is-blocked');
        [...checks.out, ...checks.in].forEach(li => { li.className = 'sim-check'; });
        packet.getAnimations().forEach(a => a.cancel());
        packet.className = 'sim-packet';
        packet.style.transform = 'translateX(0)';
    }

    // Resolves to the run id when the scenario finished, or null when another one replaced it.
    async function play(i) {
        const id = ++run;
        current = i;
        reset(i);
        try {
            await steps(SCENARIOS[i], id);
            return id;
        } catch (e) {
            if (e === STOP) return null;
            throw e;
        }
    }

    async function loop() {
        if (looping) return;
        looping = true;
        try {
            while (auto && visible) {
                const id = await play(current);
                if (id === null) return;
                await sleep(HOLD, id);
                current = (current + 1) % SCENARIOS.length;
            }
        } catch (e) {
            if (e !== STOP) throw e;
        } finally {
            looping = false;
        }
    }

    new IntersectionObserver(([entry]) => {
        visible = entry.isIntersecting;
        if (visible && auto) loop();
        else if (!visible && auto) run++; // pause; the scenario restarts when it scrolls back into view
    }, { threshold: 0.35 }).observe(root);

    // With reduced motion the first scenario is shown already finished; otherwise it plays once the section is visible.
    if (reduce) play(0); else reset(0);
})();

// Benchmark chart: compat/bench/results.json from the CI run named in the section's disclosure (main at 9ccf8ac).
(function () {
    const chart = document.getElementById('perf-chart');
    if (!chart) return;
    // HTTP/1.1 only: every client against the same server. [name, note, ours, req/s, p50 ms, p99 ms, CPU ms per 1,000 requests]
    const RESULTS = {
        '1 KiB body': [
            ['UltraTon', '', true, 6907, 1.91, 5.33, 146.1],
            ['fetch (undici)', "Node's built-in", false, 9458, 1.50, 10.52, 135.9],
            ['http.request', 'baseline, no checks', false, 8989, 1.61, 4.32, 113.0],
            ['node-fetch', '', false, 4787, 2.84, 7.29, 212.3],
            ['axios', '', false, 4385, 3.80, 7.73, 229.4],
            ['axios + secure agents', 'createSecureAgents()', false, 4299, 3.20, 9.51, 275.9],
            ['got', '', false, 3702, 3.60, 11.49, 309.1],
        ],
        '64 KiB body': [
            ['UltraTon', '', true, 5661, 2.33, 6.86, 223.4],
            ['fetch (undici)', "Node's built-in", false, 4890, 2.77, 7.04, 316.4],
            ['http.request', 'baseline, no checks', false, 7568, 1.72, 5.37, 167.3],
            ['node-fetch', '', false, 3449, 3.85, 11.41, 355.0],
            ['axios', '', false, 3502, 3.67, 10.40, 388.8],
            ['axios + secure agents', 'createSecureAgents()', false, 3530, 3.73, 10.05, 395.4],
            ['got', '', false, 2984, 4.39, 11.26, 449.7],
        ],
    };
    // UltraTon with http2: true, shown apart: another protocol and another server (node:http2, h2c), one connection.
    const HTTP2 = {
        '1 KiB body': {
            rps: 12354,
            why: 'Almost twice its HTTP/1.1 result. The gain is HTTP/2 itself: all 16 requests share one connection, and headers repeated on every request are compressed. With small bodies, those savings are most of the work.',
        },
        '64 KiB body': {
            rps: 5584,
            why: 'About the same as its HTTP/1.1 result. With large bodies the bytes dominate, and they all travel over that one connection: sharing it stops helping. HTTP/2 pays off most with many small requests.',
        },
    };
    const fmt = n => n.toLocaleString('en-US');
    const el = (tag, className, text) => {
        const e = document.createElement(tag);
        if (className) e.className = className;
        if (text !== undefined) e.textContent = text;
        return e;
    };
    const tabs = document.getElementById('perf-tabs');
    const tooltip = document.getElementById('perf-tooltip');
    const table = document.getElementById('perf-table');

    function showTooltip(row, [name, , , rps, p50, p99, cpu]) {
        tooltip.replaceChildren(
            el('strong', 'perf-tip-value', `${fmt(rps)} req/s`),
            el('span', 'perf-tip-name', name),
            el('span', 'perf-tip-detail', `p50 ${p50.toFixed(2)} ms · p99 ${p99.toFixed(2)} ms · ${cpu.toFixed(1)} ms CPU per 1,000 requests`),
        );
        tooltip.hidden = false;
        const box = chart.parentElement.getBoundingClientRect();
        const r = row.getBoundingClientRect();
        tooltip.style.top = `${r.bottom - box.top + 6}px`;
        tooltip.style.left = `${Math.max(0, Math.min(r.left - box.left + 140, box.width - tooltip.offsetWidth - 16))}px`;
    }
    const hideTooltip = () => { tooltip.hidden = true; };

    function renderHttp2(scenario) {
        const { rps, why } = HTTP2[scenario];
        const http1 = RESULTS[scenario].find(r => r[2])[3];
        const figure = document.getElementById('perf-h2-figure');
        figure.replaceChildren(el('strong', '', `${fmt(rps)} req/s`), ` with ${scenario === '1 KiB body' ? '1 KiB' : '64 KiB'} bodies, against ${fmt(http1)} over HTTP/1.1 (${(rps / http1).toFixed(2)}×).`);
        document.getElementById('perf-h2-why').textContent = why;
    }

    function render(scenario) {
        renderHttp2(scenario);
        const rows = [...RESULTS[scenario]].sort((a, b) => b[3] - a[3]);
        const max = Math.max(...rows.map(r => r[3]));
        chart.replaceChildren(...rows.map(entry => {
            const [name, note, ours, rps] = entry;
            const row = el('div', ours ? 'perf-row is-ours' : 'perf-row');
            row.setAttribute('role', 'listitem');
            row.tabIndex = 0;
            row.setAttribute('aria-label', `${name}${note ? `, ${note}` : ''}: ${fmt(rps)} requests per second`);
            const label = el('div', 'perf-label');
            label.append(el('span', 'perf-name', name));
            if (note) label.append(el('span', 'perf-note', note));
            const track = el('div', 'perf-track');
            const bar = el('div', 'perf-bar');
            bar.style.width = `${(rps / max) * 100}%`;
            track.append(bar, el('span', 'perf-value', fmt(rps)));
            row.append(label, track);
            for (const [on, off] of [['pointerenter', 'pointerleave'], ['focus', 'blur']]) {
                row.addEventListener(on, () => showTooltip(row, entry));
                row.addEventListener(off, hideTooltip);
            }
            return row;
        }));

        const head = el('tr');
        for (const h of ['Client', 'req/s', 'p50 (ms)', 'p99 (ms)', 'CPU (ms / 1k req)']) head.append(el('th', '', h));
        const caption = el('caption', '', `Requests per second, ${scenario}`);
        table.replaceChildren(caption, head, ...rows.map(([name, note, , rps, p50, p99, cpu]) => {
            const tr = el('tr');
            tr.append(el('td', '', note ? `${name} (${note})` : name), el('td', '', fmt(rps)), el('td', '', p50.toFixed(2)), el('td', '', p99.toFixed(2)), el('td', '', cpu.toFixed(1)));
            return tr;
        }));
    }

    tabs.addEventListener('click', e => {
        const button = e.target.closest('button[data-scenario]');
        if (!button) return;
        for (const b of tabs.querySelectorAll('button')) b.setAttribute('aria-pressed', String(b === button));
        hideTooltip();
        render(button.dataset.scenario);
    });
    render('1 KiB body');
})();
