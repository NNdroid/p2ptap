// Browser regression tests against local API fixtures, not a live VPN/device.
// Requires Playwright + ws on NODE_PATH and an installed Chrome (or set WEBUI_BROWSER_EXE).
// Run: node scripts/test-webui.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { chromium } = require('playwright');
const { WebSocketServer } = require('ws');

const peerID = '12D3KooWTestPeer';
const staticDir = path.resolve(__dirname, '../pkg/web/static');
const output = process.env.WEBUI_TEST_OUTPUT;
const stats = {
    node_name: 'WebUI regression node', peer_id: 'local-test-peer', version: 'test',
    tap_ip: '10.42.0.1/24', tap_ipv6: '', transport_strategy: 'best_path',
    packet_stats: { bytes_sent: 4096, bytes_recv: 8192, packets_sent: 4, packets_recv: 8, dedup_count: 2 },
    speed: { tx_bytes_per_sec: 1024, rx_bytes_per_sec: 2048 },
    speed_history: [0, 1, 2].map(i => ({ timestamp: `12:00:0${i}`, tx_speed: 1024 + i * 100, rx_speed: 2048 + i * 100, tx_pps: i + 1, rx_pps: i + 2, tx_unicast: i + 1, rx_unicast: i + 2 })),
    security: { psk_status: 'Public', obfuscation: 'Disabled', key_fingerprint: '', encryption: [] },
    protocol_stats: { ipv4: 3, ipv6: 0, arp: 1, ndp: 0, icmp: 2, udp: 3, tcp: 4, other: 1 },
    active_peers: [{ peer_id: peerID, node_name: 'Peer fixture', addr: '/ip4/192.0.2.2/tcp/4001/p2p/' + peerID, tap_ip: '10.42.0.2', rtt_ms: 0.75, transport: 'tcp', connection_path: 'direct', total_tx: 1234, total_rx: 5678, link_total_tx: 256, link_total_rx: 512, tx_speed: 64, rx_speed: 128, link_speed_measured: false }],
    routes: [], peer_metas: [], arp_table: [], mac_table: [], ip_stats: [], mesh_matrix: [],
};
let config = {
    node_name: stats.node_name, platform: 'android', transport_strategy: 'best_path', psk: '', log_level: 'info',
    transports: {}, bootstrap_peers: [], static_peers: [], obfuscation: { mode: 'random' },
    acl: { enable: false, default_action: 'accept', rules: [] },
};
let statsStatus = 200;
const requests = [];
const saves = [];
const sockets = new WebSocketServer({ noServer: true });
const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    requests.push(url.pathname);
    if (url.pathname === '/favicon.ico') { res.writeHead(204).end(); return; }
    if (url.pathname.startsWith('/api/')) {
        res.setHeader('Content-Type', 'application/json');
        let body;
        switch (url.pathname) {
            case '/api/stats': res.statusCode = statsStatus; body = statsStatus === 200 ? stats : { error: 'Test connection failure' }; break;
            case '/api/topology': body = { nodes: [], edges: [] }; break;
            case '/api/ping': body = { success: true, replies: 3, rtt_min_ms: 0.5, rtt_avg_ms: 0.75, rtt_max_ms: 1, jitter_ms: 0.25 }; break;
            case '/api/config':
                if (req.method === 'POST') {
                    const chunks = [];
                    for await (const chunk of req) chunks.push(chunk);
                    config = JSON.parse(Buffer.concat(chunks));
                    saves.push(config);
                    body = { status: 'ok', restart_required: true, restart_fields: ['transport_strategy'] };
                } else body = config;
                break;
            case '/api/tap/info': body = { name: 'fixture-tap', mtu: 1400, is_up: true, ipv4: stats.tap_ip }; break;
            case '/api/peer/echo': body = { success: false, error: 'Fixture: no live peer' }; break;
            case '/api/peer/probe': body = { reachable: false }; break;
            case '/api/multiaddr-test': body = { results: [] }; break;
            case '/api/tap/selftest': body = { available: false, detail: 'Fixture: no TAP device' }; break;
            case '/api/tap/forward-test': body = { available: false, detail: 'Fixture: no TAP device' }; break;
            case '/api/logs': body = []; break;
            case '/api/pcap/state': body = { enabled: false, seq: 0, count: 0, capacity: 200 }; break;
            case '/api/pcap/frames': body = { frames: [] }; break;
            default: res.statusCode = 404; body = { error: 'Unknown test API' };
        }
        res.end(JSON.stringify(body));
        return;
    }
    const filename = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
    if (!['index.html', 'app.js', 'theme.js', 'styles.css', 'compact.css'].includes(filename)) { res.writeHead(404).end(); return; }
    res.setHeader('Content-Type', filename.endsWith('.js') ? 'application/javascript' : filename.endsWith('.css') ? 'text/css' : 'text/html');
    res.end(fs.readFileSync(path.join(staticDir, filename)));
});
server.on('upgrade', (req, socket, head) => {
    sockets.handleUpgrade(req, socket, head, ws => sockets.emit('connection', ws, req));
});

async function run() {
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const launch = { headless: true };
    if (process.env.WEBUI_BROWSER_EXE) launch.executablePath = process.env.WEBUI_BROWSER_EXE;
    else launch.channel = 'chrome';
    const browser = await chromium.launch(launch);
    try {
        const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
        const page = await context.newPage();
        await page.addInitScript(() => localStorage.setItem('p2ptap_lang', 'en'));
        const errors = [];
        page.on('pageerror', err => errors.push(err.message));
        page.on('console', msg => { if (msg.type() === 'error' && !msg.text().includes('status of 503')) errors.push(msg.text()); });
        const url = `http://127.0.0.1:${server.address().port}/?token=webui-test`;
        await page.goto(url);
        await page.waitForFunction(() => document.getElementById('dashboardStatusText').getAttribute('data-i18n') === 'dashboard_live');
        assert.equal(await page.locator('.dashboard-panel:visible').count(), 1);
        assert.equal(await page.locator('#dashboard-overview').isVisible(), true);
        assert.equal(await page.locator('#txBytes').innerText(), '4 KB');
        assert.equal(await page.locator('.throughput-card').count(), 2);
        assert.equal(await page.locator('#txSpeed').innerText(), '1.0 KB/s');
        assert.equal(await page.locator('.stats-grid > .glass-card').evaluateAll(cards => cards.every(card => getComputedStyle(card).opacity === '1')), true, 'cards must appear immediately after page switches');
        assert.equal(await page.locator('#tapIPv4').innerText(), stats.tap_ip);
        assert.equal(await page.locator('#tapIPv6').innerText(), await page.evaluate(() => t('not_configured')));
        assert.equal(await page.locator('#meshHealthSection, #statMeshHealth, #aclEditorModal, #aclTestModal, #trafficCompContainer').count(), 0);
        assert.equal(sockets.clients.size, 0, 'overview must not start diagnostic sockets');
        assert.equal(requests.includes('/api/pcap/state'), false, 'overview must not poll capture state');

        for (const lang of ['en', 'zh-CN', 'zh-TW', 'ja', 'de', 'es', 'fr']) {
            await page.selectOption('#langSelect', lang);
            assert.equal(await page.locator('html').getAttribute('lang'), lang);
            for (const tab of await page.locator('[role=tab]').all()) assert.ok((await tab.innerText()).trim().length > 0);
        }
        await page.selectOption('#langSelect', 'zh-CN');
        await page.locator('#dashboard-tab-peers').click();
        await page.waitForFunction(() => document.getElementById('peersList').innerText.includes('Peer fixture'));
        assert.equal(await page.locator('#dashboard-peers').isVisible(), true);
        assert.equal(await page.locator('.compact-peer-table thead th').count(), 5);
        assert.equal(await page.locator('#topologyDetails').getAttribute('open'), null);
        await page.locator('.peer-details-btn').click();
        assert.equal(await page.locator('#peerDetailsTitle').innerText(), 'Peer fixture');
        let fields = await page.locator('.peer-detail-grid > div').evaluateAll(items => items.map(el => ({ label: el.querySelector('dt').innerText, value: el.querySelector('dd').innerText })));
        assert.ok(fields.some(f => f.value.includes('256 B') && f.value.includes('512 B')), 'local link totals must remain available in details');
        assert.ok(fields.some(f => f.value.includes('1.21 KB') && f.value.includes('5.54 KB')), 'remote node totals must be separate');
        assert.equal(fields.find(f => f.label === '实测链路速率').value, '—', 'unknown rates must not be fabricated');
        await page.locator('#peerDetailsBody .peer-detail-actions button').first().focus();
        stats.active_peers[0].link_speed_measured = true;
        await page.evaluate(() => fetchStats());
        await page.waitForFunction(() => document.getElementById('peerDetailsBody').innerText.includes('0.1 KB/s'));
        assert.ok(await page.locator('#peerDetailsBody .peer-detail-actions button').first().evaluate(el => el === document.activeElement), 'refresh must preserve focus on a detail action');
        await page.locator('#peerDetailsBody .btn-multiaddr-view').click();
        assert.equal(await page.locator('#peerDetailsModal').isVisible(), false);
        assert.equal(await page.locator('#multiaddrModal').isVisible(), true, 'address details must not be covered by the peer dialog');
        await page.locator('button[data-onclick="closeMultiaddrModal()"]').click();
        await page.locator('.peer-details-btn').click();
        await page.keyboard.press('Escape');
        assert.equal(await page.locator('#peerDetailsModal').isVisible(), false);
        await page.locator('#topologyDetails > summary').click();
        assert.ok((await page.locator('#topologyCanvas').boundingBox()).width > 100);
        const nodePosition = await page.evaluate(id => {
            const node = window.latestTopoNodes.find(n => n.id === id);
            return { x: node.x * topoZoom + topoPanX, y: node.y * topoZoom + topoPanY };
        }, peerID);
        const pingRequest = page.waitForRequest(req => req.url().includes('/api/ping?'));
        await page.locator('#topologyCanvas').dblclick({ position: nodePosition });
        await pingRequest;
        assert.equal(await page.locator('#dashboard-diagnostics').isVisible(), true, 'double click must run ping and reveal its result');
        await page.locator('#dashboard-tab-network').click();
        await page.locator('[data-onclick="openConfigModal(\'acl\')"]').click();
        await page.waitForFunction(() => document.getElementById('configModal').classList.contains('active'));
        assert.equal(await page.locator('#aclRulesList .acl-rule-row').count(), 0, 'editing must not insert a rule');
        assert.equal(await page.locator('#exitNodeConfigSection').isVisible(), false, 'Android must hide Linux exit server settings');
        await page.locator('[data-onclick="addACLRuleRow()"]').click();
        assert.equal(await page.locator('#aclRulesList .acl-rule-row').count(), 1);
        await page.locator('button[data-onclick="closeConfigModal()"]').click();
        await page.locator('[data-onclick="openConfigModal(\'acl\')"]').click();
        await page.waitForFunction(() => document.getElementById('configModal').classList.contains('active'));
        assert.equal(await page.locator('#aclRulesList .acl-rule-row').count(), 0, 'cancel must discard draft rules');
        await page.locator('[data-onclick="addACLRuleRow()"]').click();
        await page.locator('#cfgACLEnable').check();
        await page.selectOption('#cfgStrategy', 'fallback');
        await page.locator('[data-onclick="saveConfigModal()"]').click();
        await page.waitForFunction(() => !document.getElementById('configModal').classList.contains('active'));
        assert.equal(saves.length, 1);
        assert.equal(saves[0].acl.rules.length, 1);
        assert.equal(saves[0].acl.enable, true);
        assert.equal(saves[0].transport_strategy, 'fallback');
        assert.ok((await page.locator('#toast').innerText()).includes('transport_strategy'), 'save must display pending restart fields');

        // Opening a node's ping target must reveal the diagnostic page/input.
        await page.evaluate(() => setPingTarget('10.42.0.2'));
        assert.equal(await page.locator('#dashboard-diagnostics').isVisible(), true);
        assert.equal(await page.locator('#pingTargetInput').inputValue(), '10.42.0.2');
        assert.equal(await page.locator('#troubleshootPeerSelect, #troubleshootTargetInput').count(), 0, 'one shared diagnostic target');
        await page.locator('#btnRunConnectivity').click();
        await page.waitForFunction(() => document.querySelectorAll('#troubleshootResults .troubleshoot-card').length >= 9);
        assert.ok(requests.includes('/api/peer/echo'), 'the shared target must run connectivity probes');
        assert.equal(await page.locator('#connectivityDetails').getAttribute('open'), '');
        assert.equal(sockets.clients.size, 0, 'collapsed diagnostic tools must not connect');
        await page.locator('#logsDetails > summary').click();
        await page.waitForFunction(() => logStream.status === 'live');
        assert.equal(sockets.clients.size, 1);
        await page.locator('#captureDetails > summary').click();
        await page.waitForFunction(() => logStream.status === 'live' && pcapStream.status === 'live');
        assert.equal(sockets.clients.size, 2);
        await page.locator('#dashboard-tab-overview').click();
        await page.waitForFunction(() => logStream.status === 'off' && pcapStream.status === 'off');
        assert.equal(await page.evaluate(() => topoRAFId), null);
        await page.waitForTimeout(100);
        assert.equal(sockets.clients.size, 0);
        await page.goBack();
        await page.waitForFunction(() => !document.getElementById('dashboard-diagnostics').hidden && logStream.status === 'live' && pcapStream.status === 'live');
        assert.equal(sockets.clients.size, 2, 'returning to diagnostics must reconnect both sockets');
        const traffic = page.locator('.dashboard-details').filter({ has: page.locator('[data-i18n="dashboard_traffic_details"]') });
        await traffic.locator('summary').click();
        await page.waitForFunction(() => document.getElementById('ppsCanvas').width > 100);
        assert.ok((await page.locator('#ppsCanvas').boundingBox()).width > 100);

        statsStatus = 503;
        await page.evaluate(() => fetchStats());
        await page.waitForFunction(() => document.getElementById('dashboardStatus').classList.contains('is-offline'));
        assert.equal(await page.locator('#txBytes').innerText(), '4 KB', 'retain last known data while marking it stale');
        assert.equal(await page.locator('#dashboardRetry').isVisible(), true);
        statsStatus = 200;
        await page.locator('#dashboardRetry').click();
        await page.waitForFunction(() => !document.getElementById('dashboardStatus').classList.contains('is-offline'));

        assert.equal(await page.locator('#dashboardRetry').isVisible(), false);
        await page.selectOption('#diagViewSelect', 'raw');
        assert.equal(await page.locator('#pingOutput').isVisible(), true);
        assert.equal(await page.locator('#diagVisualContainer').isVisible(), false);
        await page.selectOption('#diagViewSelect', 'visual');
        await page.locator('#logsDetails > summary').click();
        await page.waitForFunction(() => logStream.status === 'off');
        assert.equal(await page.evaluate(() => pcapStream.status), 'live', 'closing logs must leave capture running');
        await page.locator('#captureDetails > summary').click();
        await page.waitForFunction(() => pcapStream.status === 'off');
        await page.waitForTimeout(100);
        assert.equal(sockets.clients.size, 0);
        await page.locator('#dashboard-tab-overview').click();
        await page.locator('#dashboard-tab-overview').focus();
        await page.keyboard.press('ArrowRight');
        assert.equal(await page.locator('#dashboard-tab-peers').getAttribute('aria-selected'), 'true');
        await page.keyboard.press('End');
        assert.equal(await page.locator('#dashboard-tab-diagnostics').getAttribute('aria-selected'), 'true');

        if (output) {
            fs.mkdirSync(output, { recursive: true });
            await page.locator('#dashboard-tab-overview').click();
            await page.addStyleTag({ content: '#toast { display: none !important; }' });
            await page.screenshot({ path: path.join(output, 'webui-desktop.png'), fullPage: true });
        }
        await page.setViewportSize({ width: 390, height: 844 });
        await page.locator('#dashboard-tab-overview').click();
        assert.ok(await page.evaluate(() => document.querySelector('#dashboard-overview').getBoundingClientRect().bottom <= innerHeight), 'the mobile overview must fit the first screen');
        await page.locator('#dashboard-tab-peers').click();
        assert.ok(await page.locator('.compact-peer-table').evaluate(el => el.scrollWidth <= el.clientWidth), 'mobile peer cards must not need horizontal scrolling');
        await page.locator('.peer-details-btn').click();
        assert.ok(await page.locator('.peer-details-modal').evaluate(el => el.scrollWidth <= el.clientWidth), 'peer details must fit mobile width');
        await page.keyboard.press('Escape');
        if (output) {
            await page.locator('#topologyDetails > summary').click();
            await page.screenshot({ path: path.join(output, 'webui-peers-mobile.png'), fullPage: true });
        }
        for (const name of ['overview', 'peers', 'network', 'diagnostics']) {
            await page.locator('#dashboard-tab-' + name).click();
            assert.equal(await page.locator('.dashboard-panel:visible').count(), 1);
            for (const detail of await page.locator('#dashboard-' + name + ' .dashboard-details').all()) {
                if (await detail.getAttribute('open') === null) await detail.locator('summary').click();
            }
            const overflow = await page.evaluate(() => ({
                width: document.documentElement.scrollWidth,
                elements: [...document.querySelectorAll('body *')].filter(el => {
                    const r = el.getBoundingClientRect();
                    return r.width && r.right > innerWidth && !el.closest('.table-responsive');
                }).map(el => ({ tag: el.tagName, id: el.id, class: el.className, width: Math.round(el.getBoundingClientRect().width) })).slice(0, 12),
            }));
            assert.ok(overflow.width <= 390, `${name} must fit mobile width: ${JSON.stringify(overflow)}`);
        }
        await page.locator('#themeToggle').click();
        assert.equal(await page.locator('html').getAttribute('data-theme'), 'light');
        await page.locator('#themeToggle').click();
        if (output) {
            await page.locator('#dashboard-tab-overview').click();
            await page.screenshot({ path: path.join(output, 'webui-mobile.png'), fullPage: true });
        }
        for (const lang of ['en', 'zh-CN', 'zh-TW', 'ja', 'de', 'es', 'fr']) {
            await page.selectOption('#langSelect', lang);
            for (const name of ['overview', 'peers', 'network', 'diagnostics']) {
                await page.locator('#dashboard-tab-' + name).click();
                assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `${lang}/${name} must fit mobile width`);
            }
        }
        const pageBeforeReload = await page.evaluate(() => currentDashboardPage());
        await page.reload();
        await page.waitForFunction(() => document.getElementById('dashboardStatusText').getAttribute('data-i18n') === 'dashboard_live');
        assert.equal(await page.locator('#dashboard-' + pageBeforeReload).isVisible(), true);
        await page.goto(url + '#network');
        await page.reload();
        await page.waitForFunction(() => document.getElementById('dashboardStatusText').getAttribute('data-i18n') === 'dashboard_live');
        assert.equal(await page.locator('#dashboard-network').isVisible(), true, 'bookmarked pages must survive a reload');
        assert.deepEqual(errors, [], 'browser must have no JavaScript errors');
        await context.close();
        console.log('PASS: compact first-screen overview, five-column peer list and responsive cards, live peer details, measured/unknown telemetry, per-tool diagnostic sockets, raw/visual select, retry and four pages and expanded panels, seven locales, ACL edit/cancel/save, restart notice, live/stale status, keyboard/back/bookmark navigation, double-click ping, chart redraw, themes, diagnostic socket lifecycle and mobile layout.');
    } finally {
        await browser.close();
    }
}
run().catch(err => { console.error(err); process.exitCode = 1; }).finally(() => {
    for (const ws of sockets.clients) ws.terminate();
    sockets.close();
    server.close();
});
