// Run with: node scripts/test_openwrt_status.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const template = fs.readFileSync(path.join(__dirname, '../openwrt/package/luci-app-p2ptap/luasrc/view/p2ptap/status.htm'), 'utf8');
const script = template.match(/<script[^>]*>([\s\S]*?)<\/script>/)[1].replace(/<%[\s\S]*?%>/g, 'translated');
const box = { innerHTML: '' };
let poll;
const context = {
 document: {getElementById: () => box},
 window: {location: {hostname: 'router.example'}},
 navigator: {},
 XHR: {poll: (interval, url, params, callback) => { poll = callback; }}
};
vm.createContext(context);
vm.runInContext(script, context);
const healthy = {
 running: true, stats_available: true, peer_id: '12D3test',
 node_name: '<img src=x onerror=alert(1)>', peer_count: 1,
 tap_ip: '10.0.0.1/24', tap_ipv6: 'fd00::1/64', tap_mac: '02:00:00:00:00:01',
 tx_speed: '1 KB/s', rx_speed: '2 KB/s', active_exit: '10.0.0.2',
 webui_url: 'http://0.0.0.0:5857/?token=a%26b'
};
poll({}, healthy);
assert.ok(box.innerHTML.includes('&lt;img'));
assert.ok(!box.innerHTML.includes('<img'));
assert.ok(box.innerHTML.includes('http://router.example:5857/?token=a%26b'));
assert.ok(box.innerHTML.includes('rel="noopener noreferrer"'));
assert.ok(box.innerHTML.includes('<button type="button"'));
context.window.location.hostname = '2001:db8::1';
poll({}, healthy);
assert.ok(box.innerHTML.includes('http://[2001:db8::1]:5857/'));
context.window.location.hostname = '[2001:db8::2]';
poll({}, healthy);
assert.ok(box.innerHTML.includes('http://[2001:db8::2]:5857/'));
poll({}, {...healthy, active_exit: '', tap_ipv6: '', peer_count: 0});
assert.ok(!box.innerHTML.includes('10.0.0.2'));
assert.ok(!box.innerHTML.includes('fd00::1'));
poll({}, {running: true, stats_available: false});
assert.ok(!box.innerHTML.includes('12D3test'));
poll({}, {running: false});
assert.ok(!box.innerHTML.includes('p2ptap-webui-btn'));
poll({}, null);
assert.ok(!box.innerHTML.includes('12D3test'));
console.log('OpenWrt status regression checks passed');
