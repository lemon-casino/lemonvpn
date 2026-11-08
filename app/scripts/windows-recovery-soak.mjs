// Real native host + WebView2. --network-cycle and --s3 are explicit disruptive
// test options: their OS helper installs independent restoration/wake tasks.
import assert from 'node:assert/strict';
import {spawn, execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {cp, mkdtemp, mkdir, readFile, rename, writeFile} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {createConnection, createServer} from 'node:net';
import {tmpdir} from 'node:os';
import {dirname, join, resolve} from 'node:path';
import {connect as connectTls} from 'node:tls';
import {fileURLToPath} from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const require = createRequire(join(root, 'doona/package.json'));
const {chromium} = require('@playwright/test');
const seconds = Math.max(60, Math.min(6900, Number(process.argv.find(arg => /^--seconds=/.test(arg))?.split('=')[1] ?? 3600)));
const realNetwork = process.argv.includes('--network-cycle');
const realS3 = process.argv.includes('--s3');
const folder = await mkdtemp(join(tmpdir(), 'lemonvpn-native-recovery-'));
const output = join(root, 'app/src-tauri/target');
const exe = join(folder, 'lemonvpn.exe');
const sidecar = join(folder, 'lemonvpn-engine-stub.exe');
await cp(join(root, 'app/src-tauri/target/release/lemonvpn.exe'), exe);
await cp(join(root, 'app/src-tauri/binaries/lemonvpn-engine-stub-x86_64-pc-windows-msvc.exe'), sidecar);
await cp(join(root, 'app/src-tauri/binaries/wintun.dll'), join(folder, 'wintun.dll'));
const powershell = join(process.env.SystemRoot, 'System32/WindowsPowerShell/v1.0/powershell.exe');
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
await mkdir(output, {recursive: true});
async function freePort() {
  const server = createServer(); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port; await new Promise(resolve => server.close(resolve)); return port;
}
const debugPort = await freePort(), enginePort = await freePort();
const env = {...process.env, LEMONVPN_ENGINE: sidecar, LEMONVPN_ENGINE_PORT: String(enginePort),
  LEMONVPN_DATA_DIR: join(folder, 'engine'), WEBVIEW2_USER_DATA_FOLDER: join(folder, 'webview'),
  LEMONVPN_SMOKE: '1', LEMONVPN_SMOKE_DEBUG_PORT: String(debugPort),
  LEMONVPN_SMOKE_TIMEOUT_MS: String((seconds + 30) * 1000), LEMONVPN_OPEN_LOGS: '0'};
const host = spawn(exe, [], {windowsHide: true, env});
let hostLogs = '';
host.stderr.on('data', bytes => { hostLogs += bytes; }); host.stdout.resume();
const hostExit = new Promise((resolve, reject) => { host.once('error', reject); host.once('exit', (code, signal) => resolve({code, signal})); });
const report = {startedAt: new Date().toISOString(), secondsRequested: seconds, hostPid: host.pid, enginePort,
  hostSha256: createHash('sha256').update(await readFile(exe)).digest('hex'),
  engineSha256: createHash('sha256').update(await readFile(sidecar)).digest('hex'),
  isolatedData: folder, checks: [], samples: [], windowsCycles: [], passed: false};
let browser, page, cdp, enginePid, persistent, lastApiResponse = 0;
const inspectorConnections = [];
const echoSockets = new Set();
const echo = createServer(socket => { echoSockets.add(socket); socket.on('error', () => {}); socket.once('close', () => echoSockets.delete(socket)); socket.pipe(socket); });
await new Promise(resolve => echo.listen(0, '127.0.0.1', resolve));
const echoPort = echo.address().port;
const endpoint = `http://127.0.0.1:${enginePort}`;
async function save() { await writeFile(join(folder, 'report.json'), JSON.stringify(report, null, 2)); }
function checked(name, details = {}) {
  const check = {at: new Date().toISOString(), name, ...details}; report.checks.push(check);
  console.log(JSON.stringify({check}));
}
async function api(path) {
  const response = await fetch(`${endpoint}/api/v1/${path}`, {signal: AbortSignal.timeout(3000)});
  assert.ok(response.ok, `${path}: ${response.status}`); return response.json();
}
function receive(socket, complete, timeout = 5000) {
  return new Promise((resolve, reject) => {
    let bytes = Buffer.alloc(0);
    const clean = () => { clearTimeout(timer); socket.off('data', data); socket.off('error', fail); socket.off('end', ended); };
    const fail = error => { clean(); reject(error); };
    const ended = () => fail(new Error('Unexpected EOF'));
    const data = chunk => { bytes = Buffer.concat([bytes, chunk]); if (complete(bytes)) { clean(); resolve(bytes); } };
    const timer = setTimeout(() => fail(new Error('IO deadline exceeded')), timeout);
    socket.on('data', data); socket.once('error', fail); socket.once('end', ended);
  });
}
async function tunnel(target, port) {
  const socket = createConnection({host: '127.0.0.1', port: enginePort}); socket.on('error', () => {});
  try {
    await new Promise((resolve, reject) => { socket.once('connect', resolve); socket.once('error', reject); });
    const header = receive(socket, bytes => bytes.includes('\r\n\r\n'), 15000);
    socket.write(`CONNECT ${target}:${port} HTTP/1.1\r\nHost: ${target}:${port}\r\n\r\n`);
    assert.match((await header).toString(), /^HTTP\/1.1 200/); return socket;
  } catch (error) { socket.destroy(); throw error; }
}
async function localEcho() {
  const socket = await tunnel('127.0.0.1', echoPort);
  try { const reply = receive(socket, bytes => bytes.length >= 16); socket.write('recovery payload'); assert.equal((await reply).toString(), 'recovery payload'); }
  finally { socket.destroy(); }
}
async function persistentEcho() {
  const response = receive(persistent, bytes => bytes.length >= 16);
  persistent.write('persistent echo!');
  assert.equal((await response).toString(), 'persistent echo!');
}
async function publicHttps() {
  const socket = await tunnel('example.com', 443);
  const tls = connectTls({socket, servername: 'example.com', ALPNProtocols: ['http/1.1']}); tls.on('error', () => {});
  try {
    await Promise.race([new Promise((resolve, reject) => { tls.once('secureConnect', resolve); tls.once('error', reject); }),
      pause(10000).then(() => { throw new Error('TLS handshake timed out'); })]);
    const response = receive(tls, bytes => bytes.includes('\r\n\r\n'), 10000);
    tls.write('GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: LemonVPN-Stability-Test\r\nConnection: close\r\n\r\n');
    const status = (await response).toString().split('\r\n')[0]; assert.match(status, /^HTTP\/1\.[01] [23]\d\d/); return status;
  } finally { tls.destroy(); socket.destroy(); }
}
async function waitPublic(name) {
  const start = Date.now(), deadline = start + 60000;
  let last;
  do { try { const status = await publicHttps(); checked(name, {elapsedMs: Date.now() - start, status}); return; }
    catch (error) { last = error; await pause(1000); } } while (Date.now() < deadline);
  throw last;
}
async function attachInspector(reason) {
  const version = await fetch(`http://127.0.0.1:${debugPort}/json/version`).then(response => response.json());
  const targets = await fetch(`http://127.0.0.1:${debugPort}/json/list`).then(response => response.json());
  browser = await chromium.connectOverCDP(`http://127.0.0.1:${debugPort}`);
  inspectorConnections.push(browser);
  const context = browser.contexts()[0];
  page = context.pages().find(candidate => candidate.url().includes('tauri.localhost')) ?? context.pages()[0] ?? await context.waitForEvent('page');
  await page.waitForURL(/tauri\.localhost/);
  page.on('response', response => { if (response.url().startsWith(endpoint + '/api/') && response.ok()) lastApiResponse = Date.now(); });
  cdp = await context.newCDPSession(page);
  const state = await page.evaluate(() => ({title: document.title, brand: document.querySelector('.rp-brand')?.textContent, hidden: document.hidden}));
  assert.equal(state.brand, 'LemonVPN', 'Native WebView did not retain its rendered application');
  checked('inspector attached to existing native page', {reason, browser: version.Browser, targets: targets.map(target => ({id: target.id, url: target.url})), state});
}
async function runCycle(action) {
  const started = Date.now();
  const child = spawn(powershell, ['-NoProfile', '-NonInteractive', '-File', join(root, 'app/scripts/windows-recovery-cycle.ps1'), '-Action', action, '-WorkDir', folder], {windowsHide: true});
  let output = '', errors = '';
  let outageCheck;
  child.stdout.on('data', data => {
    output += data;
    if (action === 'Network' && !outageCheck && output.includes('"phase":"network_disabled"')) {
      const at = Date.now();
      outageCheck = Promise.all([api('desktop/status'), localEcho(), persistentEcho()])
        .then(() => ({passed: true, elapsedMs: Date.now() - at}), error => ({passed: false, error: String(error)}));
    }
  }); child.stderr.on('data', data => { errors += data; });
  const code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', resolve); });
  report.windowsCycles.push({action, elapsedMs: Date.now() - started, exitCode: code, output, errors});
  await save(); assert.equal(code, 0, errors || output);
  if (action === 'Network') {
    assert.ok(outageCheck, 'No hardware-offline phase was observed');
    const result = await outageCheck; assert.ok(result.passed, result.error);
    assert.ok(result.elapsedMs < 2500, 'Local control/echo stalled while WLAN was disabled');
    checked('WLAN disabled: local API and both echo paths remained responsive', result);
  }
  checked(`${action} OS helper completed`, {elapsedMs: Date.now() - started});
  assert.equal((await fetch(`${endpoint}/health`).then(response => response.json())).pid, enginePid, 'Engine identity changed during recovery');
  await localEcho(); await persistentEcho(); await waitPublic(`${action}: public HTTPS restored`);
  if (action === 'Sleep') await attachInspector('after real S3; reconnect debugger transport without reloading the app');
  // A hidden/locked WebView legitimately defers polling until visible again.
  // Direct IPC/fetch must work even in the background; visible-page polling is
  // checked separately during the continuing soak.
  const bridge = await page.evaluate(async url => ({hidden: document.hidden, status: (await fetch(url + '/api/v1/desktop/status')).status}), endpoint);
  assert.equal(bridge.status, 200); checked(`${action}: WebView API bridge`, bridge);
}
async function sample() {
  assert.equal((await fetch(`${endpoint}/health`).then(response => response.json())).pid, enginePid, 'Unexpected engine restart during soak');
  const status = await api('desktop/status'); await localEcho();
  await persistentEcho();
  const heap = await cdp.send('Runtime.getHeapUsage');
  const script = `$all = @(Get-CimInstance Win32_Process); $ids = [System.Collections.Generic.HashSet[int]]::new(); [void]$ids.Add(${host.pid}); do { $added=$false; foreach($p in $all) { if($ids.Contains([int]$p.ParentProcessId) -and $ids.Add([int]$p.ProcessId)) { $added=$true } } } while($added); @($ids | ForEach-Object { Get-Process -Id $_ -ErrorAction SilentlyContinue } | ForEach-Object { [pscustomobject]@{id=$_.Id;name=$_.ProcessName;handles=$_.HandleCount;threads=$_.Threads.Count;privateBytes=$_.PrivateMemorySize64;rss=$_.WorkingSet64;cpuSeconds=$_.TotalProcessorTime.TotalSeconds} }) | ConvertTo-Json -Compress`;
  const processes = JSON.parse(execFileSync(powershell, ['-NoProfile', '-Command', script], {windowsHide: true, encoding: 'utf8'}));
  const row = {at: new Date().toISOString(), engineRss: Number(status.memory.process.rss_bytes), enginePrivate: Number(status.memory.process.private_bytes),
    heapUsed: heap.usedSize, heapTotal: heap.totalSize, processes, uiLastResponseAt: lastApiResponse ? new Date(lastApiResponse).toISOString() : null,
    visible: await page.evaluate(() => !document.hidden)};
  if (row.visible) assert.ok(Date.now() - lastApiResponse < 45000, 'Visible WebView API polling stopped');
  report.samples.push(row); console.log(JSON.stringify({sample: row.at, engineRss: row.engineRss, heapUsed: row.heapUsed, processes: processes.length, visible: row.visible})); await save();
}
try {
  console.log(JSON.stringify({started: report.startedAt, seconds, hostPid: host.pid, enginePort, isolatedData: folder, realNetwork, realS3}));
  const deadline = Date.now() + 10000;
  while (true) { try { if ((await fetch(`http://127.0.0.1:${debugPort}/json/version`)).ok) break; } catch {}
    assert.ok(Date.now() < deadline, hostLogs); await pause(100); }
  browser = await chromium.connectOverCDP(`http://127.0.0.1:${debugPort}`); inspectorConnections.push(browser);
  const context = browser.contexts()[0]; page = context.pages()[0] ?? await context.waitForEvent('page');
  await page.waitForURL(/tauri\.localhost/);
  page.on('response', response => { if (response.url().startsWith(endpoint + '/api/') && response.ok()) lastApiResponse = Date.now(); });
  await page.evaluate(() => { localStorage.setItem('doona-lang', 'zh-CN'); location.hash = '/overview'; });
  await page.reload(); await page.locator('.rp-top .rp-brand').waitFor();
  cdp = await context.newCDPSession(page);
  const identity = await fetch(`${endpoint}/health`).then(response => response.json()); enginePid = identity.pid;
  report.enginePid = enginePid;
  const proxyBefore = await page.evaluate(() => window.__TAURI__.core.invoke('proxy_status'));
  await waitPublic('baseline public HTTPS'); await localEcho();
  persistent = await tunnel('127.0.0.1', echoPort); await persistentEcho();
  await sample();
  if (realNetwork) await runCycle('Network');
  if (realS3) await runCycle('Sleep');
  assert.deepEqual(await page.evaluate(() => window.__TAURI__.core.invoke('proxy_status')), proxyBefore, 'OS recovery test changed proxy ownership');
  const end = Date.parse(report.startedAt) + seconds * 1000;
  while (Date.now() < end) {
    let request;
    try { request = JSON.parse(await readFile(join(folder, 'request-cycle.json'), 'utf8')); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (request) {
      assert.ok(['Network', 'Sleep'].includes(request.action), 'Unknown OS test action');
      await rename(join(folder, 'request-cycle.json'), join(folder, `handled-cycle-${Date.now()}.json`));
      report.cycleOutcomes ??= {};
      try { await runCycle(request.action); report.cycleOutcomes[request.action] = {passed: true, at: new Date().toISOString()}; }
      catch (error) { report.cycleOutcomes[request.action] = {passed: false, error: String(error)}; checked('OS cycle requires repair/retest', report.cycleOutcomes[request.action]); }
      await save();
    }
    if (!report.warmupHeap && Date.now() - Date.parse(report.startedAt) >= 600000) {
      await cdp.send('HeapProfiler.collectGarbage'); report.warmupHeap = await cdp.send('Runtime.getHeapUsage');
    }
    await sample(); await pause(Math.min(30000, Math.max(0, end - Date.now())));
  }
  await cdp.send('HeapProfiler.collectGarbage'); await sample();
  for (const [action, outcome] of Object.entries(report.cycleOutcomes ?? {})) assert.ok(outcome.passed, `${action} has not passed retest`);
  if (report.warmupHeap && report.samples.length >= 30) {
    const retained = (await cdp.send('Runtime.getHeapUsage')).usedSize;
    assert.ok(retained <= report.warmupHeap.usedSize + 32 * 1024 * 1024, 'Retained WebView JS heap kept growing');
    const settled = report.samples.filter(row => Date.parse(row.at) - Date.parse(report.startedAt) >= 600000);
    const median = values => [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];
    const total = (row, key) => row.processes.reduce((sum, item) => sum + item[key], 0);
    const early = settled.slice(0, 10), tail = settled.slice(-10);
    const growth = Object.fromEntries(['privateBytes', 'handles', 'threads'].map(key => [key,
      median(tail.map(row => total(row, key))) - median(early.map(row => total(row, key)))]));
    report.growthAfterWarmup = {...growth, retainedHeapBytes: retained - report.warmupHeap.usedSize};
    assert.ok(growth.privateBytes <= 96 * 1024 * 1024, 'Native/WebView private memory did not plateau');
    assert.ok(growth.handles <= 64, 'Native/WebView handle count accumulated');
    assert.ok(growth.threads <= 16, 'Native/WebView worker threads accumulated');
  }
  report.passed = true; report.finishedAt = new Date().toISOString();
  checked('native host/WebView soak finished', {elapsedSeconds: (Date.now() - Date.parse(report.startedAt)) / 1000});
  await save(); console.log(JSON.stringify({passed: true, samples: report.samples.length, checks: report.checks.length, report: join(folder, 'report.json')}));
} catch (error) {
  report.error = {message: String(error), stack: error.stack}; report.finishedAt = new Date().toISOString(); await save(); throw error;
} finally {
  await writeFile(join(folder, 'host-stderr.log'), hostLogs);
  for (const connection of inspectorConnections) await connection.close().catch(() => {});
  persistent?.destroy();
  echoSockets.forEach(socket => socket.destroy()); await new Promise(resolve => echo.close(resolve));
  if (!report.passed) host.kill();
  const fallback = setTimeout(() => host.kill(), 60000);
  const exit = await hostExit; clearTimeout(fallback);
  if (report.passed && exit.code !== 0) {
    report.passed = false; report.error = {message: 'Host did not exit normally', exit}; await save();
    process.exitCode = 1;
  }
  console.log(JSON.stringify({hostExit: exit}));
}
