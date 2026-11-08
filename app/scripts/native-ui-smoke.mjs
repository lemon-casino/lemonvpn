// Verify the release executable's real WebView2 UI and an upgrade with an
// existing PWA worker. No browser mocks, user profile, or system proxy changes.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdtemp, mkdir, readFile, writeFile} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {createConnection, createServer} from 'node:net';
import {tmpdir} from 'node:os';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const {chromium} = createRequire(join(root, 'doona/package.json'))('@playwright/test');
const exe = process.argv[2] ?? join(root, 'app/src-tauri/target/release/lemonvpn.exe');
const {version} = JSON.parse(await readFile(join(root, 'app/src-tauri/tauri.conf.json'), 'utf8'));
const sidecar = join(root, 'app/src-tauri/binaries/lemonvpn-engine-stub-x86_64-pc-windows-msvc.exe');
const folder = await mkdtemp(join(tmpdir(), 'lemonvpn-native-ui-'));
const output = join(root, 'app/src-tauri/target/ui-preview');
await mkdir(output, {recursive: true});

async function freePort() {
  const server = createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

async function run(check, timeout = 15000, expectedExit = 0) {
  const debugPort = await freePort();
  const enginePort = await freePort();
  const child = spawn(exe, [], {
    windowsHide: true,
    env: {
      ...process.env,
      LEMONVPN_ENGINE: sidecar,
      LEMONVPN_ENGINE_PORT: String(enginePort),
      LEMONVPN_DATA_DIR: join(folder, 'engine'),
      WEBVIEW2_USER_DATA_FOLDER: join(folder, 'webview'),
      LEMONVPN_SMOKE: '1',
      LEMONVPN_SMOKE_DEBUG_PORT: String(debugPort),
      LEMONVPN_SMOKE_TIMEOUT_MS: String(timeout),
      LEMONVPN_OPEN_LOGS: '0'
    }
  });
  let logs = '';
  child.stderr.on('data', data => { logs += data; });
  const exited = new Promise((resolve, reject) => {
    child.on('error', reject);
    child.on('exit', code => resolve(code));
  });
  let browser;
  try {
    const deadline = Date.now() + 8000;
    while (true) {
      try {
        if ((await fetch(`http://127.0.0.1:${debugPort}/json/version`)).ok) break;
      } catch { /* WebView2 is starting. */ }
      assert.ok(Date.now() < deadline, 'Native WebView inspector did not start');
      await new Promise(resolve => setTimeout(resolve, 75));
    }
    browser = await chromium.connectOverCDP(`http://127.0.0.1:${debugPort}`);
    const context = browser.contexts()[0];
    console.log('Native pages:', context.pages().map(page => page.url()));
    let page = context.pages()[0];
    page ??= await context.waitForEvent('page', {timeout: 3000});
    await page.waitForURL(/tauri\.localhost/, {timeout: 4000});
    await check(page, enginePort, child);
  } finally {
    await browser?.close().catch(() => {});
    const code = await exited;
    await writeFile(join(folder, `run-${enginePort}.log`), logs);
    if (expectedExit === 'terminated') {
      assert.ok(child.killed, 'The isolated host was deliberately terminated');
      assert.notEqual(code, 0, logs);
    } else {
      assert.equal(code, expectedExit, logs);
    }
  }
}

let proxyBefore;
await run(async (page, enginePort) => {
  proxyBefore = await page.evaluate(() => window.__TAURI__.core.invoke('proxy_status'));
  // Real Tauri globals, real local API, and real embedded production assets.
  await page.evaluate(() => {
    localStorage.setItem('doona-lang', 'zh-CN');
    location.hash = '/settings';
  });
  await page.reload();
  await page.locator('.rp-top .rp-brand').waitFor();
  assert.equal(await page.locator('.rp-top .rp-brand').innerText(), 'LemonVPN');
  assert.equal(await page.locator('#settings-backend').count(), 0);
  assert.equal(await page.getByRole('button', {name: /关于 doona/}).count(), 0);
  await page.getByText('日志级别', {exact: true}).waitFor();
  await page.screenshot({path: join(output, 'native-settings.png'), fullPage: true});
  await page.evaluate(() => { location.hash = '/overview'; });
  await page.getByText('系统可用内存', {exact: true}).waitFor();
  assert.equal(await page.getByText('cgroup 已用', {exact: true}).count(), 0);
  await page.screenshot({path: join(output, 'native-status.png'), fullPage: true});
  const runtime = await page.evaluate(() => ({
    href: location.href,
    host: window.__LEMONVPN_DESKTOP__,
    invoke: typeof window.__TAURI__?.core?.invoke,
    internal: typeof window.__TAURI_INTERNALS__?.invoke,
    build: document.querySelector('meta[name="doona-build"]')?.content
  }));
  assert.equal(runtime.host.engineUrl, `http://127.0.0.1:${enginePort}`);
  assert.equal(runtime.host.version, version);
  assert.equal(new URL(runtime.href).searchParams.get('desktop'), version);
  assert.equal(await page.evaluate(async () => (await fetch(location.pathname)).headers.get('cache-control')), 'no-store');
  console.log('Native release UI passed:', JSON.stringify(runtime));

  const identity = await fetch(`http://127.0.0.1:${enginePort}/health`).then(response => response.json());
  const duplicate = spawn(exe, [], {windowsHide: true, env: {
    ...process.env, LEMONVPN_DATA_DIR: join(folder, 'engine'),
    LEMONVPN_ENGINE: sidecar, LEMONVPN_ENGINE_PORT: String(enginePort)
  }});
  duplicate.stdout.resume(); duplicate.stderr.resume();
  const duplicateExit = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => { duplicate.kill(); reject(new Error('Duplicate instance did not exit')); }, 3000);
    duplicate.on('exit', code => { clearTimeout(timer); resolve(code); });
    duplicate.on('error', reject);
  });
  assert.equal(duplicateExit, 0);
  assert.deepEqual(await fetch(`http://127.0.0.1:${enginePort}/health`).then(response => response.json()), identity);
  console.log('Duplicate launch exited; original engine identity preserved');

  // Reproduce an existing installation which has a PWA worker and shell cache.
  await page.evaluate(async () => {
    localStorage.setItem('native-upgrade-probe', 'keep preferences');
    await caches.open('native-upgrade-keep');
    await navigator.serviceWorker.register('/sw.js');
    await navigator.serviceWorker.ready;
    await caches.open(`doona-shell:${location.origin}/:previous-build`);
  });
  await page.waitForFunction(() => !!navigator.serviceWorker.controller);
  console.log('Previous desktop worker/cache installed in isolated test profile');
}, 20000);

await run(async page => {
  await page.locator('.rp-top .rp-brand').waitFor();
  await page.waitForFunction(async () =>
    !navigator.serviceWorker.controller && (await navigator.serviceWorker.getRegistrations()).length === 0
  );
  const state = await page.evaluate(async () => ({
    keys: await caches.keys(),
    preference: localStorage.getItem('native-upgrade-probe'),
    brand: document.querySelector('.rp-brand')?.textContent
  }));
  assert.equal(state.brand, 'LemonVPN');
  assert.equal(state.preference, 'keep preferences');
  assert.ok(state.keys.includes('native-upgrade-keep'));
  assert.ok(!state.keys.some(key => key.startsWith('doona-shell:')));
  assert.deepEqual(await page.evaluate(() => window.__TAURI__.core.invoke('proxy_status')), proxyBefore);
  console.log('Native upgrade migration passed:', JSON.stringify(state));
});
console.log('Native UI and upgrade checks passed. Isolated data:', folder);

await run(async (page, enginePort, child) => {
  await page.locator('.rp-top .rp-brand').waitFor();
  const identity = await fetch(`http://127.0.0.1:${enginePort}/health`).then(response => response.json());
  const pending = [];
  try {
    // Empty/preconnected sockets and partial HTTP/SOCKS5 handshakes must not
    // hold the watchdog inside a long request timeout after its parent exits.
    for (const payload of ['', 'GET /api/v1/runtime HTTP/1.1\r\n', '\x05']) {
      const socket = createConnection({host: '127.0.0.1', port: enginePort});
      socket.on('error', () => {});
      pending.push(socket);
      await new Promise((resolve, reject) => { socket.once('connect', resolve); socket.once('error', reject); });
      if (payload) socket.write(payload);
    }
    await new Promise(resolve => setTimeout(resolve, 100));
    child.kill(); // Terminate only the isolated test host, as a Task Manager crash.
    const deadline = Date.now() + 6000;
    while (true) {
      try { process.kill(identity.pid, 0); } catch { break; }
      assert.ok(Date.now() < deadline, 'Sidecar survived its terminated desktop parent');
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    let listening = false;
    try { listening = (await fetch(`http://127.0.0.1:${enginePort}/health`)).ok; } catch { /* expected */ }
    assert.equal(listening, false);
    console.log('Terminated host: watchdog stopped sidecar, idle/partial handshakes and listener');
  } finally {
    pending.forEach(socket => socket.destroy());
  }
}, 15000, 'terminated');
