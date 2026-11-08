// Fault the isolated upstream, not the user's adapter or installed VPN.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdtemp, writeFile} from 'node:fs/promises';
import {createConnection, createServer} from 'node:net';
import {tmpdir} from 'node:os';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const folder = await mkdtemp(join(tmpdir(), 'lemonvpn-recovery-'));
const serverSockets = new Set();
const clients = new Set();
let mode = 'online';
const origin = createServer(socket => {
  serverSockets.add(socket);
  socket.on('error', () => {});
  socket.on('close', () => serverSockets.delete(socket));
  socket.on('data', bytes => { if (mode === 'online') socket.write(bytes); });
});
await new Promise(resolve => origin.listen(0, '127.0.0.1', resolve));
const target = origin.address().port;
const engine = spawn(join(root, 'app/src-tauri/binaries/lemonvpn-engine-stub-x86_64-pc-windows-msvc.exe'), [], {
  windowsHide: true, env: {...process.env, LEMONVPN_ENGINE_PORT: '0', LEMONVPN_DATA_DIR: folder, LEMONVPN_PARENT_PID: String(process.pid)}
});
let logs = '', port;
engine.stderr.on('data', data => { logs += data; port ??= /listening on http:\/\/127\.0\.0\.1:(\d+)/.exec(logs)?.[1]; });
const exited = new Promise(resolve => engine.on('exit', resolve));
const results = [];
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

function read(socket, length, header = false) {
  return new Promise((resolve, reject) => {
    let data = Buffer.alloc(0);
    const cleanup = () => { clearTimeout(timer); socket.off('data', collect); socket.off('error', fail); socket.off('end', ended); };
    const fail = error => { cleanup(); reject(error); };
    const ended = () => fail(new Error('Unexpected EOF'));
    const collect = chunk => {
      data = Buffer.concat([data, chunk]);
      if (header ? data.includes('\r\n\r\n') : data.length >= length) { cleanup(); resolve(data); }
    };
    const timer = setTimeout(() => fail(new Error('Echo timeout')), 3000);
    socket.on('data', collect); socket.once('error', fail); socket.once('end', ended);
  });
}
async function connect(socks = false) {
  const socket = createConnection({host: '127.0.0.1', port: Number(port), allowHalfOpen: true});
  clients.add(socket); socket.on('error', () => {}); socket.on('close', () => clients.delete(socket));
  await new Promise((resolve, reject) => { socket.once('connect', resolve); socket.once('error', reject); });
  if (socks) {
    let reply = read(socket, 2); socket.write(Buffer.from([5, 1, 0])); assert.deepEqual(await reply, Buffer.from([5, 0]));
    reply = read(socket, 10); socket.write(Buffer.from([5, 1, 0, 1, 127, 0, 0, 1, target >> 8, target & 255]));
    assert.equal((await reply)[1], 0);
  } else {
    const reply = read(socket, 0, true);
    socket.write(`CONNECT 127.0.0.1:${target} HTTP/1.1\r\nHost: localhost\r\n\r\n`);
    assert.match((await reply).toString(), /^HTTP\/1.1 200/);
  }
  return socket;
}
async function echo(socket, text) {
  const response = read(socket, Buffer.byteLength(text)); socket.write(text);
  assert.equal((await response).toString(), text);
}
const api = async (path, method = 'GET') => {
  const response = await fetch(`http://127.0.0.1:${port}/api/v1/${path}`, {method, signal: AbortSignal.timeout(2000)});
  assert.ok(response.ok, `${method} ${path}: ${response.status}`);
  return response.status === 204 ? null : response.json();
};
async function noConnections(timeout = 2000) {
  const deadline = Date.now() + timeout;
  do {
    const runtime = await api('runtime');
    if (Number(runtime.traffic?.connections?.tcp ?? -1) === 0) return;
    await pause(100);
  } while (Date.now() < deadline);
  throw new Error('Tunnel workers did not drain: ' + JSON.stringify(await api('runtime')));
}
try {
  const deadline = Date.now() + 8000;
  while (!port) { assert.ok(Date.now() < deadline, logs); await pause(50); }
  for (const socks of [false, true]) {
    const socket = await connect(socks); await echo(socket, 'before outage');
    mode = 'offline'; serverSockets.forEach(socket => socket.destroy());
    const started = Date.now();
    await api('desktop/status');
    assert.ok(Date.now() - started < 1500, 'API stalled during upstream outage');
    await pause(300); mode = 'online';
    const resumed = await connect(socks); await echo(resumed, 'after outage'); resumed.destroy(); socket.destroy();
    results.push({case: socks ? 'SOCKS5 upstream disconnect/reconnect' : 'HTTP upstream disconnect/reconnect', passed: true});
  }
  await noConnections();
  // A silent connection survives a period without upstream replies, then
  // resumes using the same socket, as after a brief scheduler/network pause.
  const idle = await connect(); await echo(idle, 'before idle');
  mode = 'blackhole'; await pause(5000); mode = 'online';
  await echo(idle, 'after idle'); idle.destroy(); await noConnections();
  results.push({case: 'five-second silent upstream pause/resume', passed: true});

  // Keep the client write side open to catch forced-close leaks hidden by
  // Node's default automatic FIN. The API must finish the worker itself.
  const held = await connect(); await echo(held, 'force close while half open');
  const rows = await api('connections');
  const row = (rows.tcp ?? rows.connections ?? rows.items ?? [])[0];
  assert.ok(row?.id, 'Expected one live connection');
  await api(`connections/${encodeURIComponent(row.id)}`, 'DELETE');
  await noConnections();
  held.destroy();
  results.push({case: 'forced close with half-open client drains worker', passed: true});
  const report = {passed: true, results, isolatedData: folder};
  await writeFile(join(folder, 'report.json'), JSON.stringify(report, null, 2));
  console.log(JSON.stringify(report));
} finally {
  clients.forEach(socket => socket.destroy()); serverSockets.forEach(socket => socket.destroy());
  await new Promise(resolve => origin.close(resolve));
  engine.kill(); await exited;
}
