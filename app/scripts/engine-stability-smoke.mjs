// Short, entirely local workload: real release engine, HTTP/SOCKS5 echo,
// concurrent clients, upstream failures and recovery. No host proxy/routes.
import assert from 'node:assert/strict';
import {spawn, execFileSync} from 'node:child_process';
import {cp, mkdtemp, readFile, writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {createConnection, createServer} from 'node:net';
import {tmpdir} from 'node:os';
import {dirname, join, resolve, sep} from 'node:path';
import {fileURLToPath} from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const folder = await mkdtemp(join(tmpdir(), 'lemonvpn-workload-'));
const soakSeconds = Math.max(0, Math.min(86400, Number(process.argv[2] ?? 0) || 0));
const attachedPath = process.argv.find(arg => arg.startsWith('--host-report='))?.slice('--host-report='.length);
let attached;
if (attachedPath) {
  const path = resolve(attachedPath);
  assert.ok(path.startsWith(resolve(tmpdir()) + sep + 'lemonvpn-native-recovery-'), 'Only isolated native test hosts may be driven');
  attached = JSON.parse(await readFile(path, 'utf8'));
  assert.equal(resolve(attached.isolatedData), dirname(path));
  const identity = await fetch(`http://127.0.0.1:${attached.enginePort}/health`).then(response => response.json());
  assert.equal(identity.pid, attached.enginePid, 'The isolated engine identity changed');
}
const artifact = join(root, 'app/src-tauri/binaries/lemonvpn-engine-stub-x86_64-pc-windows-msvc.exe');
const snapshot = join(folder, 'lemonvpn-engine-stub.exe');
await cp(artifact, snapshot);
const artifactSha256 = attached?.engineSha256 ?? createHash('sha256').update(await readFile(snapshot)).digest('hex');
const startedAt = new Date().toISOString();
const processSamples = [];
const engine = attached ? null : spawn(snapshot, [], {
  windowsHide: true,
  env: {...process.env, LEMONVPN_ENGINE_PORT: '0', LEMONVPN_DATA_DIR: folder, LEMONVPN_PARENT_PID: String(process.pid)}
});
let port = attached?.enginePort;
let logs = '';
engine?.stderr.on('data', data => {
  logs += data;
  port ??= /listening on http:\/\/127\.0\.0\.1:(\d+)/.exec(logs)?.[1];
});
const exited = engine ? new Promise(resolve => engine.on('exit', resolve)) : Promise.resolve();
const enginePid = engine?.pid ?? attached.enginePid;
console.log(JSON.stringify({startedAt, enginePid, attachedHost: attached?.hostPid, soakSeconds, artifactSha256, isolatedData: folder}));
const echo = createServer(socket => { socket.on('error', () => {}); socket.pipe(socket); });
await new Promise(resolve => echo.listen(0, '127.0.0.1', resolve));
const target = echo.address().port;
const sockets = new Set();
function bytes(socket, length, header = false) {
  return new Promise((resolve, reject) => {
    let data = Buffer.alloc(0);
    const cleanup = () => { socket.off('data', collect); socket.off('error', failed); socket.off('close', closed); };
    const failed = error => { cleanup(); reject(error); };
    const closed = () => failed(new Error('Socket closed before response completed'));
    const collect = chunk => {
      data = Buffer.concat([data, chunk]);
      if (header ? data.includes('\r\n\r\n') : data.length >= length) { cleanup(); resolve(data); }
    };
    socket.on('data', collect); socket.once('error', failed); socket.once('close', closed);
  });
}
async function tunnel(index, refused = false) {
  const socket = createConnection({host: '127.0.0.1', port: Number(port)});
  sockets.add(socket);
  socket.setTimeout(7000, () => socket.destroy(new Error('Workload socket timeout')));
  socket.on('error', () => {});
  try {
    await new Promise((resolve, reject) => { socket.once('connect', resolve); socket.once('error', reject); });
    const targetPort = refused ? unavailablePort : target;
    if (index % 2 === 0) {
      const response = bytes(socket, 0, true);
      socket.write(`CONNECT 127.0.0.1:${targetPort} HTTP/1.1\r\nHost: 127.0.0.1:${targetPort}\r\n\r\n`);
      const header = (await response).toString();
      assert.match(header, refused ? /^HTTP\/1.1 502/ : /^HTTP\/1.1 200/);
    } else {
      const greeting = bytes(socket, 2);
      socket.write(Buffer.from([5, 1, 0]));
      assert.deepEqual(await greeting, Buffer.from([5, 0]));
      const response = bytes(socket, 10);
      socket.write(Buffer.from([5, 1, 0, 1, 127, 0, 0, 1, targetPort >> 8, targetPort & 255]));
      const reply = await response;
      assert.equal(reply[1] === 0, !refused);
    }
    if (!refused) {
      const payload = Buffer.alloc(65536, index % 251);
      const response = bytes(socket, payload.length);
      socket.write(payload);
      assert.deepEqual(await response, payload);
    }
  } finally { socket.destroy(); sockets.delete(socket); }
}
const closed = createServer();
await new Promise(resolve => closed.listen(0, '127.0.0.1', resolve));
const unavailablePort = closed.address().port;
await new Promise(resolve => closed.close(resolve));
try {
  const deadline = Date.now() + 8000;
  while (!port) {
    assert.ok(Date.now() < deadline, `Engine startup timed out: ${logs}`);
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  const api = path => fetch(`http://127.0.0.1:${port}/api/v1/${path}`).then(response => response.json());
  const before = await api('desktop/status');
  for (let round = 0; round < 8; round++) {
    await Promise.all(Array.from({length: 32}, (_, index) => tunnel(round * 32 + index)));
  }
  await Promise.all(Array.from({length: 16}, (_, index) => tunnel(index, true)));
  await Promise.all(Array.from({length: 32}, (_, index) => tunnel(index)));
  let successfulEchoes = 288;
  const samples = [];
  const soakDeadline = Date.now() + soakSeconds * 1000;
  let lastReport = Date.now();
  while (Date.now() < soakDeadline) {
    await Promise.all(Array.from({length: 32}, (_, index) => tunnel(index)));
    successfulEchoes += 32;
    const snapshot = await api('desktop/status');
    samples.push({at: new Date().toISOString(), rss: Number(snapshot.memory.process.rss_bytes), privateBytes: Number(snapshot.memory.process.private_bytes)});
    if (Date.now() - lastReport >= 30000) {
      if (process.platform === 'win32') {
        const sample = JSON.parse(execFileSync('powershell.exe', ['-NoProfile', '-Command',
          `$p = Get-Process -Id ${enginePid} -ErrorAction Stop; [pscustomobject]@{handles=$p.HandleCount;threads=$p.Threads.Count;cpuSeconds=$p.TotalProcessorTime.TotalSeconds;privateBytes=$p.PrivateMemorySize64} | ConvertTo-Json -Compress`],
          {encoding: 'utf8', windowsHide: true}));
        processSamples.push({at: new Date().toISOString(), ...sample});
      }
      console.log(JSON.stringify({soakProgress: true, successfulEchoes, ...samples.at(-1)}));
      lastReport = Date.now();
    }
    // Limit connection churn so this check does not exhaust the machine's
    // shared Windows ephemeral-port range with loopback TIME_WAIT sockets.
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
  const after = await api('desktop/status');
  assert.ok(Number(after.memory.process.rss_bytes) > 0);
  if (processSamples.length >= 10) {
    const median = values => [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];
    const warmup = processSamples.slice(0, 5), tail = processSamples.slice(-5);
    assert.ok(median(tail.map(s => s.privateBytes)) <= median(warmup.map(s => s.privateBytes)) + 16 * 1024 * 1024, 'Private committed memory did not plateau');
    assert.ok(median(tail.map(s => s.handles)) <= median(warmup.map(s => s.handles)) + 32, 'Process handles accumulated');
    assert.ok(median(tail.map(s => s.threads)) <= median(warmup.map(s => s.threads)) + 8, 'Worker threads accumulated');
  }
  const report = {passed: true, startedAt, finishedAt: new Date().toISOString(), artifactSha256, enginePid, attachedHost: attached?.hostPid,
    concurrentClients: 32, successfulEchoes, refusedUpstreams: 16,
    echoedBytes: successfulEchoes * 65536, soakSeconds, rssSamples: samples.length, rssPeakSample: samples.length ? Math.max(...samples.map(sample => sample.rss)) : null,
    rssBefore: before.memory.process.rss_bytes, rssAfter: after.memory.process.rss_bytes,
    note: 'Bounded local soak; actual wall duration and samples are recorded, not a throughput benchmark', isolatedData: folder};
  await writeFile(join(folder, 'report.json'), JSON.stringify({...report, samples, processSamples}, null, 2));
  console.log(JSON.stringify(report));
} finally {
  for (const socket of sockets) socket.destroy();
  await new Promise(resolve => echo.close(resolve));
  engine?.kill(); await exited;
}
