// Connect to the native /32 recovery fixture without taking over default routes.
import assert from 'node:assert/strict';
import {appendFile, readFile, writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {createConnection} from 'node:net';
import {createSocket} from 'node:dgram';
import {lookup} from 'node:dns/promises';
import {connect as connectTls} from 'node:tls';

const directory = process.argv[2], phase = process.argv[3] ?? 'probe';
const expectOffline = process.argv.includes('--expect-offline');
const fixture = JSON.parse(await readFile(join(directory, 'ready.json'), 'utf8'));
const report = {at: new Date().toISOString(), phase, pid: fixture.pid, passed: false};
function receive(socket, complete, timeout = 10000) {
  return new Promise((resolve, reject) => {
    let data = Buffer.alloc(0);
    const clean = () => { clearTimeout(timer); socket.off('data', collect); socket.off('error', fail); socket.off('end', ended); };
    const fail = error => { clean(); reject(error); };
    const ended = () => fail(new Error('Unexpected EOF'));
    const collect = chunk => { data = Buffer.concat([data, chunk]); if (complete(data)) { clean(); resolve(data); } };
    const timer = setTimeout(() => fail(new Error('Probe IO deadline exceeded')), timeout);
    socket.on('data', collect); socket.once('error', fail); socket.once('end', ended);
  });
}
async function tcp(target, port) {
  const socket = createConnection({host: target, port}); socket.on('error', () => {});
  const timer = setTimeout(() => socket.destroy(new Error('Probe connect timed out')), 10000);
  try { await new Promise((resolve, reject) => { socket.once('connect', resolve); socket.once('error', reject); }); return socket; }
  finally { clearTimeout(timer); }
}
try {
  const endpoint = `http://127.0.0.1:${fixture.port}`;
  const identity = await fetch(endpoint + '/health').then(response => response.json());
  assert.equal(identity.pid, fixture.pid);
  const status = await fetch(endpoint + '/api/v1/desktop/status').then(response => response.json());
  assert.equal(status.tun.enabled, true); assert.equal(status.tun.adapter, fixture.adapter);
  const capture = await tcp(fixture.target, 18081);
  try { const echo = receive(capture, bytes => bytes.length >= 16); capture.write('native recovery!'); assert.equal((await echo).toString(), 'native recovery!'); }
  finally { capture.destroy(); }
  report.tunTcpEcho = true;

  const dns = createSocket('udp4');
  try {
    const query = Buffer.from([0x12,0x34,1,0,0,1,0,0,0,0,0,0,3,49,50,55,1,48,1,48,1,49,0,0,1,0,1]);
    const answer = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Native TUN DNS timed out')), 5000);
      dns.once('error', error => { clearTimeout(timer); reject(error); });
      dns.once('message', bytes => { clearTimeout(timer); resolve(bytes); }); dns.send(query, 53, fixture.target);
    });
    assert.equal(answer.readUInt16BE(0), 0x1234); assert.ok(answer[2] & 0x80); assert.deepEqual(answer.subarray(-4), Buffer.from([127,0,0,1]));
  } finally { dns.close(); }
  report.tunUdpDns = true;

  // An IPv4 literal guarantees IP_UNICAST_IF is exercised while TUN is active;
  // resolving/connecting via IPv6 would skip the Windows physical binding.
  const {address} = expectOffline
    ? JSON.parse(await readFile(join(directory, 'public-target.json'), 'utf8'))
    : await lookup('example.com', {family: 4});
  if (!expectOffline) await writeFile(join(directory, 'public-target.json'), JSON.stringify({address}));
  const socket = await tcp('127.0.0.1', fixture.port);
  let tls;
  try {
    const connected = receive(socket, bytes => bytes.includes('\r\n\r\n'));
    socket.write(`CONNECT ${address}:443 HTTP/1.1\r\nHost: ${address}:443\r\n\r\n`);
    const connectStatus = (await connected).toString().split('\r\n')[0];
    if (expectOffline) {
      assert.match(connectStatus, /^HTTP\/1.1 502/);
      report.physicalOfflineRejected = true;
    } else {
    assert.match(connectStatus, /^HTTP\/1.1 200/);
    tls = connectTls({socket, servername: 'example.com', ALPNProtocols: ['http/1.1']}); tls.on('error', () => {});
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('TUN physical TLS timed out')), 10000);
      tls.once('secureConnect', () => { clearTimeout(timer); resolve(); }); tls.once('error', error => { clearTimeout(timer); reject(error); });
    });
    const header = receive(tls, bytes => bytes.includes('\r\n\r\n'));
    tls.write('GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: LemonVPN-Recovery-Test\r\nConnection: close\r\n\r\n');
    report.publicStatus = (await header).toString().split('\r\n')[0]; assert.match(report.publicStatus, /^HTTP\/1\.[01] [23]\d\d/);
    report.physicalIpv4 = true;
    }
  } finally { tls?.destroy(); socket.destroy(); }
  report.passed = true;
} catch (error) { report.error = String(error); process.exitCode = 1; }
await appendFile(join(directory, 'checks.jsonl'), JSON.stringify(report) + '\n');
console.log(JSON.stringify(report));
