import assert from 'node:assert/strict';
import {join} from 'node:path';
import test from 'node:test';
import {sidecarLayout, verifyPeMachine, wintunTarget} from './engine-artifacts.mjs';

for (const triple of ['x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc', 'aarch64-apple-darwin', 'x86_64-unknown-linux-gnu']) {
  test(`artifact and sidecar name use the target: ${triple}`, () => {
    const extension = triple.includes('windows') ? '.exe' : '';
    const layout = sidecarLayout('target-output', triple);
    assert.equal(layout.artifact, join('target-output', triple, 'release', `lemonvpn-engine-stub${extension}`));
    assert.equal(layout.bundledName, `lemonvpn-engine-stub-${triple}${extension}`);
  });
}

test('Wintun selection follows the target CPU', () => {
  assert.equal(wintunTarget('x86_64-pc-windows-msvc').directory, 'amd64');
  assert.equal(wintunTarget('aarch64-pc-windows-msvc').directory, 'arm64');
  assert.equal(wintunTarget('aarch64-apple-darwin'), null);
});

test('rejects a mislabeled or corrupt DLL', () => {
  const bytes = Buffer.alloc(128);
  bytes.write('MZ');
  bytes.writeUInt32LE(64, 0x3c);
  bytes.writeUInt32LE(0x4550, 64);
  bytes.writeUInt16LE(0x8664, 68);
  assert.doesNotThrow(() => verifyPeMachine(bytes, 0x8664));
  assert.throws(() => verifyPeMachine(bytes, 0xaa64), /架构/);
  assert.throws(() => verifyPeMachine(Buffer.alloc(10), 0x8664), /PE/);
  bytes.writeUInt32LE(1000, 0x3c);
  assert.throws(() => verifyPeMachine(bytes, 0x8664), /PE/);
});

test('rejects universal or path-like targets instead of relabeling a host binary', () => {
  assert.throws(() => sidecarLayout('target', 'universal-apple-darwin'));
  assert.throws(() => sidecarLayout('target', '../release'));
});
