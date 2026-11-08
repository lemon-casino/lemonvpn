import {join} from 'node:path';

const SIDECAR = 'lemonvpn-engine-stub';

export function kernelBinaryName(triple) {
  if (triple.includes('-windows-')) return 'lemonvpn-kernel.exe';
  if (triple.endsWith('-apple-darwin') || triple.includes('-linux-')) return 'lemonvpn-kernel';
  throw new Error(`尚未支持的代理内核目标 ${triple}`);
}

export function sidecarLayout(targetDirectory, triple) {
  if (!/^[a-z0-9_]+(?:-[a-z0-9_]+){2,}$/.test(triple) || triple.startsWith('universal-')) {
    throw new Error(`不支持的引擎构建目标 ${triple};请分别构建具体 CPU 架构`);
  }
  const extension = triple.includes('-windows-') ? '.exe' : '';
  return {
    artifact: join(targetDirectory, triple, 'release', `${SIDECAR}${extension}`),
    bundledName: `${SIDECAR}-${triple}${extension}`
  };
}

export function wintunTarget(triple) {
  if (!triple.includes('-windows-')) return null;
  const targets = {
    x86_64: {directory: 'amd64', machine: 0x8664},
    aarch64: {directory: 'arm64', machine: 0xaa64},
    i686: {directory: 'x86', machine: 0x14c}
  };
  const target = targets[triple.split('-')[0]];
  if (!target) throw new Error(`没有适配 ${triple} 的 Wintun DLL`);
  return target;
}

export function verifyPeMachine(bytes, machine) {
  if (bytes.length < 64 || bytes.toString('ascii', 0, 2) !== 'MZ') {
    throw new Error('Wintun DLL 缺少有效的 PE 文件头');
  }
  const offset = bytes.readUInt32LE(0x3c);
  if (offset + 6 > bytes.length || bytes.readUInt32LE(offset) !== 0x4550) {
    throw new Error('Wintun DLL 的 PE 文件头损坏');
  }
  if (bytes.readUInt16LE(offset + 4) !== machine) {
    throw new Error('Wintun DLL 架构与引擎目标架构不匹配');
  }
}
