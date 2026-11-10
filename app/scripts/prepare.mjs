#!/usr/bin/env node
// Prepares everything `tauri build` embeds into the LemonVPN shell:
//
//   1. builds doona (pnpm --dir doona build) and copies its output to app/dist,
//      which is the frontendDist the shell loads instead of the 5173 dev server;
//   2. builds the engine sidecar in release mode and copies it to
//      app/src-tauri/binaries/lemonvpn-engine-stub-<target-triple>.exe, the name
//      Tauri 2's bundle.externalBin resolves.
//
// tauri.conf.json runs this as build.beforeBuildCommand, so `pnpm --dir app build`
// is enough on its own. It can also be run by hand: `node app/scripts/prepare.mjs`.
// Only Node's standard library is used, so the build installs nothing extra.

import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {kernelBinaryName, sidecarLayout, verifyPeMachine, wintunTarget} from './engine-artifacts.mjs';
import {prepareCompat} from './prepare-compat.mjs';
import {prepareGeodata} from './prepare-geodata.mjs';
import {prepareBranding} from './prepare-branding.mjs';
import {prepareProxyHealth} from './prepare-proxy-health.mjs';
import {prepareRulesDns, rulesDnsApplied} from './prepare-rules-dns.mjs';
import {prepareLanSharing} from './prepare-lan-sharing.mjs';

/** Sidecar binary name, without the target triple Tauri appends. */
const SIDECAR = 'lemonvpn-engine-stub';

const here = dirname(fileURLToPath(import.meta.url));
/** app/ */
const appDir = resolve(here, '..');
/** Repository root: app/.. */
const repoRoot = resolve(appDir, '..');
const doonaDir = join(repoRoot, 'doona');
const doonaDist = join(doonaDir, 'dist');
const appDist = join(appDir, 'dist');
const sidecarManifest = join(repoRoot, 'sidecar-stub', 'Cargo.toml');
const binariesDir = join(appDir, 'src-tauri', 'binaries');

/**
 * Tools the build needs. PATH is tried first; the fixed locations are the ones
 * this checkout is built on, where cargo and pnpm are not on PATH. Each can be
 * overridden with LEMONVPN_PNPM / LEMONVPN_CARGO.
 */
const KNOWN_LOCATIONS = {
  pnpm: ['D:\\volta\\pnpm.exe'],
  cargo: ['C:\\Users\\Lemon\\.cargo\\bin\\cargo.exe']
};

function exeName(base) {
  return process.platform === 'win32' ? `${base}.exe` : base;
}

/** First match of `name` on PATH, honouring PATHEXT on Windows. */
function onPath(name) {
  const exts =
    process.platform === 'win32'
      ? (process.env.PATHEXT ?? '.COM;.EXE;.BAT;.CMD').split(';').filter(Boolean)
      : [''];
  for (const dir of (process.env.PATH ?? '').split(process.platform === 'win32' ? ';' : ':').filter(Boolean)) {
    for (const ext of exts) {
      const candidate = join(dir, `${name}${ext}`);
      if (existsSync(candidate)) return candidate;
    }
  }
  return null;
}

function tool(name) {
  const override = process.env[`LEMONVPN_${name.toUpperCase()}`];
  if (override) return override;
  return onPath(name) ?? (KNOWN_LOCATIONS[name] ?? []).find(existsSync) ?? name;
}

function quote(value) {
  return /\s/.test(value) ? `"${value}"` : value;
}

/** Runs a command to completion, inheriting stdio, and fails the build on error. */
function run(command, args) {
  const line = [command, ...args].map(quote).join(' ');
  console.log(`[prepare] ${line}`);
  const result =
    process.platform === 'win32' && /\.(cmd|bat)$/i.test(command)
      ? spawnSync(line, {stdio: 'inherit', shell: true})
      : spawnSync(command, args, {stdio: 'inherit'});
  if (result.error) {
    throw new Error(`${command} 无法启动:${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new Error(`${command} 失败(退出码 ${result.status ?? 'unknown'})`);
  }
}

/**
 * doona's offline-shell plugin looks for a literal "<head>\n" in index.html, so a
 * Windows checkout with core.autocrlf=true (CRLF in the working tree) stops the
 * build at "index.html has no <head> to stamp the build on". Rewriting the file
 * with LF restores the bytes git has committed: `git -C doona diff --quiet
 * index.html` stays clean afterwards, and no source line changes.
 */
function normalizeEol(file) {
  if (!existsSync(file)) return false;
  const text = readFileSync(file, 'utf8');
  if (!text.includes('\r\n')) return false;
  writeFileSync(file, text.replace(/\r\n/g, '\n'), 'utf8');
  return true;
}

/** Target triple of the build, as Tauri 2 suffixes external binaries with it. */
function targetTriple(cargo) {
  const fromTauri = process.env.TAURI_ENV_TARGET_TRIPLE ?? process.env.CARGO_BUILD_TARGET;
  if (fromTauri) return fromTauri;

  const rustc = join(dirname(cargo), exeName('rustc'));
  const command = existsSync(rustc) ? rustc : 'rustc';
  const result = spawnSync(command, ['-vV'], {encoding: 'utf8'});
  const host = /^host:\s*(\S+)$/m.exec(result.stdout ?? '')?.[1];
  if (!host) {
    throw new Error(`无法从 ${command} -vV 读取 target triple;设置 TAURI_ENV_TARGET_TRIPLE 后重试`);
  }
  return host;
}

function prepareFrontend(pnpm) {
  if (!existsSync(join(doonaDir, 'src', 'desktop.ts'))) {
    throw new Error('doona 尚未应用桌面适配:按 README 使用 DOONA_DESKTOP_REVISION 和 doona-lemonvpn-desktop.patch');
  }
  // Later patches intentionally revise earlier hunks. Recognize the final
  // layer before checking earlier layers in an already prepared checkout.
  if (!rulesDnsApplied(doonaDir)) {
    prepareProxyHealth(doonaDir);
    prepareLanSharing(doonaDir);
    prepareRulesDns(doonaDir);
  }
  prepareBranding(doonaDir);
  if (!existsSync(join(doonaDir, 'node_modules'))) {
    throw new Error(`${doonaDir} 尚未安装依赖:先运行 pnpm --dir doona install`);
  }
  if (normalizeEol(join(doonaDir, 'index.html'))) {
    console.log('[prepare] doona/index.html 已从 CRLF 规范为 LF(内容与提交版本一致)');
  }

  run(pnpm, ['--dir', doonaDir, 'build']);

  if (!existsSync(join(doonaDist, 'index.html'))) {
    throw new Error(`doona 构建产物缺少 index.html:${doonaDist}`);
  }
  rmSync(appDist, {recursive: true, force: true});
  cpSync(doonaDist, appDist, {recursive: true});
  const files = readdirSync(appDist, {recursive: true}).length;
  console.log(`[prepare] 前端已复制到 ${appDist}(${files} 项)`);
}

async function prepareSidecar(cargo) {
  const triple = targetTriple(cargo);
  // Validate before invoking tools. The artifact must come from this exact
  // target directory; naming a host binary with a target suffix is unsafe.
  sidecarLayout('', triple);
  await prepareCompat(repoRoot, binariesDir, triple);
  await prepareGeodata(repoRoot, binariesDir);
  run(cargo, ['build', '--locked', '--release', '--bin', SIDECAR, '--target', triple, '--manifest-path', sidecarManifest]);
  const result = spawnSync(cargo, ['metadata', '--locked', '--format-version', '1', '--filter-platform', triple, '--manifest-path', sidecarManifest], {
    encoding: 'utf8', maxBuffer: 16 * 1024 * 1024
  });
  if (result.error || result.status !== 0) {
    throw new Error(`无法读取引擎依赖元数据:${result.error?.message ?? result.stderr}`);
  }
  const metadata = JSON.parse(result.stdout);
  const notices = [['zstd', 'LICENSE'], ['zstd-safe', 'LICENSE'], ['zstd-sys', 'LICENSE'], ['zstd-sys', 'zstd/LICENSE'], ['url', 'LICENSE-MIT']]
    .map(([name, relative]) => {
      const dependency = metadata.packages.find(pkg => pkg.name === name);
      if (!dependency) throw new Error(`Missing rule-resource dependency: ${name}`);
      return `${name} ${dependency.version} — ${relative}\n\n${readFileSync(join(dirname(dependency.manifest_path), relative), 'utf8')}`;
    }).join('\n\n----------------------------------------\n\n');
  writeFileSync(join(binariesDir, 'rules-dns.LICENSE.txt'), notices + '\n');
  const layout = sidecarLayout(metadata.target_directory, triple);
  const sidecarBinary = layout.artifact;

  if (!existsSync(sidecarBinary)) {
    throw new Error(`sidecar 构建产物不存在:${sidecarBinary}`);
  }
  const dest = join(binariesDir, layout.bundledName);
  mkdirSync(binariesDir, {recursive: true});
  cpSync(sidecarBinary, dest);
  for (const asset of ['geoip.dat', 'geosite.dat', 'geodata.manifest.json']) {
    cpSync(join(binariesDir, asset), join(dirname(sidecarBinary), asset));
  }
  if (triple.endsWith('-windows-msvc')) {
    run(cargo, ['build','--locked','--release','--package','lemonvpn-engine-platform','--bin','lemonvpn-service','--target',triple,'--manifest-path',sidecarManifest]);
    cpSync(join(dirname(sidecarBinary),'lemonvpn-service.exe'),join(binariesDir,'lemonvpn-service.exe'));
    cpSync(join(binariesDir,kernelBinaryName(triple)),join(dirname(sidecarBinary),kernelBinaryName(triple)));
  }
  if (triple.endsWith('-apple-darwin')) {
    // Dev runs load the kernel from the sidecar directory; the .app bundle
    // finds it in Contents/Resources via tauri.macos.conf.json. The TUN
    // service binary ships the same way for the LaunchDaemon install.
    run(cargo, ['build','--locked','--release','--package','lemonvpn-engine-platform','--bin','lemonvpn-service','--target',triple,'--manifest-path',sidecarManifest]);
    cpSync(join(dirname(sidecarBinary),'lemonvpn-service'),join(binariesDir,'lemonvpn-service'));
    cpSync(join(binariesDir,kernelBinaryName(triple)),join(dirname(sidecarBinary),kernelBinaryName(triple)));
  }
  if (triple.includes('-linux-')) {
    // Dev runs load the kernel from the sidecar directory; deb/appimage
    // bundles find it in /usr/lib/LemonVPN via tauri.linux.conf.json. The TUN
    // service binary ships the same way for the systemd install.
    run(cargo, ['build','--locked','--release','--package','lemonvpn-engine-platform','--bin','lemonvpn-service','--target',triple,'--manifest-path',sidecarManifest]);
    cpSync(join(dirname(sidecarBinary),'lemonvpn-service'),join(binariesDir,'lemonvpn-service'));
    cpSync(join(binariesDir,kernelBinaryName(triple)),join(dirname(sidecarBinary),kernelBinaryName(triple)));
  }
  console.log(`[prepare] sidecar 已复制到 ${dest}`);
  const wintun = wintunTarget(triple);
  if (wintun) {
    const dependency = metadata.packages.find(pkg => pkg.name === 'wintun');
    if (!dependency) throw new Error('引擎依赖中缺少 wintun');
    const driverRoot = join(dirname(dependency.manifest_path), 'wintun');
    const dll = join(driverRoot, 'bin', wintun.directory, 'wintun.dll');
    verifyPeMachine(readFileSync(dll), wintun.machine);
    if (triple === 'x86_64-pc-windows-msvc' || triple === 'aarch64-pc-windows-msvc') {
      const checksum=triple.startsWith('aarch64-')?'wintun-arm64.sha256':'wintun.sha256';
      const expected=readFileSync(join(repoRoot,'sidecar-stub/crates/engine-platform/assets',checksum),'utf8').trim();
      const actual=createHash('sha256').update(readFileSync(dll)).digest('hex');
      if(actual!==expected)throw new Error('Wintun DLL 与提权服务的固定摘要不一致');
    }
    cpSync(dll, join(binariesDir, 'wintun.dll'));
    cpSync(join(driverRoot, 'LICENSE.txt'), join(binariesDir, 'wintun.LICENSE.txt'));
    console.log(`[prepare] Wintun 驱动和许可证已准备(${wintun.directory})`);
  }
}

try {
  const pnpm = tool('pnpm');
  const cargo = tool('cargo');
  if (!process.argv.includes('--engine-only')) prepareFrontend(pnpm);
  await prepareSidecar(cargo);
  console.log('[prepare] 完成');
} catch (err) {
  console.error(`[prepare] 失败:${err.message}`);
  process.exit(1);
}
