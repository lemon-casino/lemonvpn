// Download only; never execute the third-party core during preparation/build.
import {createHash} from 'node:crypto';
import {chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {spawnSync} from 'node:child_process';
import {gunzipSync} from 'node:zlib';
import {kernelBinaryName, verifyPeMachine} from './engine-artifacts.mjs';
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const psQuote=s=>`'${s.replaceAll("'","''")}'`;
const loadPins=repoRoot=>Object.fromEntries(readFileSync(join(repoRoot,'pins.env'),'utf8').split(/\r?\n/).filter(line=>/^[A-Z_0-9]+=/.test(line)).map(line=>line.split('=',2)));
async function fetchPinned(cache,version,asset,assetSha){
  mkdirSync(cache,{recursive:true});
  const archive=join(cache,asset);
  if(!existsSync(archive)||hash(readFileSync(archive))!==assetSha){
    const response=await fetch(`https://github.com/MetaCubeX/mihomo/releases/download/${version}/${asset}`,{signal:AbortSignal.timeout(600000)});
    if(!response.ok)throw new Error(`下载 mihomo 失败: HTTP ${response.status}`);
    const bytes=Buffer.from(await response.arrayBuffer());
    if(hash(bytes)!==assetSha)throw new Error('mihomo 官方发布包 SHA256 不匹配');
    writeFileSync(archive,bytes);
  }
  return archive;
}
async function fetchLicense(cache,version,binaries){
  const licensePath=join(cache,'LICENSE');
  if(!existsSync(licensePath)){
    const response=await fetch(`https://raw.githubusercontent.com/MetaCubeX/mihomo/${version}/LICENSE`,{signal:AbortSignal.timeout(60000)});
    if(!response.ok)throw new Error('缺少 mihomo GPL 许可证');
    writeFileSync(licensePath,await response.text());
  }
  copyFileSync(licensePath,join(binaries,'mihomo.LICENSE.txt'));
}
export async function prepareCompat(repoRoot,binaries,triple){
  if(triple.endsWith('-apple-darwin'))return prepareDarwinKernel(repoRoot,binaries,triple);
  if(triple.includes('-linux-'))return prepareLinuxKernel(repoRoot,binaries,triple);
  if(!triple.endsWith('windows-msvc'))return;
  const arch=triple==='x86_64-pc-windows-msvc'?'amd64':triple==='aarch64-pc-windows-msvc'?'arm64':null;
  if(!arch)throw new Error(`尚未支持的 Windows 内核目标 ${triple}`);
  const pins=loadPins(repoRoot);
  const version=pins.MIHOMO_VERSION;
  const zipSha=pins[`MIHOMO_WINDOWS_${arch.toUpperCase()}_ASSET_SHA256`];
  if(!/^v\d+\.\d+\.\d+$/.test(version??'')||!/^[a-f0-9]{64}$/.test(zipSha??''))throw new Error('pins.env 缺少有效的 mihomo 固定版本与 SHA256');
  const asset=arch==='amd64'?`mihomo-windows-amd64-compatible-${version}.zip`:`mihomo-windows-arm64-${version}.zip`;
  const cache=resolve(repoRoot,'app/src-tauri/target/compat-cache',version);
  mkdirSync(binaries,{recursive:true});
  const archive=await fetchPinned(cache,version,asset,zipSha);
  const destination=join(binaries,kernelBinaryName(triple));
  const command=`Add-Type -AssemblyName System.IO.Compression.FileSystem; $archiveHandle=[System.IO.Compression.ZipFile]::OpenRead(${psQuote(archive)}); try { $entries=@($archiveHandle.Entries | Where-Object { $_.Name -like 'mihomo*.exe' }); if ($entries.Count -ne 1) { throw 'Unexpected mihomo archive entries' }; $sourceStream=$entries[0].Open(); try { $targetStream=[System.IO.File]::Create(${psQuote(destination)}); try { $sourceStream.CopyTo($targetStream) } finally { $targetStream.Dispose() } } finally { $sourceStream.Dispose() } } finally { $archiveHandle.Dispose() }`;
  const result=spawnSync('powershell.exe',['-NoProfile','-NonInteractive','-Command',command],{stdio:'inherit',windowsHide:true});
  if(result.status!==0)throw new Error('解压兼容内核失败');
  verifyPeMachine(readFileSync(destination),arch==='arm64'?0xaa64:0x8664);
  await fetchLicense(cache,version,binaries);
  const executableSha=hash(readFileSync(destination));
  writeFileSync(join(binaries,'mihomo.manifest.json'),JSON.stringify({project:'https://github.com/MetaCubeX/mihomo',version,binary:kernelBinaryName(triple),asset,archiveSha256:zipSha,executableSha256:executableSha,license:'GPL-3.0'},null,2)+'\n');
  // The privileged installer validates the exact pinned executable, independently
  // of the editable per-user resource directory.
  const assets=resolve(repoRoot,'sidecar-stub/crates/engine-platform/assets');mkdirSync(assets,{recursive:true});
  const checksumFile=join(assets,arch==='arm64'?'mihomo-arm64.sha256':'mihomo.sha256');
  const checksumText=executableSha+'\n';
  if(!existsSync(checksumFile)||readFileSync(checksumFile,'utf8')!==checksumText)writeFileSync(checksumFile,checksumText);
  console.log(`[prepare] mihomo ${version} 已准备，发布包 SHA256 已核对`);
}

// macOS bundles the kernel as a plain executable: amd64 ships the broadest
// compatibility build, arm64 a single standard build, both gzip-compressed.
// The checksum file follows the build host's arch and is compiled into the
// macOS TUN service by prepare.mjs right after this step.
async function prepareDarwinKernel(repoRoot,binaries,triple){
  const pins=loadPins(repoRoot);
  const version=pins.MIHOMO_VERSION;
  const arch=triple.startsWith('aarch64-')?'arm64':triple.startsWith('x86_64-')?'amd64':null;
  if(!arch)throw new Error(`尚未支持的 Darwin 架构 ${triple}`);
  const pinKey=`MIHOMO_DARWIN_${arch.toUpperCase()}_ASSET_SHA256`;
  const assetSha=pins[pinKey];
  if(!/^v\d+\.\d+\.\d+$/.test(version??'')||!/^[a-f0-9]{64}$/.test(assetSha??''))throw new Error(`pins.env 缺少有效的 mihomo 固定版本与 ${pinKey}`);
  const asset=arch==='amd64'?`mihomo-darwin-amd64-compatible-${version}.gz`:`mihomo-darwin-arm64-${version}.gz`;
  const cache=resolve(repoRoot,'app/src-tauri/target/compat-cache',version);
  mkdirSync(binaries,{recursive:true});
  const archive=await fetchPinned(cache,version,asset,assetSha);
  const destination=join(binaries,kernelBinaryName(triple));
  writeFileSync(destination,gunzipSync(readFileSync(archive)));
  chmodSync(destination,0o755);
  await fetchLicense(cache,version,binaries);
  const executableSha=hash(readFileSync(destination));
  writeFileSync(join(binaries,'mihomo.manifest.json'),JSON.stringify({project:'https://github.com/MetaCubeX/mihomo',version,binary:kernelBinaryName(triple),asset,archiveSha256:assetSha,executableSha256:executableSha,license:'GPL-3.0'},null,2)+'\n');
  // The privileged macOS installer validates the exact pinned executable,
  // independently of the editable per-user resource directory.
  const assets=resolve(repoRoot,'sidecar-stub/crates/engine-platform/assets');mkdirSync(assets,{recursive:true});
  const checksumFile=join(assets,'mihomo-darwin.sha256');
  const checksumText=executableSha+'\n';
  if(!existsSync(checksumFile)||readFileSync(checksumFile,'utf8')!==checksumText)writeFileSync(checksumFile,checksumText);
  console.log(`[prepare] mihomo ${version}(${arch}) 已准备，发布包 SHA256 已核对`);
}
// Linux bundles the kernel as a plain gzip-compressed executable: amd64 ships
// the broadest-compatibility build, arm64 a single standard build. The
// checksum file follows the build host's arch and is compiled into the Linux
// TUN service by prepare.mjs right after this step.
async function prepareLinuxKernel(repoRoot,binaries,triple){
  const pins=loadPins(repoRoot);
  const version=pins.MIHOMO_VERSION;
  const arch=triple.startsWith('aarch64-')?'arm64':triple.startsWith('x86_64-')?'amd64':null;
  if(!arch)throw new Error(`尚未支持的 Linux 架构 ${triple}`);
  const pinKey=`MIHOMO_LINUX_${arch.toUpperCase()}_ASSET_SHA256`;
  const assetSha=pins[pinKey];
  if(!/^v\d+\.\d+\.\d+$/.test(version??'')||!/^[a-f0-9]{64}$/.test(assetSha??''))throw new Error(`pins.env 缺少有效的 mihomo 固定版本与 ${pinKey}`);
  const asset=arch==='amd64'?`mihomo-linux-amd64-compatible-${version}.gz`:`mihomo-linux-arm64-${version}.gz`;
  const cache=resolve(repoRoot,'app/src-tauri/target/compat-cache',version);
  mkdirSync(binaries,{recursive:true});
  const archive=await fetchPinned(cache,version,asset,assetSha);
  const destination=join(binaries,kernelBinaryName(triple));
  writeFileSync(destination,gunzipSync(readFileSync(archive)));
  chmodSync(destination,0o755);
  await fetchLicense(cache,version,binaries);
  const executableSha=hash(readFileSync(destination));
  writeFileSync(join(binaries,'mihomo.manifest.json'),JSON.stringify({project:'https://github.com/MetaCubeX/mihomo',version,binary:kernelBinaryName(triple),asset,archiveSha256:assetSha,executableSha256:executableSha,license:'GPL-3.0'},null,2)+'\n');
  // The privileged Linux installer validates the exact pinned executable,
  // independently of the editable per-user resource directory.
  const assets=resolve(repoRoot,'sidecar-stub/crates/engine-platform/assets');mkdirSync(assets,{recursive:true});
  const checksumFile=join(assets,`mihomo-linux-${arch}.sha256`);
  const checksumText=executableSha+'\n';
  if(!existsSync(checksumFile)||readFileSync(checksumFile,'utf8')!==checksumText)writeFileSync(checksumFile,checksumText);
  console.log(`[prepare] mihomo ${version}(${arch}) 已准备，发布包 SHA256 已核对`);
}
