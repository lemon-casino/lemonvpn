// Download only; never execute the third-party core during preparation/build.
import {createHash} from 'node:crypto';
import {existsSync, mkdirSync, readFileSync, writeFileSync, copyFileSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {spawnSync} from 'node:child_process';
import {kernelBinaryName} from './engine-artifacts.mjs';
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const psQuote=s=>`'${s.replaceAll("'","''")}'`;
export async function prepareCompat(repoRoot,binaries,triple){
  if(!triple.endsWith('windows-msvc')) return;
  if(triple!=='x86_64-pc-windows-msvc') throw new Error('本轮仅构建 Windows x64；ARM64 兼容内核打包延后。');
  const pins=Object.fromEntries(readFileSync(join(repoRoot,'pins.env'),'utf8').split(/\r?\n/).filter(line=>/^[A-Z_0-9]+=/.test(line)).map(line=>line.split('=',2)));
  const version=pins.MIHOMO_VERSION;
  const zipSha=pins.MIHOMO_WINDOWS_AMD64_ASSET_SHA256;
  if(!/^v\d+\.\d+\.\d+$/.test(version??'')||!/^[a-f0-9]{64}$/.test(zipSha??''))throw new Error('pins.env 缺少有效的 mihomo 固定版本与 SHA256');
  const asset=`mihomo-windows-amd64-compatible-${version}.zip`;
  const cache=resolve(repoRoot,'app/src-tauri/target/compat-cache',version);
  mkdirSync(cache,{recursive:true});mkdirSync(binaries,{recursive:true});
  const archive=join(cache,asset);
  if(!existsSync(archive)||hash(readFileSync(archive))!==zipSha){
    const response=await fetch(`https://github.com/MetaCubeX/mihomo/releases/download/${version}/${asset}`);
    if(!response.ok)throw new Error(`下载 mihomo 失败: HTTP ${response.status}`);
    const bytes=Buffer.from(await response.arrayBuffer());
    if(hash(bytes)!==zipSha)throw new Error('mihomo 官方发布包 SHA256 不匹配');
    writeFileSync(archive,bytes);
  }
  const destination=join(binaries,kernelBinaryName(triple));
  const command=`Add-Type -AssemblyName System.IO.Compression.FileSystem; $archiveHandle=[System.IO.Compression.ZipFile]::OpenRead(${psQuote(archive)}); try { $entries=@($archiveHandle.Entries | Where-Object { $_.Name -like 'mihomo*.exe' }); if ($entries.Count -ne 1) { throw 'Unexpected mihomo archive entries' }; $sourceStream=$entries[0].Open(); try { $targetStream=[System.IO.File]::Create(${psQuote(destination)}); try { $sourceStream.CopyTo($targetStream) } finally { $targetStream.Dispose() } } finally { $sourceStream.Dispose() } } finally { $archiveHandle.Dispose() }`;
  const result=spawnSync('powershell.exe',['-NoProfile','-NonInteractive','-Command',command],{stdio:'inherit',windowsHide:true});
  if(result.status!==0)throw new Error('解压兼容内核失败');
  const licensePath=join(cache,'LICENSE');
  if(!existsSync(licensePath)){
    const response=await fetch(`https://raw.githubusercontent.com/MetaCubeX/mihomo/${version}/LICENSE`);
    if(!response.ok)throw new Error('缺少 mihomo GPL 许可证');writeFileSync(licensePath,await response.text());
  }
  copyFileSync(licensePath,join(binaries,'mihomo.LICENSE.txt'));
  const executableSha=hash(readFileSync(destination));
  writeFileSync(join(binaries,'mihomo.manifest.json'),JSON.stringify({project:'https://github.com/MetaCubeX/mihomo',version,binary:kernelBinaryName(triple),asset,archiveSha256:zipSha,executableSha256:executableSha,license:'GPL-3.0'},null,2)+'\n');
  // The privileged installer validates the exact pinned executable, independently
  // of the editable per-user resource directory.
  const assets=resolve(repoRoot,'sidecar-stub/crates/engine-platform/assets');mkdirSync(assets,{recursive:true});
  const checksumFile=join(assets,'mihomo.sha256');
  const checksumText=executableSha+'\n';
  if(!existsSync(checksumFile)||readFileSync(checksumFile,'utf8')!==checksumText)writeFileSync(checksumFile,checksumText);
  console.log(`[prepare] mihomo ${version} 已准备，发布包 SHA256 已核对`);
}
