// Official V2Ray assets, pinned and SHA256-verified. Download only.
import {createHash} from 'node:crypto';
import {copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync} from 'node:fs';
import {join} from 'node:path';

export async function prepareGeodata(root, binaries) {
  const pins = Object.fromEntries(readFileSync(join(root, 'pins.env'), 'utf8').split(/\r?\n/).filter(line => /^[A-Z_0-9]+=/.test(line)).map(line => {
    const at = line.indexOf('='); return [line.slice(0, at), line.slice(at + 1)];
  }));
  const cache = join(root, 'app/src-tauri/target/geodata-cache');
  mkdirSync(cache, {recursive: true}); mkdirSync(binaries, {recursive: true});
  const assets = [];
  for (const kind of ['geoip', 'geosite']) {
    const url = pins[`${kind.toUpperCase()}_URL`], expected = pins[`${kind.toUpperCase()}_SHA256`];
    if (!/^https:\/\/github\.com\/v2fly\//.test(url ?? '') || !/^[a-f0-9]{64}$/.test(expected ?? '')) throw new Error(`缺少 ${kind} 固定来源与 SHA256`);
    const cached = join(cache, `${expected}.dat`);
    const digest = bytes => createHash('sha256').update(bytes).digest('hex');
    if (!existsSync(cached) || digest(readFileSync(cached)) !== expected) {
      const response = await fetch(url, {signal: AbortSignal.timeout(120000)});
      if (!response.ok) throw new Error(`${kind} 下载失败: HTTP ${response.status}`);
      const bytes = Buffer.from(await response.arrayBuffer());
      if (bytes.length > 64 * 1024 * 1024 || digest(bytes) !== expected) throw new Error(`${kind} SHA256 不匹配`);
      writeFileSync(cached, bytes);
    }
    copyFileSync(cached, join(binaries, `${kind}.dat`));
    const license = join(binaries, `${kind}.LICENSE.txt`);
    const licenseSha = pins[`${kind.toUpperCase()}_LICENSE_SHA256`];
    if (!/^[a-f0-9]{64}$/.test(licenseSha ?? '')) throw new Error(`${kind} 缺少许可证摘要`);
    if (!existsSync(license) || digest(readFileSync(license)) !== licenseSha) {
      const response = await fetch(pins[`${kind.toUpperCase()}_LICENSE_URL`], {signal: AbortSignal.timeout(30000)});
      if (!response.ok) throw new Error(`${kind} 许可证下载失败`);
      const bytes = Buffer.from(await response.arrayBuffer());
      if (digest(bytes) !== licenseSha) throw new Error(`${kind} 许可证 SHA256 不匹配`);
      writeFileSync(license, bytes);
    }

    assets.push({kind, url, sha256: expected, binary: `${kind}.dat`, license: `${kind}.LICENSE.txt`, licenseSha256: licenseSha, modified: false, size: readFileSync(cached).length});
  }
  writeFileSync(join(binaries, 'geodata.manifest.json'), JSON.stringify({assets}, null, 2) + '\n');
  console.log('[prepare] GeoIP/GeoSite 官方数据 SHA256 已核对');
}
