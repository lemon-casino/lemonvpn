import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { appendFileSync, chmodSync, cpSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { download } from './download.mjs';

// Preseed only the disposable CI runner, never the installed application.
if (process.env.GITHUB_ACTIONS !== 'true') throw new Error('Bundler preparation is restricted to GitHub Actions.');
const app = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const pins = JSON.parse(readFileSync(join(app, 'scripts/bundler-tools.json'), 'utf8'));
const cli = JSON.parse(readFileSync(join(app, 'node_modules/@tauri-apps/cli/package.json'), 'utf8'));
if (cli.version !== pins.tauriCli) throw new Error('Update bundler tool pins for the installed Tauri CLI version.');
const assets = pins.assets.filter(
  (asset) => asset.platform === process.platform && ['all', process.arch].includes(asset.arch),
);
if (!assets.length) process.exit(0);
const metadata = spawnSync(
  'cargo',
  ['metadata', '--format-version', '1', '--no-deps', '--locked', '--manifest-path', join(app, 'src-tauri/Cargo.toml')],
  { encoding: 'utf8', windowsHide: true },
);
if (metadata.status !== 0) throw new Error(`Cannot locate Cargo tools directory: ${metadata.stderr}`);
const target = JSON.parse(metadata.stdout).target_directory;
const cache = join(target, 'bundler-cache');
const tools = join(target, '.tauri');
mkdirSync(cache, { recursive: true });
mkdirSync(tools, { recursive: true });
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
for (const asset of assets) {
  const cached = join(cache, `${asset.sha256}-${asset.name}`);
  let bytes = existsSync(cached) ? readFileSync(cached) : null;
  if (!bytes || sha256(bytes) !== asset.sha256) {
    bytes = await download(asset.url, { description: asset.name, sha256: asset.sha256 });
    writeFileSync(cached, bytes);
  }
  if (asset.archiveDirectory) {
    // Windows' bundled bsdtar extracts the already verified official NSIS ZIP.
    const unpack = join(cache, asset.sha256);
    mkdirSync(unpack, { recursive: true });
    const extracted = spawnSync(join(process.env.SystemRoot, 'System32/tar.exe'), ['-xf', cached, '-C', unpack], {
      windowsHide: true,
      encoding: 'utf8',
    });
    if (extracted.status !== 0) throw new Error(`Cannot extract ${asset.name}: ${extracted.stderr}`);
    cpSync(join(unpack, asset.archiveDirectory), join(tools, 'NSIS'), { recursive: true, force: true });
  } else {
    const destination = join(tools, asset.destination);
    mkdirSync(dirname(destination), { recursive: true });
    writeFileSync(destination, bytes);
    if (process.platform !== 'win32') chmodSync(destination, 0o755);
    if (asset.environment) appendFileSync(process.env.GITHUB_ENV, `${asset.environment}=${destination}\n`);
  }
  console.log(`[prepare] ${asset.name}: verified SHA256 and prepared packaging cache`);
}
