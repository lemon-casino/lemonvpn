// CI orchestration only. Never starts LemonVPN, its kernel or its service.
import {
  appendFileSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { kernelBinaryName } from './engine-artifacts.mjs';
import { releaseTargets } from './release-targets.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const readJson = (path) => JSON.parse(readFileSync(path, 'utf8'));
const digest = (path) => createHash('sha256').update(readFileSync(path)).digest('hex');
const ensure = (condition, message) => {
  if (!condition) throw new Error(message);
};
const shaPattern = /^[a-f0-9]{64}$/;
const pins = () =>
  Object.fromEntries(
    readFileSync(join(root, 'pins.env'), 'utf8')
      .split(/\r?\n/)
      .filter((line) => /^[A-Z_0-9]+=/.test(line))
      .map((line) => {
        const at = line.indexOf('=');
        return [line.slice(0, at), line.slice(at + 1)];
      }),
  );

function command(executable, args, optional = false) {
  const result = spawnSync(executable, args, {
    cwd: root,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    timeout: 10 * 60 * 1000,
  });
  if (!optional && (result.error || result.status !== 0))
    throw new Error(`${executable} failed: ${result.error?.message ?? result.stderr ?? result.stdout}`);
  return result;
}

export function releaseVersion(tag) {
  ensure(typeof tag === 'string' && tag.length < 100, 'RELEASE_TAG is required');
  const match = /^v((?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*))?)$/.exec(
    tag,
  );
  ensure(match, 'Tag must be vX.Y.Z or vX.Y.Z-rc.N');
  ensure(
    !match[2]?.split('.').some((part) => /^0\d+$/.test(part)),
    'Numeric prerelease identifiers cannot have leading zeroes',
  );
  return { tag, version: match[1], prerelease: Boolean(match[2]) };
}

function releaseContext() {
  const context = releaseVersion(process.env.RELEASE_TAG);
  const sha = process.env.RELEASE_SHA || command('git', ['rev-parse', 'HEAD']).stdout.trim();
  ensure(/^[a-f0-9]{40}$/.test(sha), 'Invalid release commit');
  return { ...context, sha };
}

function output(values) {
  for (const [key, value] of Object.entries(values)) {
    const line = `${key}=${typeof value === 'string' ? value : JSON.stringify(value)}\n`;
    if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, line);
    else process.stdout.write(line);
  }
}

function prepare() {
  const context = releaseContext();
  const tagSha = command('git', ['rev-parse', '--verify', `refs/tags/${context.tag}^{commit}`]).stdout.trim();
  ensure(tagSha === context.sha, 'Checked-out commit does not match the existing version tag');
  const config = pins();
  ensure(/^[a-f0-9]{40}$/.test(config.DOONA_DESKTOP_REVISION ?? ''), 'Missing pinned desktop frontend revision');
  for (const target of releaseTargets) {
    const os = target.platform === 'windows' ? 'WINDOWS' : target.platform === 'macos' ? 'DARWIN' : 'LINUX';
    const arch = target.arch === 'x64' ? 'AMD64' : 'ARM64';
    ensure(
      shaPattern.test(config[`MIHOMO_${os}_${arch}_ASSET_SHA256`] ?? ''),
      `Missing official kernel archive SHA256 for ${target.id}`,
    );
  }
  ensure(existsSync(join(root, 'patches/doona-lemonvpn-desktop.patch')), 'Missing desktop frontend patch');
  output({ ...context, matrix: releaseTargets, doona_revision: config.DOONA_DESKTOP_REVISION });
}

function stamp() {
  const { version } = releaseContext();
  const jsonPath = join(root, 'app/src-tauri/tauri.conf.json');
  const config = readJson(jsonPath);
  config.version = version;
  writeFileSync(jsonPath, JSON.stringify(config, null, 2) + '\n');
  for (const [name, pattern] of [
    ['Cargo.toml', /(\[package\][\s\S]*?\r?\nversion\s*=\s*")[^"]+("\r?\n)/],
    ['Cargo.lock', /(\[\[package\]\]\r?\nname = "lemonvpn"\r?\nversion = ")[^"]+("\r?\n)/],
  ]) {
    const path = join(root, 'app/src-tauri', name);
    const text = readFileSync(path, 'utf8');
    ensure(pattern.test(text), `Cannot find shell version in ${name}`);
    writeFileSync(
      path,
      text.replace(pattern, (_, prefix, suffix) => prefix + version + suffix),
    );
  }
  console.log(`Stamped desktop version ${version} from the release tag`);
}

function verifyArchitecture(path, target) {
  const bytes = readFileSync(path);
  const arm = target.arch === 'arm64';
  if (target.platform === 'windows') {
    ensure(bytes.length >= 64 && bytes.toString('ascii', 0, 2) === 'MZ', `Invalid PE: ${path}`);
    const pe = bytes.readUInt32LE(0x3c);
    ensure(
      pe + 6 <= bytes.length &&
        bytes.readUInt32LE(pe) === 0x4550 &&
        bytes.readUInt16LE(pe + 4) === (arm ? 0xaa64 : 0x8664),
      `PE architecture mismatch: ${path}`,
    );
  } else if (target.platform === 'linux') {
    ensure(
      bytes.length >= 64 &&
        bytes.toString('ascii', 1, 4) === 'ELF' &&
        bytes[0] === 0x7f &&
        bytes[4] === 2 &&
        bytes[5] === 1 &&
        bytes.readUInt16LE(18) === (arm ? 183 : 62),
      `ELF architecture mismatch: ${path}`,
    );
  } else {
    ensure(
      bytes.length >= 32 &&
        bytes.readUInt32LE(0) === 0xfeedfacf &&
        bytes.readUInt32LE(4) === (arm ? 0x0100000c : 0x01000007),
      `Mach-O architecture mismatch: ${path}`,
    );
  }
}

function singlePackage(directory, extension, version) {
  const files = readdirSync(directory).filter((name) => name.endsWith(extension) && name.includes(version));
  ensure(files.length === 1, `Expected one ${extension} package for ${version} in ${directory}, got ${files.length}`);
  return join(directory, files[0]);
}

function collect() {
  const context = releaseContext();
  const target = releaseTargets.find((target) => target.target === process.env.BUILD_TARGET);
  ensure(target, 'Unknown BUILD_TARGET');
  ensure(command('git', ['rev-parse', 'HEAD']).stdout.trim() === context.sha, 'Build checkout changed');
  ensure(
    readJson(join(root, 'app/src-tauri/tauri.conf.json')).version === context.version,
    'Shell version was not stamped',
  );
  const output = join(root, 'output/release', target.id);
  mkdirSync(output, { recursive: true });
  ensure(readdirSync(output).length === 0, `Refusing to mix with old release files in ${output}`);
  const releaseDir = join(root, 'app/src-tauri/target', target.target, 'release');
  const binaries = join(root, 'app/src-tauri/binaries');
  const extension = target.platform === 'windows' ? '.exe' : '';
  const components = {};
  for (const [name, path] of [
    ['desktop', join(releaseDir, `lemonvpn${extension}`)],
    ['engine', join(binaries, `lemonvpn-engine-stub-${target.target}${extension}`)],
    ['kernel', join(binaries, kernelBinaryName(target.target))],
    ['service', join(binaries, `lemonvpn-service${extension}`)],
    ...(target.platform === 'windows' ? [['wintun', join(binaries, 'wintun.dll')]] : []),
  ]) {
    verifyArchitecture(path, target);
    components[name] = digest(path);
  }
  const upstream = readJson(join(binaries, 'mihomo.manifest.json'));
  ensure(
    upstream.binary === kernelBinaryName(target.target) && upstream.executableSha256 === components.kernel,
    'Kernel manifest differs from packaged executable',
  );
  const stem = `LemonVPN_${context.version}_${target.platform}_${target.arch}`;
  const artifacts = [];
  const record = (path) => artifacts.push({ name: basename(path), bytes: statSync(path).size, sha256: digest(path) });
  const copy = (source, suffix) => {
    const dest = join(output, stem + suffix);
    copyFileSync(source, dest);
    record(dest);
  };
  const bundles = join(releaseDir, 'bundle');
  if (target.platform === 'windows') copy(singlePackage(join(bundles, 'nsis'), '.exe', context.version), '_setup.exe');
  if (target.platform === 'linux') {
    copy(singlePackage(join(bundles, 'deb'), '.deb', context.version), '.deb');
    copy(singlePackage(join(bundles, 'appimage'), '.AppImage', context.version), '.AppImage');
  }
  if (target.platform === 'macos') {
    copy(singlePackage(join(bundles, 'dmg'), '.dmg', context.version), '.dmg');
    const app = join(bundles, 'macos/LemonVPN.app');
    ensure(statSync(app).isDirectory(), 'Missing macOS application bundle');
    const tar = join(output, stem + '.app.tar.gz');
    const result = spawnSync('tar', ['-czf', tar, '-C', dirname(app), basename(app)], {
      env: { ...process.env, COPYFILE_DISABLE: '1' },
      stdio: 'inherit',
    });
    ensure(!result.error && result.status === 0, 'Cannot archive macOS application bundle');
    record(tar);
  }
  const manifest = {
    ...context,
    target: target.target,
    platform: target.platform,
    arch: target.arch,
    unsigned: true,
    components,
    upstream,
    artifacts,
  };
  writeFileSync(join(output, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  writeFileSync(join(output, 'SHA256SUMS'), artifacts.map((file) => `${file.sha256}  ${file.name}\n`).join(''));
  console.log(`Collected ${target.id}: ${artifacts.map((file) => file.name).join(', ')}`);
}

function verifyRemoteTag(context) {
  const repo = process.env.GH_REPO;
  ensure(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo ?? ''), 'GH_REPO is required');
  let object = JSON.parse(
    command('gh', ['api', `repos/${repo}/git/ref/tags/${encodeURIComponent(context.tag)}`]).stdout,
  ).object;
  for (let depth = 0; object.type === 'tag' && depth < 8; depth++)
    object = JSON.parse(command('gh', ['api', `repos/${repo}/git/tags/${object.sha}`]).stdout).object;
  ensure(
    object.type === 'commit' && object.sha === context.sha,
    'Remote tag moved during the build; refusing to publish different sources',
  );
}

function reportPublished(context) {
  const url = command('gh', ['release', 'view', context.tag, '--json', 'url', '--jq', '.url']).stdout.trim();
  console.log(`Published ${url}`);
  if (process.env.GITHUB_STEP_SUMMARY)
    appendFileSync(
      process.env.GITHUB_STEP_SUMMARY,
      `Published [LemonVPN ${context.tag}](${url}) with all six targets and SHA256SUMS.\n`,
    );
}

function publish() {
  const context = releaseContext();
  const manifests = [];
  const uploads = [];
  const seen = new Set();
  for (const target of releaseTargets) {
    const directory = join(root, 'output/downloaded', `lemonvpn-${target.id}`);
    const manifest = readJson(join(directory, 'manifest.json'));
    ensure(
      manifest.tag === context.tag &&
        manifest.version === context.version &&
        manifest.sha === context.sha &&
        manifest.target === target.target &&
        manifest.platform === target.platform &&
        manifest.arch === target.arch &&
        manifest.unsigned === true,
      `Wrong build identity for ${target.id}`,
    );
    ensure(
      manifest.artifacts?.length === (target.platform === 'windows' ? 1 : 2),
      `Incomplete packages for ${target.id}`,
    );
    const suffixes =
      target.platform === 'windows'
        ? ['_setup.exe']
        : target.platform === 'macos'
          ? ['.dmg', '.app.tar.gz']
          : ['.deb', '.AppImage'];
    const expected = suffixes
      .map((suffix) => `LemonVPN_${context.version}_${target.platform}_${target.arch}${suffix}`)
      .sort();
    ensure(
      JSON.stringify(manifest.artifacts.map((file) => file.name).sort()) === JSON.stringify(expected),
      `Unexpected filenames for ${target.id}`,
    );
    for (const file of manifest.artifacts) {
      ensure(basename(file.name) === file.name && !seen.has(file.name), 'Duplicate or invalid release filename');
      const path = join(directory, file.name);
      ensure(
        shaPattern.test(file.sha256) && statSync(path).size === file.bytes && digest(path) === file.sha256,
        `Artifact integrity failure: ${file.name}`,
      );
      seen.add(file.name);
      uploads.push({ path, ...file });
    }
    manifests.push(manifest);
  }
  const directory = join(root, 'output/publish');
  mkdirSync(directory, { recursive: true });
  const provenance = join(directory, 'build-manifest.json');
  writeFileSync(provenance, JSON.stringify({ ...context, unsigned: true, builds: manifests }, null, 2) + '\n');
  uploads.push({ path: provenance, name: basename(provenance), sha256: digest(provenance) });
  const sums = join(directory, 'SHA256SUMS');
  writeFileSync(
    sums,
    uploads
      .toSorted((a, b) => a.name.localeCompare(b.name))
      .map((file) => `${file.sha256}  ${file.name}\n`)
      .join(''),
  );
  const notes = join(directory, 'release-notes.md');
  writeFileSync(
    notes,
    `LemonVPN ${context.tag}\n\nWindows、macOS、Linux，分别提供 x64 / ARM64 构建。\n\n- Windows：NSIS 安装包\n- macOS：DMG 与 .app.tar.gz\n- Linux：DEB 与 AppImage\n\n所有产物未签名；macOS 未公证。本次自动构建未运行测试。\n\n下载文件可通过 SHA256SUMS 核对；build-manifest.json 包含提交、目标架构和内核来源摘要。\n\nCommit: ${context.sha}\n`,
  );
  verifyRemoteTag(context);
  const existing = command('gh', ['release', 'view', context.tag, '--json', 'isDraft,tagName'], true);
  if (existing.error) throw existing.error;
  if (existing.status === 0) {
    if (JSON.parse(existing.stdout).isDraft !== true) {
      const publishedSums = join(directory, 'already-published-SHA256SUMS');
      command('gh', [
        'release',
        'download',
        context.tag,
        '--pattern',
        'SHA256SUMS',
        '--output',
        publishedSums,
        '--clobber',
      ]);
      ensure(
        readFileSync(publishedSums).equals(readFileSync(sums)),
        'This tag already has different published packages. Use a new tag instead of replacing them.',
      );
      reportPublished(context);
      return;
    }
    command('gh', [
      'release',
      'edit',
      context.tag,
      '--target',
      context.sha,
      '--title',
      `LemonVPN ${context.tag}`,
      '--notes-file',
      notes,
    ]);
  } else {
    command('gh', [
      'release',
      'create',
      context.tag,
      '--draft',
      '--verify-tag',
      '--target',
      context.sha,
      '--title',
      `LemonVPN ${context.tag}`,
      '--notes-file',
      notes,
    ]);
  }
  command('gh', ['release', 'upload', context.tag, ...uploads.map((file) => file.path), sums, '--clobber']);
  verifyRemoteTag(context);
  command('gh', [
    'release',
    'edit',
    context.tag,
    '--draft=false',
    `--prerelease=${context.prerelease}`,
    `--latest=${!context.prerelease}`,
  ]);
  reportPublished(context);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const action = { prepare, stamp, collect, publish }[process.argv[2]];
    ensure(action, 'Usage: node app/scripts/release.mjs prepare|stamp|collect|publish');
    action();
  } catch (error) {
    console.error(`[release] ${error.message}`);
    process.exitCode = 1;
  }
}
