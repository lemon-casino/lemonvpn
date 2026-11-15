// Docker publication metadata only; never starts an app, kernel or container.
import { appendFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { releaseVersion } from './release.mjs';

const ensure = (condition, message) => {
  if (!condition) throw new Error(message);
};
const stable = /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

function gh(path, paginate = false) {
  const result = spawnSync('gh', ['api', ...(paginate ? ['--paginate', '--slurp'] : []), path], {
    encoding: 'utf8',
    timeout: 120_000,
    maxBuffer: 16 * 1024 * 1024,
  });
  ensure(!result.error && result.status === 0, `GitHub metadata request failed: ${result.error?.message || result.stderr}`);
  return JSON.parse(result.stdout);
}

function emit(key, value) {
  ensure(process.env.GITHUB_OUTPUT, 'GITHUB_OUTPUT is required');
  appendFileSync(process.env.GITHUB_OUTPUT, `${key}=${value}\n`);
}

try {
  const mode = process.argv[2];
  ensure(mode === 'verify' || mode === 'latest', 'Usage: node app/scripts/docker-release.mjs verify|latest');
  const { tag, prerelease } = releaseVersion(process.env.RELEASE_TAG);
  const sha = process.env.RELEASE_SHA;
  const repository = process.env.GITHUB_REPOSITORY;
  ensure(/^[a-f0-9]{40}$/.test(sha ?? ''), 'Invalid release commit');
  ensure(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository ?? ''), 'Invalid repository');

  // A tag can be moved while both architectures build. Never publish their
  // old digests under a tag which now points to a different commit.
  let object = gh(`repos/${repository}/git/ref/tags/${tag}`).object;
  for (let depth = 0; object.type === 'tag' && depth < 8; depth++) {
    object = gh(`repos/${repository}/git/tags/${object.sha}`).object;
  }
  ensure(object.type === 'commit' && object.sha === sha, 'Version tag changed during the build; publication stopped');

  let latest = false;
  if (mode === 'latest' && !prerelease) {
    const tags = gh(`repos/${repository}/tags?per_page=100`, true).flat();
    const versions = tags.map(({ name }) => stable.exec(name)).filter(Boolean);
    ensure(versions.some(([name]) => name === tag), 'Version tag disappeared');
    versions.sort((a, b) => {
      for (let part = 1; part <= 3; part++) {
        const left = BigInt(a[part]);
        const right = BigInt(b[part]);
        if (left !== right) return left > right ? -1 : 1;
      }
      return 0;
    });
    latest = versions[0][0] === tag;
  }
  emit('latest', latest);
  console.log(`${tag}: commit verified${mode === 'latest' ? (latest ? '; latest may be updated' : '; latest retained') : ''}`);
} catch (error) {
  console.error(`[docker-release] ${error.message}`);
  process.exitCode = 1;
}
