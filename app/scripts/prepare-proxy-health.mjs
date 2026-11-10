// Keep local desktop builds and a clean pinned frontend checkout identical.
import {spawnSync} from 'node:child_process';
import {resolve, dirname} from 'node:path';
import {fileURLToPath} from 'node:url';

export function prepareProxyHealth(frontendDir) {
  const patch = resolve(dirname(fileURLToPath(import.meta.url)), '../../patches/doona-lemonvpn-proxy-health.patch');
  const git = args => spawnSync('git', ['apply', ...args, patch], {cwd: frontendDir, encoding: 'utf8'});
  if (git(['--reverse', '--check']).status === 0) return;
  const checked = git(['--check']);
  if (checked.error || checked.status !== 0) {
    throw new Error(`Cannot apply proxy-health patch; apply the pinned desktop patch first and preserve local edits.\n${checked.stderr ?? ''}`);
  }
  const applied = git(['--whitespace=nowarn']);
  if (applied.error || applied.status !== 0) throw new Error('Proxy-health patch could not be applied');
}
