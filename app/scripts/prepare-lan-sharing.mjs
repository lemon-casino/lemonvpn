// Apply the shared LAN UI after the desktop and proxy-health adaptations.
import {spawnSync} from 'node:child_process';
import {resolve, dirname} from 'node:path';
import {fileURLToPath} from 'node:url';

export function prepareLanSharing(frontendDir) {
  const patch = resolve(dirname(fileURLToPath(import.meta.url)), '../../patches/doona-lemonvpn-lan-sharing.patch');
  const git = args => spawnSync('git', ['apply', ...args, patch], {cwd: frontendDir, encoding: 'utf8'});
  if (git(['--reverse', '--check']).status === 0) return;
  const checked = git(['--check']);
  if (checked.error || checked.status !== 0) throw new Error(`Cannot apply LAN-sharing frontend patch. Preserve local edits and apply the desktop/proxy-health patches first.\n${checked.stderr ?? ''}`);
  const applied = git(['--whitespace=nowarn']);
  if (applied.error || applied.status !== 0) throw new Error('LAN-sharing frontend patch could not be applied');
}
