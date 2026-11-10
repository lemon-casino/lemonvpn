// The shared rule resources and DNS UI build on the desktop, proxy and LAN patches.
import {spawnSync} from 'node:child_process';
import {resolve, dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
export function rulesDnsApplied(frontendDir) {
  const patch = resolve(dirname(fileURLToPath(import.meta.url)), '../../patches/doona-lemonvpn-rules-dns.patch');
  return spawnSync('git', ['apply', '--reverse', '--check', patch], {cwd: frontendDir, encoding: 'utf8'}).status === 0;
}
export function prepareRulesDns(frontendDir) {
  const patch = resolve(dirname(fileURLToPath(import.meta.url)), '../../patches/doona-lemonvpn-rules-dns.patch');
  const git = args => spawnSync('git', ['apply', ...args, patch], {cwd: frontendDir, encoding: 'utf8'});
  if (git(['--reverse', '--check']).status === 0) return;
  const checked = git(['--check']);
  if (checked.error || checked.status !== 0) throw new Error(`Cannot apply rules/DNS UI patch after the desktop, proxy-health and LAN patches.\n${checked.stderr ?? ''}`);
  const applied = git(['--whitespace=nowarn']);
  if (applied.error || applied.status !== 0) throw new Error('Rules/DNS frontend patch could not be applied');
}
