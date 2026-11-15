// LAN DNS, IPv6 and nested outbound management build on rules/DNS.
import {spawnSync} from 'node:child_process';
import {resolve, dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
const patch = resolve(dirname(fileURLToPath(import.meta.url)), '../../patches/doona-lemonvpn-migration.patch');
const git = (frontendDir, args) => spawnSync('git', ['apply', ...args, patch], {cwd: frontendDir, encoding: 'utf8'});
export function migrationApplied(frontendDir) {
  return git(frontendDir, ['--reverse', '--check']).status === 0;
}
export function prepareMigration(frontendDir) {
  if (migrationApplied(frontendDir)) return;
  const checked = git(frontendDir, ['--check']);
  if (checked.status !== 0) throw new Error(`Cannot apply migration management patch.\n${checked.stderr ?? ''}`);
  const applied = git(frontendDir, ['--whitespace=nowarn']);
  if (applied.status !== 0) throw new Error(`Cannot apply migration management patch.\n${applied.stderr ?? ''}`);
}
