import { createHash } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';

const permanent = (message) => Object.assign(new Error(message), { permanent: true });
function headers(url, binary = false) {
  const api = new URL(url).hostname === 'api.github.com';
  return {
    'User-Agent': 'LemonVPN-build',
    'Cache-Control': 'no-cache',
    ...(api
      ? {
          Accept: binary ? 'application/octet-stream' : 'application/vnd.github+json',
          ...(process.env.GITHUB_TOKEN ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {}),
        }
      : {}),
  };
}
async function assetApi(url) {
  const source = new URL(url);
  const match =
    source.hostname === 'github.com' && /^\/([^/]+)\/([^/]+)\/releases\/download\/([^/]+)\/(.+)$/.exec(source.pathname);
  if (!match) return null;
  const [, owner, repo, tag, name] = match;
  const metadata = `https://api.github.com/repos/${owner}/${repo}/releases/tags/${tag}`;
  const response = await fetch(metadata, {
    headers: headers(metadata),
    cache: 'no-store',
    signal: AbortSignal.timeout(30000),
  });
  if (!response.ok) throw new Error(`Release metadata: HTTP ${response.status}`);
  const value = await response.json();
  const asset = value.assets?.find((asset) => asset.name === decodeURIComponent(name));
  if (!asset) throw permanent(`Official release asset is missing: ${name}`);
  const endpoint = new URL(asset.url);
  if (
    endpoint.hostname !== 'api.github.com' ||
    !endpoint.pathname.startsWith(`/repos/${owner}/${repo}/releases/assets/`)
  )
    throw permanent('Unexpected official asset endpoint');
  return endpoint.href;
}
function curl(url, timeoutMs, maxBytes) {
  let executable = process.platform === 'win32' ? 'curl.exe' : 'curl';
  if (process.platform === 'win32') {
    const git = spawnSync('git', ['--exec-path'], { encoding: 'utf8', windowsHide: true });
    if (git.status === 0) {
      const candidate = join(dirname(dirname(git.stdout.trim())), 'bin', 'curl.exe');
      if (existsSync(candidate)) executable = candidate;
    }
  }
  const config =
    [
      `url = ${JSON.stringify(url)}`,
      ...Object.entries(headers(url, true)).map(([key, value]) => `header = ${JSON.stringify(`${key}: ${value}`)}`),
    ].join('\n') + '\n';
  const result = spawnSync(
    executable,
    [
      '--config',
      '-',
      '--http1.1',
      '--connect-timeout',
      '15',
      '--max-time',
      String(Math.ceil(timeoutMs / 1000)),
      '--location',
      '--fail',
      '--silent',
      '--show-error',
    ],
    { input: config, timeout: timeoutMs + 5000, maxBuffer: maxBytes + 1024, windowsHide: true },
  );
  if (result.error || result.status !== 0)
    throw new Error(`curl download failed: ${result.error?.message ?? result.stderr?.toString().trim()}`);
  if (result.stdout.length > maxBytes) throw permanent('Download exceeds size limit');
  return result.stdout;
}
async function fetchBytes(url, timeoutMs, maxBytes) {
  const response = await fetch(url, {
    headers: headers(url, true),
    cache: 'no-store',
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!response.ok) {
    const error = new Error(`HTTP ${response.status}`);
    error.permanent = ![408, 429, 500, 502, 503, 504].includes(response.status);
    await response.body?.cancel();
    throw error;
  }
  if (new URL(url).hostname === 'api.github.com' && response.headers.get('content-type')?.includes('application/json'))
    throw new Error('Asset API returned metadata instead of binary');
  const parts = [];
  let size = 0;
  for await (const part of response.body) {
    size += part.byteLength;
    if (size > maxBytes) throw permanent('Download exceeds size limit');
    parts.push(part);
  }
  return Buffer.concat(parts);
}
// Both endpoints stay on official GitHub infrastructure; every path uses the same pin.
export async function download(url, { description, sha256, maxBytes = 96 * 1024 * 1024, timeoutMs = 120000 }) {
  let alternate;
  for (let attempt = 1; attempt <= 4; attempt++) {
    try {
      let selected = url;
      if (attempt === 2 || attempt === 4) {
        try {
          alternate ??= await assetApi(url);
        } catch (error) {
          if (error.permanent) throw error;
          console.warn(
            `[prepare] ${description}: official API fallback unavailable; retaining verified direct download`,
          );
        }
        selected = alternate || url;
      }
      if (attempt >= 3) {
        const fresh = new URL(selected);
        fresh.searchParams.set('lemonvpn_download', `${Date.now()}-${attempt}`);
        selected = fresh.href;
      }
      const bytes =
        attempt >= 3 ? curl(selected, timeoutMs, maxBytes) : await fetchBytes(selected, timeoutMs, maxBytes);
      if (sha256 && createHash('sha256').update(bytes).digest('hex') !== sha256)
        throw permanent(`${description}: SHA256 mismatch`);
      return bytes;
    } catch (error) {
      if (error.permanent || attempt === 4) throw error;
      console.warn(`[prepare] ${description}: ${error.message}; retry ${attempt}/3 using official fallback`);
      await delay(Math.min(1500 * 2 ** (attempt - 1), 8000));
    }
  }
}
