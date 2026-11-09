import {createHash} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';

// Retry transport/temporary upstream failures; never weaken pinned digests.
export async function download(url, {description, sha256, maxBytes = 96 * 1024 * 1024, timeoutMs = 120000}) {
  for (let attempt = 1; attempt <= 4; attempt++) {
    try {
      const response = await fetch(url, {signal: AbortSignal.timeout(timeoutMs)});
      if (!response.ok) {
        const error = new Error(`${description}: HTTP ${response.status}`);
        error.permanent = ![408, 429, 500, 502, 503, 504].includes(response.status);
        await response.body?.cancel();
        throw error;
      }
      const parts = [];
      let size = 0;
      for await (const part of response.body) {
        size += part.byteLength;
        if (size > maxBytes) throw Object.assign(new Error(`${description}: download exceeds size limit`), {permanent: true});
        parts.push(part);
      }
      const bytes = Buffer.concat(parts);
      if (sha256 && createHash('sha256').update(bytes).digest('hex') !== sha256) {
        throw Object.assign(new Error(`${description}: SHA256 mismatch`), {permanent: true});
      }
      return bytes;
    } catch (error) {
      if (error.permanent || attempt === 4) throw error;
      console.warn(`[prepare] ${error.message}; retry ${attempt}/3`);
      await delay(Math.min(1500 * 2 ** (attempt - 1), 8000));
    }
  }
}
