const HASH = /^[0-9a-f]{64}$/;
const MAX_HEIGHT = 1_000_000;
const MAX_PAGE = 128;

function requireValue(condition, message) {
  if (!condition) throw new Error(message);
}

function height(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= MAX_HEIGHT;
}

export function networkConfiguration(value, pageOrigin) {
  requireValue(value && ['siworld-eng-1', 'siworld-eng-2'].includes(value.name), 'Unknown engineering network.');
  requireValue(HASH.test(value.network) && HASH.test(value.genesis), 'Pinned network identity is required.');
  requireValue(typeof value.api === 'string' && value.api.length > 0 && value.api.length <= 1024,
    'A public chain service path is required.');
  const origin = new URL(pageOrigin);
  const api = new URL(value.api, origin);
  requireValue(api.origin === origin.origin && !api.username && !api.password && !api.search && !api.hash,
    'The public chain service must use the page origin.');
  requireValue(api.protocol === 'https:' || api.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(api.hostname),
    'The public chain service requires HTTPS.');
  requireValue(!api.pathname.includes('//'), 'Invalid public chain service path.');
  return Object.freeze({name: value.name, network: value.network, genesis: value.genesis, api: api.href.replace(/\/$/, '')});
}

export async function boundedJSON(response, maximum) {
  requireValue(response.ok && !response.redirected, 'Public chain service unavailable.');
  requireValue(response.headers.get('content-type')?.split(';')[0].trim() === 'application/json', 'Unexpected public chain response.');
  const length = response.headers.get('content-length');
  requireValue(length === null || /^\d+$/.test(length) && Number(length) <= maximum, 'Public chain response exceeds its limit.');
  requireValue(response.body, 'Public chain response is empty.');
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const {done, value} = await reader.read();
      if (done) break;
      size += value.byteLength;
      requireValue(size <= maximum, 'Public chain response exceeds its limit.');
      chunks.push(value);
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes));
}

/** Read-only full-node view. Responses are not independent consensus verification. */
export class PublicChainClient {
  constructor(configuration, {origin, request = globalThis.fetch} = {}) {
    this.configuration = networkConfiguration(configuration, origin ?? globalThis.location?.origin);
    this.request = request.bind(globalThis);
  }

  async read(path, maximum, signal) {
    const response = await this.request(this.configuration.api + path, {
      method: 'GET', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer',
      cache: 'no-store', headers: {Accept: 'application/json'},
      signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(15_000)]) : AbortSignal.timeout(15_000),
    });
    return boundedJSON(response, maximum);
  }

  async head(signal) {
    const value = await this.read('/v1/head', 4096, signal);
    const config = this.configuration;
    requireValue(value && value.network === config.network && value.genesis === config.genesis,
      'The public chain service returned a different network.');
    requireValue(height(value.height) && HASH.test(value.tip), 'Invalid public chain head.');
    requireValue(value.height !== 0 || value.tip === config.genesis, 'Genesis head identity differs.');
    const available = value.compact_available_height ?? value.height;
    requireValue(height(available) && available <= value.height, 'Invalid public chain availability.');
    return Object.freeze({network: config.network, genesis: config.genesis, height: value.height,
      tip: value.tip, compactAvailableHeight: available});
  }

  async snapshot(signal) {
    return normalizeProjection(await this.read('/v1/explorer', 131072, signal), this.configuration);
  }

  async page(head, from, limit = MAX_PAGE, signal) {
    const config = this.configuration;
    requireValue(head && head.network === config.network && head.genesis === config.genesis &&
      height(head.height) && HASH.test(head.tip) && (head.height !== 0 || head.tip === config.genesis),
    'A pinned head from the selected network is required.');
    requireValue(Number.isSafeInteger(from) && from >= 1 && from <= head.height + 1 &&
      Number.isInteger(limit) && limit >= 1 && limit <= MAX_PAGE, 'Invalid public chain page range.');
    const query = new URLSearchParams({tip: head.tip, from: String(from), limit: String(limit)});
    const value = await this.read('/v1/chain?' + query, 9000, signal);
    const expected = Math.min(limit, head.height - from + 1);
    requireValue(value && Object.keys(value).length === 1 && Array.isArray(value.ids) &&
      value.ids.length === expected && value.ids.every(id => HASH.test(id)) &&
      new Set(value.ids).size === value.ids.length, 'Invalid or incomplete public chain page.');
    if (from + value.ids.length - 1 === head.height && value.ids.length) {
      requireValue(value.ids.at(-1) === head.tip, 'Public chain page does not end at the pinned head.');
    }
    return Object.freeze(value.ids.map((id, index) => Object.freeze({height: from + index, id})));
  }
}
import {normalizeProjection} from './projection.mjs';
