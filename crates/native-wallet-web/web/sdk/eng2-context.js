// Immutable runtime pins. No network identifier or genesis is discovered from
// a service response, a legacy wallet or a checkpoint snapshot.
const id = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value) && !/^0+$/.test(value);
const fields = ['network', 'genesis', 'rules', 'profile'];
function origin(value) {
  if(typeof value!=='string')throw new Error('An exact engineering-v2 API origin is required.');
  const url = new URL(value);
  if (url.username || url.password || url.search || url.hash || url.pathname !== '/' || !(url.protocol === 'https:' || url.protocol === 'http:' && ['localhost','127.0.0.1','[::1]'].includes(url.hostname))) throw new Error('Use an exact pinned HTTPS or loopback engineering-v2 API origin.');
  return url.origin;
}
function origins(value,first) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 2) throw new Error('Pin one or two independent engineering-v2 API origins.');
  const result=value.map(origin);
  if (new Set(result).size !== result.length || first !== undefined && result[0] !== first) throw new Error('Engineering-v2 API origin order or uniqueness differs.');
  return Object.freeze(result);
}
export function eng2Context(value) {
  if (!value || value.version !== 2 || value.name !== 'siworld-eng-2' || value.fee_mode !== 0 || !fields.every(field => id(value[field]))) throw new Error('Pin the exact engineering-v2 network, genesis, rules, native profile and LegacyMiner fee mode.');
  const api=origin(value.api),apis=origins(value.apis === undefined ? [api] : value.apis,api);
  const submission_apis=origins(value.submission_apis === undefined ? apis : value.submission_apis);
  return Object.freeze({version:2,name:'siworld-eng-2',...Object.fromEntries(fields.map(field => [field,value[field]])),fee_mode:0,api,apis,submission_apis});
}
export function eng2Namespace(value) {
  const context = eng2Context(value);
  return 'siworld-eng2-wallet-' + fields.map(field => context[field]).join('-') + '-0';
}
export function sameEng2Context(value, pin) {
  return value?.version === 2 && value.fee_mode === 0 && fields.every(field => value[field] === pin[field]);
}
export function eng2Head(value, pin, now = Date.now() / 1000) {
  if (!value || Object.keys(value).sort().join() !== 'fee_mode,genesis,height,network,profile,published_unix_seconds,rules,tip,version' || !sameEng2Context(value,pin) || !Number.isSafeInteger(value.height) || value.height < 0 || value.height > 100000 || !id(value.tip) || !Number.isSafeInteger(value.published_unix_seconds) || value.published_unix_seconds < 0 || !Number.isFinite(now) || now-value.published_unix_seconds < -30 || now-value.published_unix_seconds > 300 || value.height === 0 && value.tip !== pin.genesis) throw new Error('Engineering-v2 head differs from its pinned context, height bound or freshness policy.');
  return Object.freeze({...value});
}
