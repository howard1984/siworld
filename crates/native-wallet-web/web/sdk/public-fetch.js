const retryStatuses = new Set([429,502,503,504]);

function wait(milliseconds,signal) {
  return new Promise((resolve,reject) => {
    signal?.throwIfAborted();
    const abort = () => { clearTimeout(timer); reject(signal.reason); };
    const timer = setTimeout(() => { signal?.removeEventListener('abort',abort); resolve(); },milliseconds);
    signal?.addEventListener('abort',abort,{once:true});
  });
}

export function publicTransportFailure(error,timeout) {
  if (error?.status !== undefined) return retryStatuses.has(error.status);
  return error instanceof TypeError
    || error instanceof DOMException && error.name === 'TimeoutError'
    || timeout?.aborted && error?.name === 'AbortError';
}

export async function publicJSON(request,url,options={},io={}) {
  const {bytes} = await publicGet(request,url,options,io);
  try { return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)); }
  catch { throw new Error('Malformed engineering service response.'); }
}

// Retry transport failures only. Decoding and native authentication stay with
// the caller, which retains ownership of every successfully returned buffer.
export async function publicGet(request,url,options={},io={}) {
  if ((options.method ?? 'GET') !== 'GET' || options.body !== undefined) throw new Error('Only an idempotent public GET may be retried.');
  const {signal,...settings} = options;
  for (let attempt=0;attempt<3;attempt++) {
    signal?.throwIfAborted();
    const timeout = io.timeout ? io.timeout(30000) : AbortSignal.timeout(30000);
    const combined = signal ? AbortSignal.any([signal,timeout]) : timeout;
    try { return await request(url,{...settings,method:'GET',signal:combined}); }
    catch (error) {
      signal?.throwIfAborted();
      if (attempt === 2 || !publicTransportFailure(error,timeout)) throw error;
      await (io.wait || wait)(attempt === 0 ? 500 : 1000,signal);
    }
  }
}
