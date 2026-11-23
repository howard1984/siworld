import { useEffect, useState } from 'react';
import { ArrowUpRight, LockKeyhole, Plug, RefreshCw, Save, Wallet } from 'lucide-react';
import { invoke } from '@tauri-apps/api/core';
import { message, native } from './bridge';
import { en } from './locale/en';

type Profile = 'loading' | 'missing' | 'locked' | 'unavailable';
type Operation = 'create' | 'restore' | 'unlock';
type HistoryRow = { id: string; height: number; amount_atoms: string; kind: 'received' | 'mining' | 'allocation' };
type PaymentStatus = {
  statement_id: string; amount_atoms: string; fee_atoms: string; height: number | null; acknowledged: boolean;
};
type PublicWallet = {
  address: string;
  short_address: string;
  published: boolean;
  chain?: {
    height: number; available_atoms: string; locked_atoms: string; history: HistoryRow[];
    standard_fee_atoms: string; payment: PaymentStatus | null;
  };
};

export function WalletNodeStatus() {
  const [status, setStatus] = useState<'checking' | 'unconfigured' | 'reachable' | 'unreachable'>('checking');
  useEffect(() => {
    let active = true;
    let timeout: number | undefined;
    async function check() {
      try {
        const endpoint = await invoke<string | null>('wallet_endpoint');
        if (endpoint) await invoke('wallet_probe_endpoint');
        if (active) setStatus(endpoint ? 'reachable' : 'unconfigured');
      } catch {
        if (active) setStatus('unreachable');
      } finally {
        if (active) timeout = window.setTimeout(() => void check(), 5000);
      }
    }
    void check();
    return () => { active = false; window.clearTimeout(timeout); };
  }, []);
  return <span className="node-status" data-state={status} role="status">
    <span className="status-dot" aria-hidden="true" />{en.walletNodeStatus[status]}
  </span>;
}

function WalletEndpoint() {
  const [origin, setOrigin] = useState('');
  const [savedOrigin, setSavedOrigin] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [probing, setProbing] = useState(false);
  const [responded, setResponded] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    invoke<string | null>('wallet_endpoint').then(
      (value) => {
        if (!active) return;
        setOrigin(value ?? '');
        setSavedOrigin(value ?? '');
      },
      (failure) => { if (active) setError(message(failure)); },
    );
    return () => { active = false; };
  }, []);

  async function save() {
    setSaving(true);
    setResponded(false);
    setError('');
    try {
      await invoke('wallet_set_endpoint', { origin });
      setSavedOrigin(origin);
    } catch (failure) {
      setError(message(failure));
    } finally {
      setSaving(false);
    }
  }

  async function probe() {
    setProbing(true);
    setResponded(false);
    setError('');
    try {
      await invoke('wallet_probe_endpoint');
      setResponded(true);
    } catch (failure) {
      setError(message(failure));
    } finally {
      setProbing(false);
    }
  }

  return <form className="wallet-endpoint" aria-busy={saving || probing} onSubmit={(event) => { event.preventDefault(); void save(); }}>
    <label className="field">
      {en.walletEndpoint}
      <input type="text" inputMode="url" placeholder={en.walletEndpointExample}
        value={origin} maxLength={64} autoComplete="off" spellCheck={false}
        disabled={saving || probing || (savedOrigin === null && !error)}
        onChange={(event) => { setOrigin(event.target.value); setResponded(false); }} />
    </label>
    <div className="wallet-endpoint-actions">
      <button type="submit" className="button" disabled={saving || probing || origin === savedOrigin || (savedOrigin === null && !error)}>
        <Save size={15} />{en.walletSaveEndpoint}
      </button>
      <button type="button" className="button" disabled={saving || probing || !savedOrigin || origin !== savedOrigin} onClick={() => void probe()}>
        <Plug size={15} />{en.walletProbeEndpoint}
      </button>
    </div>
    {error && <p className="form-error" role="alert">{error}</p>}
    {responded && <p className="wallet-endpoint-status" role="status">{en.walletEndpointResponded}</p>}
  </form>;
}

export function WalletView() {
  const [profile, setProfile] = useState<Profile>('loading');
  const [wallet, setWallet] = useState<PublicWallet | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [attempt, setAttempt] = useState(0);
  const [compose, setCompose] = useState(false);
  const [recipient, setRecipient] = useState('');
  const [amount, setAmount] = useState('');
  const walletOpen = wallet !== null;

  useEffect(() => {
    if (!native || !walletOpen) return;
    let running = false;
    async function refresh() {
      if (running) return;
      running = true;
      try { await invoke('wallet_refresh_directory'); } catch { /* Keep the previous complete directory. */ }
      finally { running = false; }
    }
    const job = window.setInterval(() => void refresh(), 15_000);
    return () => window.clearInterval(job);
  }, [walletOpen]);

  useEffect(() => {
    if (!native) {
      setProfile('unavailable');
      return;
    }
    let active = true;
    invoke<boolean>('wallet_status').then(
      (exists) => { if (active) setProfile(exists ? 'locked' : 'missing'); },
      () => { if (active) setProfile('unavailable'); },
    );
    return () => { active = false; };
  }, [attempt]);

  async function access(operation: Operation) {
    setBusy(true);
    setError('');
    try {
      const opened = await invoke<PublicWallet | null>('wallet_access', { operation });
      if (opened) {
        setWallet(opened);
        setProfile('locked');
      }
    } catch (failure) {
      setError(message(failure));
    } finally {
      setBusy(false);
    }
  }

  async function send(retry = false) {
    if (!wallet?.chain) return;
    setBusy(true);
    setError('');
    try {
      const payment = retry
        ? await invoke<PaymentStatus | null>('wallet_retry_payment')
        : await invoke<PaymentStatus | null>('wallet_send', {
          recipient: recipient.trim(), amount, fee: wallet.chain.standard_fee_atoms,
        });
      if (payment) {
        setWallet({ ...wallet, chain: { ...wallet.chain, payment } });
        setCompose(false);
        setRecipient('');
        setAmount('');
      }
    } catch (failure) {
      setError(message(failure));
    } finally {
      setBusy(false);
    }
  }

  const payment = wallet?.chain?.payment;
  const pending = !!payment && payment.height === null;
  const sendBlocked = busy ? en.working : pending ? en.walletSendPending
    : !wallet?.chain ? en.walletSendNoChain
    : wallet.chain.available_atoms === '0' ? en.walletSendNoFunds : '';

  return <main id="wallet" className="main wallet-page" tabIndex={-1} aria-busy={busy || profile === 'loading'}>
    <div className="view-heading">
      <div><div className="eyebrow">{en.walletLocal}</div><h1>{en.walletTab}</h1></div>
      {wallet && <button type="button" className="button" disabled={busy} onClick={() => {
        setWallet(null); setCompose(false); setRecipient(''); setAmount(''); setError('');
      }}><LockKeyhole size={15} />{en.walletLock}</button>}
    </div>
    {error && <p className="notification error" role="alert">{error}</p>}
    {wallet ? <div className="wallet-info">
      <div className="wallet-stat"><h2>{en.walletBalance}</h2>
        <p>{wallet.chain ? en.walletAtoms(wallet.chain.available_atoms) : en.walletOfflineAmount}</p>
        <small>{wallet.chain ? en.walletVerifiedHeight(wallet.chain.height) : en.walletNoNetwork}</small>
        {wallet.chain && wallet.chain.locked_atoms !== '0' && <small>{en.walletLockedAtoms(wallet.chain.locked_atoms)}</small>}
      </div>
      <section>
        <h2>{en.walletReceive}</h2>
        <textarea aria-label={en.walletReceive} value={wallet.short_address} rows={2} spellCheck={false} readOnly />
        {!wallet.published && <small>{en.walletAddressUnpublished}</small>}
        <details>
          <summary>{en.walletAdvanced}</summary>
          <textarea aria-label={en.walletFullAddress} value={wallet.address} rows={4} spellCheck={false} readOnly />
        </details>
      </section>
      <section>
        <div className="wallet-action">
          <h2>{en.walletActivity}</h2>
          {wallet.chain && <button type="button" className="button" disabled={busy}
            onClick={() => void access('unlock')}><RefreshCw size={15} />{en.walletRefresh}</button>}
          <button type="button" className="button" disabled={!!sendBlocked}
            aria-describedby={sendBlocked ? 'wallet-send-blocked' : undefined}
            onClick={() => setCompose(!compose)}><ArrowUpRight size={16} />{en.walletSend}</button>
        </div>
        {sendBlocked && <small id="wallet-send-blocked" className="wallet-send-blocked">{sendBlocked}</small>}
        {compose && wallet.chain && !pending && <form className="wallet-endpoint"
          onSubmit={(event) => { event.preventDefault(); void send(); }}>
          <label className="field">{en.walletRecipient}
            <input required value={recipient} maxLength={2058} autoComplete="off" spellCheck={false}
              onChange={(event) => setRecipient(event.target.value)} disabled={busy} />
          </label>
          <label className="field">{en.walletAmount}
            <input required inputMode="numeric" pattern="[1-9][0-9]{0,19}" maxLength={20} value={amount}
              onChange={(event) => setAmount(event.target.value)} disabled={busy} />
          </label>
          <small>{en.walletFee(wallet.chain.standard_fee_atoms)}</small>
          <button type="submit" className="button primary" disabled={busy}>{en.walletReviewPayment}</button>
        </form>}
        {payment && <p role="status">
          {en.walletAtoms(payment.amount_atoms)} · {payment.height !== null ? en.walletPaymentIncluded(payment.height)
            : payment.acknowledged ? en.walletPaymentPending : en.walletPaymentUnknown}
        </p>}
        {pending && !payment?.acknowledged && <button type="button" className="button" disabled={busy}
          onClick={() => void send(true)}><RefreshCw size={15} />{en.walletRetryPayment}</button>}
        {wallet.chain?.history.length ? <ul aria-label={en.walletActivity}>
          {wallet.chain.history.map((row) => <li key={row.id}>
            {en.walletHistoryRow(en.walletHistoryKind[row.kind], row.height, row.amount_atoms)}
          </li>)}
        </ul> : !payment && <p>{en.walletNoHistory}</p>}
      </section>
    </div> : <div className="locked-view">
      <span className="locked-icon"><Wallet size={20} /></span>
      <h2>{profile === 'loading' ? en.working : profile === 'unavailable' ? en.walletUnavailable : profile === 'missing' ? en.walletNew : en.walletLocked}</h2>
      {profile !== 'loading' && (profile !== 'unavailable' || native) && <div className="state-actions">
        {profile === 'missing' && <>
          <button type="button" className="button primary" disabled={busy} onClick={() => void access('create')}>{en.walletCreate}</button>
          <button type="button" className="button" disabled={busy} onClick={() => void access('restore')}>{en.walletRestore}</button>
        </>}
        {profile === 'locked' && <button type="button" className="button primary" disabled={busy} onClick={() => void access('unlock')}><LockKeyhole size={15} />{en.walletUnlock}</button>}
        {profile === 'unavailable' && native && <button type="button" className="button" onClick={() => { setProfile('loading'); setAttempt(attempt + 1); }}><RefreshCw size={15} />{en.walletRetry}</button>}
      </div>}
    </div>}
    {native && (profile === 'locked' || profile === 'missing') && <WalletEndpoint />}
  </main>;
}
