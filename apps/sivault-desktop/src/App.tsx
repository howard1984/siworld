import { en } from './locale/en';
import { WalletNodeStatus, WalletView } from './WalletView';
import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { ArrowDown, ArrowUp, Check, ChevronRight, Download, FileText, Folder, FolderOpen, FolderPlus, HardDrive, Info, KeyRound, LockKeyhole, Plus, Search, ShieldCheck, Upload, Wallet, X } from 'lucide-react';
import { authorizeReleaser, createControlled, demoAvailable, manageControlled, message, native, nativeBridge, prepareOwner, releaserStatus, setReleaserRunning, showOwnerRecovery, verifyReleaser, type Entry, type ReleaserStatus, type SafeBridge, type SafeInfo } from './bridge';

const brandMark = Object.values(import.meta.glob<string>('./branding.local/siworld-icon.svg', {
  eager: true,
  import: 'default',
  query: '?inline',
}))[0];

type Recent = Omit<SafeInfo, 'sessionId'>;
type Modal = 'create' | 'open' | 'unlock' | 'folder' | 'export' | null;
type Crumb = { id: string | null; name: string };

function IconButton({ label, children, ...props }: React.ButtonHTMLAttributes<HTMLButtonElement> & { label: string; children: ReactNode }) {
  return <button type="button" className="icon-button" title={label} aria-label={label} {...props}>{children}</button>;
}

function bytes(size: number): string {
  if (size < 1024) return `${size} B`;
  if (size < 1024 ** 2) return `${(size / 1024).toFixed(1)} KB`;
  if (size < 1024 ** 3) return `${(size / 1024 ** 2).toFixed(1)} MB`;
  return `${(size / 1024 ** 3).toFixed(1)} GB`;
}

export default function App() {
  const [bridge, setBridge] = useState<SafeBridge | null>(native ? nativeBridge : null);
  const [section, setSection] = useState<'vault' | 'wallet' | 'releaser'>('vault');
  const [localReleaser, setLocalReleaser] = useState<ReleaserStatus | null>(null);
  const [ownerId, setOwnerId] = useState<string | null>(null);
  const [controlled, setControlled] = useState(false);
  const [fixed, setFixed] = useState(false);
  const [controlledName, setControlledName] = useState('');
  const [setupOwner, setSetupOwner] = useState<string | null>(null);
  const [showingRecovery, setShowingRecovery] = useState(false);
  const [demo, setDemo] = useState(false);
  const [recent, setRecent] = useState<Recent[]>([]);
  const [safe, setSafe] = useState<SafeInfo | null>(null);
  const [chosenId, setChosenId] = useState<string | null>(null);
  const [entries, setEntries] = useState<Entry[]>([]);
  const [crumbs, setCrumbs] = useState<Crumb[]>([{ id: null, name: en.allFiles }]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [ascending, setAscending] = useState(true);
  const [modal, setModal] = useState<Modal>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const dialogRef = useRef<HTMLDialogElement>(null);
  const chosen = recent.find((item) => item.id === chosenId);
  const parent = crumbs[crumbs.length - 1].id;
  const selected = entries.find((entry) => entry.id === selectedId);
  const visible = entries.filter((entry) => entry.name.toLocaleLowerCase().includes(query.toLocaleLowerCase())).sort((a, b) =>
    Number(b.is_dir) - Number(a.is_dir) || (ascending ? 1 : -1) * a.name.localeCompare(b.name));

  useEffect(() => {
    if (modal) dialogRef.current?.showModal();
    else dialogRef.current?.close();
  }, [modal]);

  useEffect(() => {
    if (section !== 'releaser' || busy || !localReleaser?.address) return;
    let active = true;
    const timer = window.setInterval(() => {
      void releaserStatus().then((status) => {
        if (active) setLocalReleaser(status);
      }).catch(() => {
        if (active) {
          setLocalReleaser(null);
          setError(en.errors.RELEASER_UNAVAILABLE);
        }
      });
    }, 1500);
    return () => { active = false; window.clearInterval(timer); };
  }, [section, busy, localReleaser?.address]);

  async function run(action: () => Promise<void>) {
    if (busy) return;
    setBusy(true);
    setError('');
    setNotice('');
    try { await action(); } catch (err) { setError(message(err)); }
    finally { setBusy(false); }
  }

  async function refresh(session: SafeInfo, directory: string | null = parent) {
    if (!bridge) return;
    const next = await bridge.list(session.sessionId, directory);
    setEntries(next);
    setSelectedId(null);
  }

  async function lock() {
    if (!safe || !bridge) return;
    await bridge.lock(safe.sessionId);
    setLocalReleaser(null);
    setOwnerId(null);
    setSafe(null);
    setEntries([]);
    setSelectedId(null);
    setQuery('');
    setCrumbs([{ id: null, name: en.allFiles }]);
    setNotice(en.safeLockedNotice);
  }

  async function accept(info: SafeInfo) {
    setSafe(info);
    setChosenId(info.id);
    setRecent((items) => [{ id: info.id, name: info.name, readOnly: info.readOnly }, ...items.filter((item) => item.id !== info.id)]);
    setCrumbs([{ id: null, name: en.allFiles }]);
    setQuery('');
    setEntries([]);
    setSelectedId(null);
    await refresh(info, null);
  }

  async function enableDemo() {
    await run(async () => {
      const { createDemoBridge } = await import('./demo');
      const next = createDemoBridge();
      setBridge(next);
      setDemo(true);
      const info = await next.open(false);
      if (info) {
        setSafe(info);
        setChosenId(info.id);
        setRecent([{ id: info.id, name: info.name, readOnly: false }]);
        setEntries(await next.list(info.sessionId, null));
      }
    });
  }

  function showModal(next: Modal) {
    setError(''); setNotice(''); setControlled(false); setFixed(false); setControlledName(''); setSetupOwner(null); setModal(next);
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!bridge) return;
    const form = new FormData(event.currentTarget);
    const name = String(form.get('name') ?? '').trim();
    const readOnly = form.get('readOnly') === 'on';
    await run(async () => {
      if (modal === 'folder' && safe) {
        await bridge.createDirectory(safe.sessionId, name, parent);
        await refresh(safe);
      } else if (modal === 'export' && safe && selected) {
        const exported = await bridge.exportFile(safe.sessionId, selected.id);
        if (exported) setNotice(demo ? en.sampleExported : en.exported);
      } else {
        if (safe) await lock();
        if (modal === 'create' && controlled && !setupOwner) {
          setControlledName(name);
          const owner = await prepareOwner();
          if (owner) setSetupOwner(owner);
          return;
        }
        const info = modal === 'create' ? controlled && native
          ? await createControlled(controlledName, String(form.get('address') ?? '').trim(), String(form.get('identifier') ?? '').trim(), Number(form.get('allowance')))
          : fixed && native ? await createFixed(name, form.get('decoy') === 'on') : await bridge.create(name)
          : modal === 'unlock' && chosenId ? await bridge.unlock(chosenId, readOnly)
          : await bridge.open(readOnly);
        if (info) await accept(info);
      }
      setModal(null);
    });
  }

  async function navigate(index: number) {
    if (!safe) return;
    await run(async () => {
      await refresh(safe, crumbs[index].id);
      setCrumbs(crumbs.slice(0, index + 1));
      setQuery('');
    });
  }

  async function enter(entry: Entry) {
    if (!entry.is_dir || !safe) return;
    await run(async () => {
      await refresh(safe, entry.id);
      setCrumbs([...crumbs, { id: entry.id, name: entry.name }]);
      setQuery('');
    });
  }

  return <div className="app-shell" aria-busy={busy}>
    <a className="skip-link" href={section === 'vault' ? '#files' : '#' + section}>{section === 'vault' ? en.skip : section === 'wallet' ? en.skipWallet : en.skipReleaser}</a>
    {demoAvailable && <div className="dev-banner"><span><Info size={14} />{demo ? en.demoActive : en.browserPreview}</span>{!demo && <button disabled={busy} onClick={enableDemo}>{en.openDemo}</button>}</div>}
    {!native && !demoAvailable && <div className="dev-banner">{en.nativeRequired}</div>}
    {native && <div className="dev-banner">{en.development}</div>}
    <header className="app-header"><div className="brand">{brandMark && <img className="brand-icon" src={brandMark} width={24} height={24} alt={en.brandName} />}<span>{en.appName}</span></div><nav className="section-nav" aria-label={en.sectionNavigation}>
      <button type="button" aria-current={section === 'vault' ? 'page' : undefined} onClick={() => setSection('vault')}><ShieldCheck size={15} aria-hidden="true" />{en.vaultTab}</button>
      <button type="button" aria-current={section === 'wallet' ? 'page' : undefined} disabled={busy || modal !== null} onClick={() => run(async () => { await lock(); setSection('wallet'); })}><Wallet size={15} aria-hidden="true" />{en.walletTab}</button>
      {native && <button type="button" aria-current={section === 'releaser' ? 'page' : undefined} disabled={busy || modal !== null} onClick={() => run(async () => { setSection('releaser'); setLocalReleaser(await releaserStatus()); })}><KeyRound size={15} aria-hidden="true" />{en.releaserTab}</button>}
    </nav>{section === 'wallet' && native && <WalletNodeStatus />}</header>
    {section === 'wallet' ? <WalletView /> : section === 'releaser' ? <main className="main releaser-page" id="releaser" tabIndex={-1}>
      <div className="view-heading"><h1>{en.releaserTab}</h1></div>
      {(error || notice) && <div role={error ? 'alert' : 'status'} className={`notification ${error ? 'error' : ''}`}>{error || notice}</div>}
      <section className="releaser-group" aria-labelledby="my-releasers"><h2 id="my-releasers">{en.myReleasers}</h2>
      <h3>{en.localReleaser}</h3>
      <label className="checkbox-field"><input type="checkbox" role="switch" checked={Boolean(localReleaser?.address)} disabled={busy} onChange={(event) => {
        const enabled = event.currentTarget.checked;
        void run(async () => setLocalReleaser(await setReleaserRunning(enabled)));
      }} />{en.runReleaser}</label>
      {localReleaser?.address && <p>{en.releaserAddress}: <code>{localReleaser.address}</code></p>}
      {localReleaser?.identifier && <p>{en.releaserIdentifier}: <code className="releaser-identifier">{localReleaser.identifier}</code></p>}
      {localReleaser?.address && <p role="status">{!localReleaser.enrolled ? en.noReleaserEnrollment
        : localReleaser.ledger?.state === 'active' ? (localReleaser.ledger.remaining > 0 ? en.attemptsRemaining(localReleaser.ledger.remaining) : en.allowanceExhausted)
        : localReleaser.ledger?.state === 'revoked' ? en.releaserRevoked : en.releaserLedgerUnavailable}</p>}
      {localReleaser?.address && !localReleaser.enrolled && <form className="releaser-form" onSubmit={(event) => {
        event.preventDefault();
        const form = new FormData(event.currentTarget);
        void run(async () => {
          if (await authorizeReleaser(String(form.get('owner') ?? ''), Number(form.get('allowance')))) setNotice(en.enrollmentAuthorized);
        });
      }}>
        <label className="field">{en.ownerIdentifier}<input name="owner" required minLength={64} maxLength={64} autoComplete="off" spellCheck={false} /></label>
        <label className="field">{en.attemptAllowance}<input name="allowance" type="number" required min={1} max={1000} defaultValue={2} /></label>
        <button type="submit" className="button" disabled={busy}>{en.allowEnrollment}</button>
      </form>}
      </section>
      <section className="releaser-group" aria-labelledby="owner-controls"><h2 id="owner-controls">{en.ownerControls}</h2>
      <button type="button" className="button" disabled={busy} onClick={() => run(async () => setOwnerId(await prepareOwner()))}>{en.showOwnerIdentifier}</button>
      {ownerId && <p>{en.ownerIdentifier}: <code className="releaser-identifier">{ownerId}</code></p>}
      <form className="releaser-form" onSubmit={(event) => {
        event.preventDefault();
        const values = new FormData(event.currentTarget);
        void run(async () => {
          if (await manageControlled(Number(values.get('current')), Number(values.get('additional')), null)) setNotice(en.refillConfirmed);
        });
      }}>
        <label className="field">{en.currentAllowance}<input name="current" type="number" required min={1} defaultValue={2} /></label>
        <label className="field">{en.additionalAllowance}<input name="additional" type="number" required min={1} defaultValue={2} /></label>
        <button type="submit" className="button" disabled={busy}>{en.refillAllowance}</button>
      </form>
      <form className="releaser-form" onSubmit={(event) => {
        event.preventDefault();
        const values = new FormData(event.currentTarget);
        void run(async () => {
          if (await manageControlled(0, 0, String(values.get('label') ?? ''))) setNotice(en.revocationConfirmed);
        });
      }}>
        <label className="field">{en.safeName}<input name="label" required maxLength={120} autoComplete="off" /></label>
        <button type="submit" className="button" disabled={busy}>{en.revokeSafe}</button>
      </form>
      <p className="limit-note">{en.revokeLimits}</p>
      <form className="releaser-form" onSubmit={(event) => {
        event.preventDefault();
        const form = new FormData(event.currentTarget);
        void run(async () => {
          await verifyReleaser(String(form.get('address') ?? ''), String(form.get('identifier') ?? ''));
          setNotice(en.releaserVerified);
        });
      }}>
        <label className="field">{en.releaserAddress}<input name="address" required maxLength={21} autoComplete="off" placeholder="127.0.0.1:12345" /></label>
        <label className="field">{en.releaserIdentifier}<input name="identifier" required minLength={64} maxLength={64} autoComplete="off" spellCheck={false} /></label>
        <button type="submit" className="button" disabled={busy}><ShieldCheck size={15} aria-hidden="true" />{en.verifyReleaser}</button>
      </form>
      </section>
    </main> : <div className="workspace">
      <aside className="sidebar" aria-label={en.safeNavigation}>
        <div className="sidebar-heading"><span>{en.safesUpper}</span><IconButton label={en.createSafe} disabled={!bridge || busy} onClick={() => showModal('create')}><Plus size={17} /></IconButton></div>
        <nav className="safe-list" aria-label={en.safes}>{recent.map((item) => <button key={item.id} className={`safe-item ${chosenId === item.id ? 'active' : ''}`} disabled={busy} onClick={() => run(async () => { if (safe?.id !== item.id) { if (safe) await lock(); setChosenId(item.id); } })}><HardDrive size={19} /><span><strong>{item.name}</strong><small>{safe?.id === item.id ? en.open : en.locked}</small></span>{safe?.id !== item.id && <LockKeyhole size={13} />}</button>)}{recent.length === 0 && <p className="sidebar-empty">{en.noSafes}</p>}</nav>
        <button className="sidebar-command" title={en.openExisting} disabled={!bridge || busy} onClick={() => showModal('open')}><FolderOpen size={17} />{en.openExisting}</button>
        <div className="sidebar-bottom"><ShieldCheck size={17} /><span>{en.standardSafe}<small>{en.localFiles}</small></span></div>
      </aside>
      <main className="main" id="files" tabIndex={-1}>
        <div className="view-heading">
          <div><div className="eyebrow">{en.standardSafeUpper}</div><h1>{safe?.name ?? chosen?.name ?? en.yourSafes}</h1></div>
          {safe && <div className="heading-actions"><span className={`state-label ${safe.readOnly ? 'read-only' : ''}`}>{safe.readOnly ? en.readOnly : en.open}</span><button disabled={busy} className="button" onClick={() => run(lock)}><LockKeyhole size={15} />{en.lockSafe}</button></div>}
        </div>
        {(error || notice) && !modal && <div role={error ? 'alert' : 'status'} className={`notification ${error ? 'error' : ''}`}><span>{error || notice}</span><IconButton label={en.dismiss} onClick={() => { setError(''); setNotice(''); }}><X size={15} /></IconButton></div>}
        {safe ? <>
          <div className="file-toolbar"><nav className="breadcrumbs" aria-label={en.folderPath}>{crumbs.map((crumb, index) => <span key={crumb.id ?? 'root'}>{index > 0 && <ChevronRight size={13} />}<button disabled={busy || index === crumbs.length - 1} onClick={() => navigate(index)}>{index === 0 && <Folder size={15} />}{crumb.name}</button></span>)}</nav><div className="file-actions">{safe.canManageDecoy && <IconButton label={en.addDecoyFile} disabled={busy} onClick={() => run(async () => { if (await updateDecoy(safe.sessionId)) setNotice(en.decoyUpdated); })}><FileText size={18} /></IconButton>}<IconButton label={en.newFolder} disabled={busy || safe.readOnly || safe.fixed} onClick={() => showModal('folder')}><FolderPlus size={18} /></IconButton><IconButton label={en.exportSelected} disabled={busy || !selected || selected.is_dir} onClick={() => showModal('export')}><Download size={18} /></IconButton><button className="button primary" disabled={busy || safe.readOnly} onClick={() => run(async () => { try { const count = await bridge!.importFiles(safe.sessionId, parent); if (count) setNotice(demo ? en.sampleAdded : en.imported(count)); } finally { await refresh(safe); } })}><Upload size={15} />{demo ? en.importSample : en.importFiles}</button></div></div>
          <div className="search-row"><label className="search-box"><Search size={16} /><input aria-label={en.search} type="search" placeholder={en.search} value={query} onChange={(event) => setQuery(event.target.value)} /><span>{en.itemCount(visible.length)}</span></label>{busy && <span className="working" role="status">{en.working}</span>}</div>
          <div className="browser-layout"><section className="file-list" aria-label={en.contents}><table><thead><tr><th scope="col"><button className="sort-button" onClick={() => setAscending(!ascending)}>Name {ascending ? <ArrowUp size={13} /> : <ArrowDown size={13} />}</button></th><th scope="col">{en.type}</th><th scope="col" className="size-column">{en.size}</th></tr></thead><tbody>{visible.map((entry) => <tr key={entry.id} className={selectedId === entry.id ? 'selected' : ''} onClick={() => setSelectedId(entry.id)}><td><button className="entry-name" disabled={busy} onClick={(event) => { event.stopPropagation(); if (entry.is_dir) enter(entry); else setSelectedId(entry.id); }} title={entry.name}>{entry.is_dir ? <Folder className="folder-icon" size={19} /> : <FileText className="file-icon" size={18} />}<span>{entry.name}</span>{entry.is_dir && <ChevronRight className="entry-chevron" size={14} />}</button></td><td>{entry.is_dir ? en.folder : entry.name.includes('.') ? en.fileType(entry.name.split('.').pop()!.toUpperCase()) : en.file}</td><td className="size-column">{entry.is_dir ? '--' : bytes(entry.size)}</td></tr>)}</tbody></table>{visible.length === 0 && <div className="empty-folder"><FolderOpen size={34} strokeWidth={1.3} /><h2>{query ? en.noMatching : en.empty}</h2>{!query && !safe.readOnly && <button className="button" disabled={busy} onClick={() => run(async () => { try { await bridge!.importFiles(safe.sessionId, parent); } finally { await refresh(safe); } })}><Upload size={15} />{demo ? en.importSample : en.importFiles}</button>}</div>}</section>
            {selected && <aside className="details" aria-label={en.itemDetails}>
              <div className="detail-heading">{en.details}</div>
              <h2 className="detail-name">{selected.is_dir ? <Folder className="folder-icon" size={16} /> : <FileText className="file-icon" size={16} />}<span>{selected.name}</span></h2>
              <dl>
                <div><dt>{en.kind}</dt><dd>{selected.is_dir ? en.folder : en.file}</dd></div>
                {!selected.is_dir && <div><dt>{en.size}</dt><dd>{bytes(selected.size)}</dd></div>}
                <div><dt>{en.location}</dt><dd>{crumbs[crumbs.length - 1].name}</dd></div>
                <div><dt>{en.access}</dt><dd>{safe.readOnly ? en.readOnly : en.readWrite}</dd></div>
              </dl>
              {selected.is_dir ? <button className="button full-width" disabled={busy} onClick={() => enter(selected)}><FolderOpen size={15} />{en.openFolder}</button> : <button className="button full-width" disabled={busy} onClick={() => showModal('export')}><Download size={15} />{en.exportFile}</button>}
            </aside>}
          </div><footer className="file-status"><span>{en.fileCount(entries.filter((entry) => !entry.is_dir).length)}<span className="status-divider" />{en.folderCount(entries.filter((entry) => entry.is_dir).length)}</span><span>{demo ? en.syntheticData : safe.readOnly ? en.readOnly : en.localSafe}<Check size={13} /></span></footer>
        </> : <div className="locked-view">
          <span className="locked-icon">{chosen ? <LockKeyhole size={20} /> : <HardDrive size={20} />}</span>
          <h2>{chosen ? en.safeLocked : en.emptySafes}</h2>
          <div className="state-actions">
            <button className="button primary" disabled={!bridge || busy} onClick={() => showModal(chosen ? 'unlock' : 'create')}>{chosen ? <LockKeyhole size={15} /> : <Plus size={15} />}{chosen ? en.openSafe : en.createSafe}</button>
            {!chosen && <button className="button" disabled={!bridge || busy} onClick={() => showModal('open')}><FolderOpen size={15} />{en.openExisting}</button>}
          </div>
        </div>}
      </main>
    </div>}
    <dialog ref={dialogRef} className="modal" onCancel={(event) => { if (busy) event.preventDefault(); else setModal(null); }} onClose={() => { if (!busy) setModal(null); }} aria-labelledby="modal-title"><form onSubmit={submit} key={modal}>
      <div className="modal-heading"><h2 id="modal-title">{modal === 'create' ? (setupOwner ? en.controlledDetails : native ? en.createSafe : en.createStandard) : modal === 'folder' ? en.newFolder : modal === 'export' ? en.exportFile : (native ? en.openSafe : en.openStandard)}</h2><IconButton label={en.closeDialog} disabled={busy} onClick={() => setModal(null)}><X size={18} /></IconButton></div>
      {modal === 'create' && native && !setupOwner && <label className="field">{en.safeType}<select value={controlled ? 'controlled' : fixed ? 'fixed' : 'offline'} onChange={(event) => { setControlled(event.target.value === 'controlled'); setFixed(event.target.value === 'fixed'); }}>
        <option value="offline">{en.offlineSafe}</option><option value="fixed">{en.fixedSafe}</option><option value="controlled">{en.controlledSafe}</option>
      </select></label>}
      {modal === 'create' && fixed && <label className="checkbox-field"><input type="checkbox" name="decoy" />{en.enableDecoy}</label>}
      {modal === 'create' && controlled && <p className="limit-note">{en.controlledLimits}</p>}
      {modal === 'create' && setupOwner && <div className="controlled-fields">
        <p>{en.ownerIdentifier}: <code className="releaser-identifier">{setupOwner}</code></p>
        <button className="button" type="button" disabled={busy} onClick={() => void run(async () => {
          setShowingRecovery(true);
          try { await showOwnerRecovery(); } finally { setShowingRecovery(false); }
        })}><KeyRound size={16} />{en.showOwnerRecovery}</button>
        <label className="field">{en.releaserAddress}<input name="address" required maxLength={21} autoComplete="off" /></label>
        <label className="field">{en.releaserIdentifier}<input name="identifier" required minLength={64} maxLength={64} autoComplete="off" spellCheck={false} /></label>
        <label className="field">{en.attemptAllowance}<input name="allowance" type="number" required min={1} max={1000} defaultValue={2} /></label>
      </div>}
      {demo && <p className="demo-note">{en.demoNote}</p>}
      {((modal === 'create' && !setupOwner) || modal === 'folder') && <label className="field">{modal === 'folder' ? en.folderName : en.safeName}<input name="name" required autoFocus maxLength={120} pattern={'[^/\\\\]+'} autoComplete="off" defaultValue={modal === 'create' ? controlledName : ''} placeholder={modal === 'folder' ? en.untitledFolder : en.personalArchive} /></label>}
      {modal === 'unlock' && <p className="unlock-name"><HardDrive size={17} />{chosen?.name}</p>}
      {(modal === 'open' || modal === 'unlock') && <label className="checkbox-field"><input type="checkbox" name="readOnly" />{en.openReadOnly}</label>}
      {modal === 'export' && <><p className="export-name"><FileText size={18} />{selected?.name}</p><p className="export-notice">{en.exportWarning}</p></>}
      {error && <div className="form-error" role="alert">{error}</div>}
      {busy && <p className="operation-status" role="status">{showingRecovery ? en.recoveryDialog : modal === 'open' || modal === 'unlock' ? en.openingSafe : setupOwner ? en.enrollingSafe : en.working}</p>}
      <div className="modal-actions"><button className="button" type="button" disabled={busy} onClick={() => { if (setupOwner) setSetupOwner(null); else setModal(null); }}>{setupOwner ? en.back : en.cancel}</button><button className="button primary" type="submit" disabled={busy}>{modal === 'create' ? (controlled && !setupOwner ? en.continue : en.createSafe) : modal === 'folder' ? en.createFolder : modal === 'export' ? en.chooseDestination : modal === 'open' && !demo ? en.chooseSafe : en.openSafe}</button></div>
    </form></dialog>
  </div>;
}
import { createFixed, updateDecoy } from './bridge';
