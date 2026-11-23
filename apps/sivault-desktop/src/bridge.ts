import { invoke, isTauri } from '@tauri-apps/api/core';
import { en } from './locale/en';

export type Entry = {
  id: string;
  parent: string | null;
  name: string;
  is_dir: boolean;
  size: number;
};

export type SafeInfo = {
  id: string;
  name: string;
  sessionId: string;
  readOnly: boolean;
};

export const native = isTauri();
export const demoAvailable = import.meta.env.DEV && !native;

export type ReleaserStatus = {
  address: string | null;
  identifier: string | null;
  enrolled: boolean;
  ledger: { state: 'active'; remaining: number } | { state: 'revoked' | 'unavailable' } | null;
};
export const releaserStatus = () => invoke<ReleaserStatus>('releaser_status');
export const setReleaserRunning = (enabled: boolean) =>
  invoke<ReleaserStatus>('releaser_set_running', { enabled });
export const verifyReleaser = (address: string, identifier: string) =>
  invoke<void>('releaser_verify', { address, identifier });
export const prepareOwner = async () => await invoke<boolean>('owner_prepare')
  ? invoke<string>('owner_identifier') : null;
export const showOwnerRecovery = () => invoke<boolean>('owner_show_recovery');
export const authorizeReleaser = (owner: string, allowance: number) =>
  invoke<boolean>('releaser_authorize', { owner, allowance });
export const createControlled = (name: string, address: string, identifier: string, allowance: number) =>
  invoke<SafeInfo | null>('safe_create_controlled', { name, address, identifier, allowance });
export const manageControlled = (current: number, additional: number, revokeLabel: string | null) =>
  invoke<boolean>('safe_manage_controlled', { current, additional, revokeLabel });

export interface SafeBridge {
  create(name: string): Promise<SafeInfo | null>;
  open(readOnly: boolean): Promise<SafeInfo | null>;
  unlock(id: string, readOnly: boolean): Promise<SafeInfo | null>;
  list(sessionId: string, parent: string | null): Promise<Entry[]>;
  importFiles(sessionId: string, parent: string | null): Promise<number>;
  exportFile(sessionId: string, entryId: string): Promise<boolean>;
  createDirectory(sessionId: string, name: string, parent: string | null): Promise<Entry>;
  lock(sessionId: string): Promise<void>;
}

export const nativeBridge: SafeBridge = {
  create: (name) => invoke('safe_create', { name }),
  open: (readOnly) => invoke('safe_open', { readOnly }),
  unlock: (id, readOnly) => invoke('safe_unlock', { id, readOnly }),
  list: (sessionId, parent) => invoke('safe_list', { sessionId, parent }),
  importFiles: (sessionId, parent) => invoke('safe_import', { sessionId, parent }),
  exportFile: (sessionId, entryId) => invoke('safe_export', { sessionId, entryId }),
  createDirectory: (sessionId, name, parent) => invoke('safe_create_directory', { sessionId, name, parent }),
  lock: (sessionId) => invoke('safe_lock', { sessionId }),
};

export function message(error: unknown): string {
  if (error && typeof error === 'object' && 'code' in error &&
      typeof error.code === 'string' && Object.hasOwn(en.errors, error.code)) {
    return en.errors[error.code as keyof typeof en.errors];
  }
  return en.genericError;
}
