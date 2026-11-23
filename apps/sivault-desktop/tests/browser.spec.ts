import { expect, test } from '@playwright/test';

test('brand header renders without external asset requests', async ({ page, baseURL }) => {
  const externalRequests: string[] = [];
  page.on('request', (request) => {
    const url = new URL(request.url());
    if ((url.protocol === 'http:' || url.protocol === 'https:') &&
        url.origin !== new URL(baseURL!).origin) externalRequests.push(url.href);
  });
  await page.goto('/');
  const header = page.getByRole('banner');
  await expect(header.getByText('SIVault', { exact: true })).toBeVisible();
  await expect(header).toHaveCSS('background-color', 'rgb(6, 6, 6)');
  const mark = header.getByRole('img', { name: 'SIWORLD', exact: true });
  if (process.env.SIVAULT_EXPECT_BRAND === '1') await expect(mark).toBeVisible();
  if (await mark.count()) {
    await expect(mark).toHaveAttribute('src', /^data:image\/svg\+xml/);
    await expect.poll(() => mark.evaluate((element: HTMLImageElement) => element.naturalWidth)).toBeGreaterThan(0);
  }
  expect(externalRequests).toEqual([]);
});

test('wallet is loaded only on entry and failure does not block a safe', async ({ page }) => {
  const invocations: string[] = [];
  await page.exposeFunction('walletFixtureInvoke', (command: string) => {
    invocations.push(command);
    switch (command) {
      case 'safe_create':
        return { id: 'fixture', sessionId: 'open-1', name: 'Independent safe', readOnly: false };
      case 'safe_list':
        return [];
      case 'safe_lock':
        return null;
      case 'wallet_status':
        throw new Error('Worker not available');
      default:
        throw new Error('Unexpected command');
    }
  });
  await page.addInitScript(() => {
    const mock = window as Window & { walletFixtureInvoke: (...args: unknown[]) => Promise<unknown> };
    Object.assign(window, { isTauri: true, __TAURI_INTERNALS__: { invoke: mock.walletFixtureInvoke } });
  });
  await page.goto('/');
  await page.getByRole('button', { name: 'Create safe', exact: true }).first().click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('Safe name').fill('Independent safe');
  await dialog.getByRole('button', { name: 'Create safe', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Independent safe' })).toBeVisible();
  expect(invocations).toEqual(['safe_create', 'safe_list']);
  const sections = page.getByRole('navigation', { name: 'Application sections' });
  await sections.getByRole('button', { name: 'Wallet' }).click();
  await expect(page.getByText('The wallet process is not available.')).toBeVisible();
  expect(invocations.slice(0, 3)).toEqual(['safe_create', 'safe_list', 'safe_lock']);
  expect(new Set(invocations.slice(3))).toEqual(new Set(['wallet_status', 'wallet_endpoint']));
  await sections.getByRole('button', { name: 'Vault' }).click();
  await expect(page.getByRole('heading', { name: 'Safe locked' })).toBeVisible();
});

test('native renderer submits operations without credentials', async ({ page }) => {
  const requests: unknown[] = [];
  await page.exposeFunction('recordInvoke', (command: string, args: unknown) => {
    requests.push({ command, args });
    return null;
  });
  await page.addInitScript(() => {
    const mock = window as Window & { recordInvoke: (...args: unknown[]) => Promise<null> };
    Object.assign(window, { isTauri: true, __TAURI_INTERNALS__: { invoke: mock.recordInvoke } });
  });
  await page.goto('/');
  await expect(page.getByText('Development build. Not for distribution.')).toBeVisible();
  await page.getByRole('button', { name: 'Create safe', exact: true }).first().click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('Safe name').fill('Synthetic contract');
  await expect(dialog.locator('input[type=password]')).toHaveCount(0);
  await dialog.getByRole('button', { name: 'Create safe', exact: true }).click();
  await expect(dialog).not.toBeVisible();
  await page.getByRole('button', { name: 'Open existing safe', exact: true }).last().click();
  await expect(dialog.locator('input[type=password]')).toHaveCount(0);
  await dialog.getByLabel('Open read-only').check();
  await dialog.getByRole('button', { name: 'Choose safe' }).click();
  await expect(dialog).not.toBeVisible();
  expect(requests).toEqual([
    { command: 'safe_create', args: { name: 'Synthetic contract' } },
    { command: 'safe_open', args: { readOnly: true } },
  ]);
});

test('wallet endpoint persists through navigation without opening custody', async ({ page }, testInfo) => {
  const origin = 'http://127.0.0.1:8180';
  let saved: string | null = null;
  const changes: string[] = [];
  await page.exposeFunction('endpointInvoke', (command: string, args?: { origin: string }) => {
    switch (command) {
      case 'wallet_status': return false;
      case 'wallet_endpoint': return saved;
      case 'wallet_set_endpoint':
        changes.push(args!.origin);
        saved = args!.origin || null;
        return null;
      default: throw new Error('Unexpected command');
    }
  });
  await page.addInitScript(() => {
    const mock = window as Window & { endpointInvoke: (...args: unknown[]) => Promise<unknown> };
    Object.assign(window, { isTauri: true, __TAURI_INTERNALS__: { invoke: mock.endpointInvoke } });
  });
  await page.goto('/');
  const navigation = page.getByRole('navigation', { name: 'Application sections' });
  await navigation.getByRole('button', { name: 'Wallet' }).click();
  const input = page.getByLabel('Local node endpoint');
  const save = page.getByRole('button', { name: 'Save endpoint' });
  const create = page.getByRole('button', { name: 'Create wallet' });
  await expect(create).toBeVisible();
  expect((await create.boundingBox())!.y).toBeLessThan((await input.boundingBox())!.y);
  await page.screenshot({ path: testInfo.outputPath('wallet-setup.png'), fullPage: true });
  await input.fill(origin);
  await save.click();
  await expect(save).toBeDisabled();
  await navigation.getByRole('button', { name: 'Vault' }).click();
  await navigation.getByRole('button', { name: 'Wallet' }).click();
  await expect(input).toHaveValue(origin);
  await input.clear();
  await save.click();
  await expect(save).toBeDisabled();
  expect(changes).toEqual([origin, '']);
});

test('wallet shows fee, resolves errors, and distinguishes submission from inclusion', async ({ page }) => {
  const address = 'tsi1pwl6pnufr5kwq4a25yr4yneu2vk6qzt45sdy2urmqyvx75p69mtcq640vmd';
  const payment = { statement_id: 'aa'.repeat(32), amount_atoms: '300', fee_atoms: '25', height: null, acknowledged: true };
  let submissions = 0;
  await page.exposeFunction('paymentInvoke', (command: string, args: unknown) => {
    switch (command) {
      case 'wallet_status': return true;
      case 'wallet_endpoint': return 'http://127.0.0.1:8180';
      case 'wallet_access': return {
        address: 'fixture', short_address: address, published: true,
        chain: { height: 32, available_atoms: '5000', locked_atoms: '10', history: [],
          standard_fee_atoms: '25', payment: submissions > 1 ? { ...payment, height: 32 } : null },
      };
      case 'wallet_send':
        expect(args).toEqual({ recipient: address, amount: '300', fee: '25' });
        if (!submissions++) return Promise.reject({ code: 'WALLET_RECIPIENT_MISSING' });
        return payment;
      default: return null;
    }
  });
  await page.addInitScript(() => {
    const mock = window as Window & { paymentInvoke: (...args: unknown[]) => Promise<unknown> };
    Object.assign(window, { isTauri: true, __TAURI_INTERNALS__: {
      invoke: async (command: string, args: unknown) => {
        try { return await mock.paymentInvoke(command, args); }
        catch { throw { code: 'WALLET_RECIPIENT_MISSING' }; }
      },
    } });
  });
  await page.goto('/');
  await page.getByRole('navigation', { name: 'Application sections' }).getByRole('button', { name: 'Wallet' }).click();
  await expect(page.getByRole('banner').getByRole('status')).toHaveText('Node reachable');
  await page.getByRole('button', { name: 'Unlock wallet' }).click();
  await page.getByRole('button', { name: 'Send', exact: true }).click();
  await page.getByLabel('Recipient address', { exact: true }).fill(address);
  await page.getByLabel('Amount in SIP atoms').fill('300');
  await expect(page.getByText('Network fee: 25 SIP atoms')).toBeVisible();
  const review = page.getByRole('button', { name: 'Review payment' });
  await review.click();
  await expect(page.getByRole('alert')).toContainText('paste the full address');
  await review.click();
  await expect(page.getByText('Submitted. Waiting for block inclusion.')).toBeVisible();
  const send = page.getByRole('button', { name: 'Send', exact: true });
  await expect(send).toBeDisabled();
  await expect(send).toHaveAccessibleDescription('Send is unavailable until the previous payment is verified in a block.');
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await expect(page.getByText('Included in block 32')).toBeVisible();
  await expect(send).toBeEnabled();
});

test('controlled setup shows owner identifier without requesting secrets in the webview', async ({ page }) => {
  const identifier = 'a'.repeat(64);
  let finishEnrollment!: (result: null) => void;
  await page.exposeFunction('controlledInvoke', (command: string, args: unknown) => {
    if (command === 'owner_prepare') return true;
    if (command === 'owner_identifier') return identifier;
    if (command === 'safe_create_controlled') {
      expect(args).toEqual({ name: 'Fixture', address: '127.0.0.1:1234', identifier, allowance: 2 });
      return new Promise<null>((resolve) => { finishEnrollment = resolve; });
    }
    throw new Error(command);
  });
  await page.addInitScript(() => {
    const mock = window as Window & { controlledInvoke: (...args: unknown[]) => Promise<unknown> };
    Object.assign(window, { isTauri: true, __TAURI_INTERNALS__: { invoke: mock.controlledInvoke } });
  });
  await page.goto('/');
  await page.getByRole('button', { name: 'Create safe', exact: true }).first().click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('Safe name').fill('Fixture');
  await dialog.getByLabel('Safe type').selectOption('controlled');
  await dialog.getByRole('button', { name: 'Continue' }).click();
  await expect(dialog.getByText(identifier, { exact: true })).toBeVisible();
  await expect(dialog.locator('input[type=password]')).toHaveCount(0);
  await dialog.getByLabel('Local address').fill('127.0.0.1:1234');
  await dialog.getByLabel('Releaser identifier').fill(identifier);
  await dialog.getByRole('button', { name: 'Create safe' }).click();
  await expect(dialog.getByRole('status')).toContainText('Waiting for enrollment confirmation');
  finishEnrollment(null);
  await expect(dialog).not.toBeVisible();
});

test('releaser view follows the local ledger through exhaustion and revocation', async ({ page }) => {
  let status: { state: string; remaining?: number } = { state: 'active', remaining: 2 };
  await page.exposeFunction('releaserInvoke', (command: string) => {
    expect(command).toBe('releaser_status');
    return { address: '127.0.0.1:1234', identifier: 'b'.repeat(64), enrolled: true, ledger: status };
  });
  await page.addInitScript(() => {
    const mock = window as Window & { releaserInvoke: (...args: unknown[]) => Promise<unknown> };
    Object.assign(window, { isTauri: true, __TAURI_INTERNALS__: { invoke: mock.releaserInvoke } });
  });
  await page.goto('/');
  await page.getByRole('button', { name: 'Releaser', exact: true }).click();
  await expect(page.getByRole('status')).toHaveText('2 attempts remaining');
  status = { state: 'active', remaining: 0 };
  await expect(page.getByRole('status')).toHaveText('Attempt allowance exhausted');
  status = { state: 'revoked' };
  await expect(page.getByRole('status')).toHaveText('Access revoked');
});

test('compact vault keeps actions and the file table near the top', async ({ page }, testInfo) => {
  await page.goto('/');
  await page.keyboard.press('Tab');
  await expect(page.getByRole('link', { name: 'Skip to files' })).toBeFocused();
  const header = page.getByRole('banner');
  expect((await header.boundingBox())!.height).toBeLessThanOrEqual(50);
  expect((await page.getByRole('heading', { name: 'No safe selected' }).boundingBox())!.y).toBeLessThan(255);
  await page.screenshot({ path: testInfo.outputPath('vault-empty.png'), fullPage: true });
  await page.getByRole('button', { name: 'Open synthetic demo' }).click();
  const table = page.getByRole('table');
  await expect(table).toBeVisible();
  expect((await table.boundingBox())!.y).toBeLessThan(290);
  const details = page.getByRole('complementary', { name: 'Item details' });
  await expect(details).toHaveCount(0);
  await page.getByRole('button', { name: 'Documents', exact: true }).click();
  const file = page.getByRole('button', { name: 'Sample record.txt' });
  await file.focus();
  await page.keyboard.press('Enter');
  await expect(details.getByRole('heading', { name: 'Sample record.txt' })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: testInfo.outputPath('vault-detail.png'), fullPage: true });
});

test('synthetic browser create, import, lock, open, read-only and export', async ({ page }, testInfo) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.goto('/');
  await expect(page.getByRole('button', { name: 'Create safe', exact: true }).first()).toBeDisabled();
  await page.getByRole('button', { name: 'Open synthetic demo' }).click();
  await expect(page.getByText('Synthetic demo · memory only · no encryption')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Personal archive', exact: true })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath('browser-files.png'), fullPage: true });
  await page.getByRole('button', { name: 'Documents', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Sample record.txt' })).toBeVisible();
  await page.getByRole('button', { name: 'All files', exact: true }).click();
  await page.getByRole('button', { name: 'Create safe', exact: true }).first().click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('Safe name').fill('Synthetic work archive');
  await expect(dialog.getByLabel('Password', { exact: true })).toHaveCount(0);
  await dialog.getByRole('button', { name: 'Create safe', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'This folder is empty' })).toBeVisible();
  await page.getByRole('button', { name: 'New folder', exact: true }).click();
  await dialog.getByLabel('Folder name').fill('Documents');
  await dialog.getByRole('button', { name: 'Create folder' }).click();
  await page.getByRole('button', { name: 'Documents', exact: true }).click();
  await page.getByRole('button', { name: 'Import sample', exact: true }).first().click();
  await expect(page.getByRole('button', { name: 'Sample import 1.txt', exact: true })).toBeVisible();
  await page.getByLabel('Search this folder').fill('missing-file');
  await expect(page.getByRole('heading', { name: 'No matching files' })).toBeVisible();
  await page.getByLabel('Search this folder').clear();
  await page.getByRole('button', { name: 'Sample import 1.txt', exact: true }).click();
  await page.screenshot({ path: testInfo.outputPath('browser-selected.png'), fullPage: true });
  await page.getByRole('button', { name: 'Lock safe', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Safe locked', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Sample import 1.txt', exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Open safe', exact: true }).first().click();
  await dialog.getByLabel('Open read-only').check();
  await dialog.getByRole('button', { name: 'Open safe', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Import sample', exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'New folder', exact: true })).toBeDisabled();
  await page.getByRole('button', { name: 'Documents', exact: true }).click();
  await page.getByRole('button', { name: 'Sample import 1.txt', exact: true }).click();
  await page.getByRole('button', { name: 'Export selected file', exact: true }).click();
  await expect(dialog.getByText('The exported copy will be unencrypted.')).toBeVisible();
  const downloadPromise = page.waitForEvent('download');
  await dialog.getByRole('button', { name: 'Choose destination', exact: true }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe('Sample import 1.txt');
  await download.delete();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  expect(errors).toEqual([]);
  await page.screenshot({ path: testInfo.outputPath('browser-readonly.png'), fullPage: true });
});
