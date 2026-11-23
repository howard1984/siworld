import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  fullyParallel: false,
  retries: 0,
  reporter: 'list',
  outputDir: process.env.SIVAULT_EVIDENCE_DIR ?? '/private/tmp/sivault-desktop-e2e',
  use: { channel: 'chrome', baseURL: process.env.SIVAULT_PREVIEW_URL ?? 'http://127.0.0.1:1420', trace: 'retain-on-failure' },
  projects: [
    { name: 'desktop', use: { viewport: { width: 1280, height: 800 } } },
    { name: 'native-default', use: { viewport: { width: 1000, height: 680 } } },
    { name: 'native-minimum', use: { viewport: { width: 360, height: 500 } } },
    { name: 'mobile', use: { viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true } },
  ],
});
