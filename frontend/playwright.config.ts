import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 60000,
  expect: { timeout: 15000 },
  reporter: 'line',
  use: {
    baseURL: process.env.PASSGUARD_BASE_URL || 'http://127.0.0.1:8000',
    browserName: 'chromium',
    viewport: { width: 1440, height: 1000 },
    trace: 'off', screenshot: 'off', video: 'off',
  },
});
