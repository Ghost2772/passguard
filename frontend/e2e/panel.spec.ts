import { test, expect, request } from '@playwright/test';
import type { APIRequestContext, Page } from '@playwright/test';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';

const prefix = '/api/control';
const checks: Record<string, boolean> = {};
const users: Record<string, { id: string; username: string; password: string }> = {};
const created: string[] = [];
let admin: APIRequestContext;
let adminCsrf = '';
let reportId = '';

function requireStatus(status: number, expected: number) {
  if (status !== expected) throw new Error(`Unexpected API status: ${status}; expected ${expected}`);
}
async function login(page: Page, role: string) {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Вход в PassGuard' })).toBeVisible();
  await page.getByLabel('Логин', { exact: true }).fill(users[role].username);
  await page.getByLabel('Пароль', { exact: true }).fill(users[role].password);
  await page.getByRole('button', { name: 'Войти в панель' }).click();
  await expect(page.getByRole('heading', { name: 'Обзор безопасности' })).toBeVisible();
}

// This suite is only for the disposable CI stack. It never changes the real
// bootstrap administrator's password; all browser accounts are disabled after.
test.describe.configure({ mode: 'serial' });
test.beforeAll(async ({ baseURL }) => {
  // Operator files stay root-owned/0600. Read inside the existing tools
  // container and capture stdout in memory; never chmod or log credentials.
  let initial: { username: string; password: string };
  try {
    const content = execFileSync('docker', ['compose', 'run', '--rm', '-T', '--no-deps', 'tools', 'python', '-c',
      'import json;from scripts.common import state_dir;x=json.loads((state_dir()/"operator/control-admin.json").read_text());print(json.dumps({k:x[k] for k in ("username","password")}))'],
      { cwd: resolve('..'), encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
    initial = JSON.parse(content);
  } catch { throw new Error('Could not read test login through the operator container'); }
  admin = await request.newContext({ baseURL });
  const response = await admin.post(prefix + '/auth/login', { data: { username: initial.username, password: initial.password } });
  requireStatus(response.status(), 200); adminCsrf = (await response.json()).csrf_token;
  for (const role of ['admin', 'operator', 'auditor']) {
    const username = 'ui_' + role + '_' + randomBytes(5).toString('hex');
    const password = randomBytes(24).toString('base64url');
    const createdUser = await admin.post(prefix + '/users', { headers: { 'X-CSRF-Token': adminCsrf }, data: { username, password, role } });
    requireStatus(createdUser.status(), 201);
    const data = await createdUser.json(); created.push(data.id); users[role] = { id: data.id, username, password };
  }
});

test.afterAll(async () => {
  if (admin && adminCsrf) {
    for (const id of created) await admin.patch(prefix + '/users/' + id, { headers: { 'X-CSRF-Token': adminCsrf }, data: { active: false } }).catch(() => {});
    await admin.post(prefix + '/auth/logout', { headers: { 'X-CSRF-Token': adminCsrf } }).catch(() => {});
    await admin.dispose();
  }
  const directory = resolve('..', 'reports'); await mkdir(directory, { recursive: true });
  await writeFile(resolve(directory, 'panel-browser.json'), JSON.stringify({ status: Object.keys(checks).length === 5 && Object.values(checks).every(Boolean) ? 'passed' : 'failed', checked_at: new Date().toISOString(), checks }, null, 2));
});

test('administrator rotates once after a lost response and manages user access', async ({ page }) => {
  await login(page, 'admin');
  if (process.env.PASSGUARD_VISUAL_QA === '1') {
    await expect(page.getByText('Хранилище и база доступны', { exact: true })).toBeVisible();
    await page.evaluate(() => document.fonts.ready);
    const png = await page.screenshot();
    console.log('PASSGUARD_OVERVIEW_PNG=' + png.toString('base64'));
  }
  const cookie = (await page.context().cookies()).find(cookie => cookie.name === 'passguard_session');
  expect(cookie?.httpOnly).toBe(true); expect(cookie?.sameSite).toBe('Strict');
  expect(await page.evaluate(() => document.cookie.includes('passguard_session'))).toBe(false);
  await page.getByRole('link', { name: 'Секреты', exact: true }).click();
  await page.getByRole('button', { name: 'Заменить пароль', exact: true }).click();
  const keys: string[] = [];
  await page.route('**/api/control/secrets/demo-db/rotate', async route => {
    keys.push(route.request().postDataJSON().idempotency_key);
    if (keys.length === 1) { const response = await route.fetch(); requireStatus(response.status(), 200); await route.abort('failed'); }
    else await route.continue();
  });
  await page.getByRole('button', { name: 'Подтвердить замену' }).click();
  await expect(page.getByRole('dialog').getByText(/Результат не подтверждён/)).toBeVisible();
  const replayResponse = page.waitForResponse(response => response.url().endsWith('/secrets/demo-db/rotate') && response.status() === 200);
  await page.getByRole('button', { name: 'Повторить запрос', exact: true }).click();
  expect((await (await replayResponse).json()).replayed).toBe(true);
  await expect(page.getByRole('dialog').getByRole('heading', { name: 'Пароль заменён' })).toBeVisible();
  expect(keys.length).toBe(2); expect(keys[0]).toBe(keys[1]);
  await page.getByRole('button', { name: 'Готово', exact: true }).click();
  await page.unroute('**/api/control/secrets/demo-db/rotate');
  await page.getByRole('button', { name: 'Проверить приложение', exact: true }).click();
  await expect(page.getByText('Приложение доступно', { exact: true })).toBeVisible();
  await page.getByRole('link', { name: 'Пользователи', exact: true }).click();
  await page.getByRole('button', { name: 'Добавить пользователя' }).click();
  const username = 'ui_created_' + randomBytes(5).toString('hex');
  await page.getByRole('dialog').getByLabel('Логин', { exact: true }).fill(username);
  await page.getByRole('dialog').getByLabel('Первоначальный пароль').fill(randomBytes(24).toString('base64url'));
  const createResponse = page.waitForResponse(response => response.url().endsWith('/users') && response.request().method() === 'POST');
  await page.getByRole('button', { name: 'Создать пользователя', exact: true }).click();
  const response = await createResponse; requireStatus(response.status(), 201); created.push((await response.json()).id);
  const row = page.getByRole('row').filter({ hasText: username });
  await row.getByRole('button', { name: `Изменить доступ ${username}` }).click();
  await page.getByRole('dialog').getByLabel('Роль', { exact: true }).selectOption('auditor');
  await page.getByRole('dialog').getByLabel('Доступ включён', { exact: true }).uncheck();
  await page.getByRole('button', { name: 'Сохранить изменения' }).click();
  await expect(row.getByText('Аудитор', { exact: true })).toBeVisible();
  await expect(row.getByText('Отключён', { exact: true })).toBeVisible();
  await page.getByRole('link', { name: 'Журнал действий', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Журнал действий' })).toBeVisible();
  checks.admin_rotation_retry_and_user_management = true;
});

test('operator uploads a ZIP and exports findings without secret values or HTML execution', async ({ page }) => {
  await login(page, 'operator');
  await expect(page.getByRole('link', { name: 'Пользователи', exact: true })).toHaveCount(0);
  await page.getByRole('link', { name: 'Секреты', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Заменить пароль', exact: true })).toHaveCount(0);
  await page.getByRole('link', { name: 'Проверка исходников', exact: true }).click();
  const secret = 'Educational-' + randomBytes(20).toString('hex');
  const filename = 'src/<img onerror=window.injected=1>.py';
  const archive = execFileSync('python', ['-c', 'import io,json,sys,zipfile\nx=json.load(sys.stdin);b=io.BytesIO()\nwith zipfile.ZipFile(b,"w",zipfile.ZIP_DEFLATED) as z:z.writestr(x["path"],x["content"])\nsys.stdout.buffer.write(b.getvalue())'], { input: JSON.stringify({ path: filename, content: `password = "${secret}"\n` }) });
  await page.getByLabel('ZIP с исходниками', { exact: true }).setInputFiles({ name: 'educational-source.zip', mimeType: 'application/zip', buffer: archive });
  await page.getByRole('button', { name: 'Проверить исходники', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Отчёт по исходникам' })).toBeVisible();
  await expect(page.getByText(filename, { exact: true })).toBeVisible();
  reportId = new URL(page.url()).hash.split('/').pop()!;
  expect(await page.locator('img[onerror]').count()).toBe(0);
  expect(await page.evaluate(() => 'injected' in window)).toBe(false);
  expect(await page.locator('body').innerText()).not.toContain(secret);
  expect(await page.evaluate(() => localStorage.length + sessionStorage.length)).toBe(0);
  const downloadEvent = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Скачать JSON', exact: true }).click();
  const download = await downloadEvent; const stream = await download.createReadStream();
  const chunks: Buffer[] = []; for await (const chunk of stream!) chunks.push(chunk);
  const content = Buffer.concat(chunks).toString('utf8');
  expect(content.includes(secret)).toBe(false);
  expect(JSON.parse(content).result.findings.some((finding: { rule_id: string }) => finding.rule_id === 'passguard-hardcoded-password')).toBe(true);
  await download.delete();
  await page.goto('/#/users');
  await expect(page.getByRole('heading', { name: 'Доступ ограничен' })).toBeVisible();
  checks.operator_scan_download_and_html_escaping = true;
});

test('auditor reads reports and audit while scan writes remain forbidden', async ({ page }) => {
  await login(page, 'auditor');
  await page.goto('/#/scans');
  await expect(page.getByLabel('ZIP с исходниками', { exact: true })).toHaveCount(0);
  await page.goto('/#/scans/' + reportId);
  await expect(page.getByRole('heading', { name: 'Отчёт по исходникам' })).toBeVisible();
  const me = await page.request.get(prefix + '/auth/me'); const csrf = (await me.json()).csrf_token;
  const write = await page.request.post(prefix + '/scans', { headers: { 'X-CSRF-Token': csrf, 'Content-Type': 'application/zip' }, data: Buffer.from('not-a-zip') });
  expect(write.status()).toBe(403);
  await page.getByRole('link', { name: 'Журнал действий', exact: true }).click();
  await expect(page.getByRole('table')).toBeVisible();
  await page.getByRole('button', { name: 'Подробнее', exact: true }).first().click();
  await expect(page.getByRole('dialog').getByRole('heading', { name: 'Сведения о событии' })).toBeVisible();
  await page.getByRole('dialog').getByRole('button', { name: 'Закрыть', exact: true }).last().click();
  await page.getByRole('button', { name: 'Выйти', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Вход в PassGuard' })).toBeVisible();
  checks.auditor_read_only_and_logout = true;
});

test('personal password change ends the session and accepts the new password', async ({ page }) => {
  await login(page, 'operator');
  await page.getByRole('link', { name: 'Мой аккаунт', exact: true }).click();
  const password = randomBytes(24).toString('base64url');
  await page.getByLabel('Текущий пароль', { exact: true }).fill(users.operator.password);
  await page.getByLabel('Новый пароль', { exact: true }).fill(password);
  await page.getByLabel('Повторите новый пароль', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Сменить пароль', exact: true }).click();
  await expect(page.getByText('Пароль изменён. Войдите с новым паролем.', { exact: true })).toBeVisible();
  users.operator.password = password;
  await login(page, 'operator');
  checks.password_change_and_session_revocation = true;
});

test('mobile navigation and report layout fit a narrow viewport', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await login(page, 'operator');
  await page.getByRole('button', { name: 'Открыть меню', exact: true }).click();
  const menu = page.getByRole('dialog');
  await expect(menu).toBeVisible();
  await menu.getByRole('link', { name: 'Проверка исходников', exact: true }).click();
  await expect(menu).not.toBeVisible();
  await expect(page.getByRole('heading', { name: 'Проверка исходников' })).toBeVisible();
  if (process.env.PASSGUARD_VISUAL_QA === '1') {
    await page.evaluate(() => document.fonts.ready);
    const png = await page.screenshot();
    console.log('PASSGUARD_MOBILE_PNG=' + png.toString('base64'));
  }
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.goto('/#/scans/' + reportId);
  await expect(page.getByRole('heading', { name: 'Отчёт по исходникам' })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  checks.mobile_navigation_and_layout = true;
});
