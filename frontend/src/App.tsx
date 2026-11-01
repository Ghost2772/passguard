import { useEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { ArrowRight, CheckCircle2, ChevronRight, CircleHelp, FileSearch, Fingerprint, KeyRound, LayoutDashboard, ListChecks, LoaderCircle, LogOut, Menu, Settings2, ShieldCheck, Users, X } from 'lucide-react';
import { ApiError, errorMessage } from './api';
import { useAuth } from './auth';
import { Alert, Badge, Brand, Button, Loading, PasswordInput } from './components';
import { OverviewPage } from './pages/Overview';
import { SecretsPage } from './pages/Secrets';
import { ScansPage } from './pages/Scans';
import { AuditPageView } from './pages/Audit';
import { UsersPage } from './pages/Users';
import { AccountPage } from './pages/Account';
import type { Operation, RotationReason, Session } from './types';
import { roleNames } from './types';

const navigation = [
  { id: 'overview', label: 'Обзор', icon: LayoutDashboard, roles: ['admin', 'operator', 'auditor'] },
  { id: 'secrets', label: 'Секреты', icon: KeyRound, roles: ['admin', 'operator', 'auditor'] },
  { id: 'scans', label: 'Проверка исходников', icon: FileSearch, roles: ['admin', 'operator', 'auditor'] },
  { id: 'audit', label: 'Журнал действий', icon: ListChecks, roles: ['admin', 'auditor'] },
  { id: 'users', label: 'Пользователи', icon: Users, roles: ['admin'] },
];
export interface RotationAttempt { id: string; reason: RotationReason; operation: Operation | null; uncertain: boolean }

function useRoute() {
  const [hash, setHash] = useState(window.location.hash);
  useEffect(() => { const changed = () => setHash(window.location.hash); window.addEventListener('hashchange', changed); return () => window.removeEventListener('hashchange', changed); }, []);
  const parts = hash.replace(/^#\/?/, '').split('/');
  return { page: parts[0] || 'overview', id: parts[1] || '' };
}

function Login() {
  const { api, acceptSession, loginMessage } = useAuth();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  async function login(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const fields = new FormData(form);
    const credentials = { username: String(fields.get('username') || ''), password: String(fields.get('password') || '') };
    setBusy(true); setError('');
    try {
      const session = await api.request<Session>('/auth/login', { method: 'POST', body: credentials, silent401: true });
      form.reset();
      acceptSession(session);
      window.location.hash = '/overview';
    } catch (error) {
      setError(error instanceof ApiError && error.status === 401 ? 'Неверный логин или пароль.' : errorMessage(error));
    } finally {
      const field = form.elements.namedItem('password') as HTMLInputElement | null;
      if (field) field.value = '';
      credentials.password = '';
      setBusy(false);
    }
  }
  return <div className="login-layout">
    <section className="login-story"><Brand light /><div className="login-story-content"><div className="eyebrow">КОНТРОЛЬ НА КАЖДОМ ЭТАПЕ</div>
      <h1>Секреты —<br />под вашей<br /><span>защитой.</span></h1>
      <p>Храните централизованно. Меняйте вовремя.<br />Замечайте то, что не должно попасть в код.</p>
      <div className="security-orbit" aria-hidden="true"><div className="orbit-ring ring-one" /><div className="orbit-ring ring-two" /><div className="orbit-shield"><ShieldCheck size={68} strokeWidth={1} /></div><span className="orbit-label orbit-label-one"><KeyRound size={15} /> Защищённое хранение</span><span className="orbit-label orbit-label-two"><Fingerprint size={15} /> Доступ по ролям</span><span className="orbit-label orbit-label-three"><FileSearch size={15} /> Проверка исходников</span></div>
    </div><div className="login-story-footer"><span className="tiny-square" /> PASSGUARD / УПРАВЛЕНИЕ СЕКРЕТАМИ</div></section>
    <main className="login-main"><div className="mobile-login-brand"><Brand /></div><div className="login-top"><Badge>Учебный стенд</Badge><span>Информационная безопасность</span></div>
      <div className="login-form-wrap"><div className="login-icon"><KeyRound size={25} strokeWidth={1.6} /></div><div className="eyebrow">ДОБРО ПОЖАЛОВАТЬ</div><h2>Вход в PassGuard</h2><p className="muted">Войдите, чтобы управлять секретами и проверками.</p>
        {loginMessage && <Alert tone="info">{loginMessage}</Alert>}{error && <Alert>{error}</Alert>}
        <form onSubmit={login} className="form-stack">
          <label>Логин<input name="username" autoComplete="username" minLength={3} maxLength={64} pattern="[a-zA-Z0-9][a-zA-Z0-9_.-]*" placeholder="Ваш логин" required autoFocus /></label>
          <label>Пароль<PasswordInput name="password" autoComplete="current-password" maxLength={128} placeholder="Введите пароль" required /></label>
          <Button type="submit" busy={busy} className="login-submit">Войти в панель{!busy && <ArrowRight size={18} />}</Button>
        </form>
        <div className="login-help"><CircleHelp size={18} /><p>Нет доступа? Обратитесь к администратору вашего стенда.</p></div>
      </div><div className="login-footer"><ShieldCheck size={16} /> Доступ к функциям определяется вашей ролью.</div>
    </main>
  </div>;
}

function Workspace() {
  const { user, api, endSession, notify, notice, dismissNotice } = useAuth();
  const route = useRoute();
  const [rotation, setRotation] = useState<RotationAttempt | null>(null);
  const [logoutBusy, setLogoutBusy] = useState(false);
  const menu = useRef<HTMLDialogElement>(null);
  const main = useRef<HTMLElement>(null);
  const allowed = navigation.filter(item => item.roles.includes(user!.role));
  const current = navigation.find(item => item.id === route.page);
  const forbidden = !!current && !current.roles.includes(user!.role);
  const known = !!current || route.page === 'account';
  useEffect(() => { menu.current?.close(); }, [route.page, route.id]);
  async function logout() {
    setLogoutBusy(true);
    try { await api.request('/auth/logout', { method: 'POST' }); endSession('Вы вышли из системы.'); }
    catch (error) { notify(errorMessage(error), 'error'); }
    finally { setLogoutBusy(false); }
  }
  function Sidebar({ mobile = false }) {
    return <><div className="sidebar-logo"><Brand light />{mobile && <button className="icon-button" onClick={() => menu.current?.close()} aria-label="Закрыть меню"><X size={21} /></button>}</div>
      <div className="workspace-label"><span className="workspace-initial">P</span><div><strong>Рабочее пространство</strong><span>Учебный стенд</span></div></div>
      <div className="nav-caption">УПРАВЛЕНИЕ</div><nav aria-label={mobile ? 'Мобильная навигация' : 'Основная навигация'}>{allowed.map(({ id, label, icon: Icon }) =>
        <a href={`#/${id}`} key={id} className={route.page === id ? 'nav-link active' : 'nav-link'} aria-current={route.page === id ? 'page' : undefined} onClick={() => menu.current?.close()}><Icon size={19} strokeWidth={1.6} /><span>{label}</span>{route.page === id && <span className="nav-active-dot" />}</a>)}</nav>
      <div className="sidebar-bottom"><div className="sidebar-security"><ShieldCheck size={23} /><strong>Каждому — свои права</strong><p>Доступ к секретам и действиям разделён по ролям.</p></div><a href="#/account" className={`nav-link ${route.page === 'account' ? 'active' : ''}`} aria-current={route.page === 'account' ? 'page' : undefined} onClick={() => menu.current?.close()}><Settings2 size={19} strokeWidth={1.6} /><span>Мой аккаунт</span></a><div className="sidebar-version">PASSGUARD <span>v0.4</span></div></div>
    </>;
  }
  return <div className="app-layout">
    <button className="skip-link" onClick={() => main.current?.focus()}>Перейти к содержимому</button>
    <aside className="sidebar"><Sidebar /></aside><dialog className="mobile-sidebar" ref={menu}><Sidebar mobile /></dialog>
    <div className="workspace"><header className="topbar"><div className="breadcrumb"><button className="icon-button mobile-menu-toggle" aria-label="Открыть меню" onClick={() => menu.current?.showModal()}><Menu size={21} /></button><span className="breadcrumb-home">Рабочее пространство</span><ChevronRight size={13} /><span>{current?.label || (route.page === 'account' ? 'Мой аккаунт' : 'Страница')}</span></div><div className="topbar-user"><div className="user-avatar">{user!.username.slice(0, 2).toUpperCase()}</div><div className="user-meta"><strong>{user!.username}</strong><span>{roleNames[user!.role]}</span></div><button className="icon-button logout-button" aria-label="Выйти" title="Выйти" onClick={logout} disabled={logoutBusy}>{logoutBusy ? <LoaderCircle size={18} className="spin" /> : <LogOut size={18} />}</button></div></header>
      <main className="main-content" ref={main} tabIndex={-1}>
        {forbidden ? <div className="permission-state"><ShieldCheck size={40} /><h1>Доступ ограничен</h1><p>Этот раздел недоступен вашей роли.</p><a className="button button-primary" href="#/overview">Вернуться к обзору</a></div> : !known ? <div className="permission-state"><h1>Страница не найдена</h1><a className="button button-primary" href="#/overview">Вернуться к обзору</a></div> : <>
          {route.page === 'overview' && <OverviewPage />}
          {route.page === 'secrets' && <SecretsPage attempt={rotation} onAttempt={setRotation} />}
          {route.page === 'scans' && <ScansPage reportId={route.id} />}
          {route.page === 'audit' && <AuditPageView />}
          {route.page === 'users' && <UsersPage />}
          {route.page === 'account' && <AccountPage />}
        </>}
        <footer className="workspace-footer"><span>PassGuard · Управление секретами</span><span><span className="footer-dot" /> Учебный стенд</span></footer>
      </main>
    </div>
    {notice && <div className={`toast toast-${notice.tone}`} role={notice.tone === 'error' ? 'alert' : 'status'}>{notice.tone === 'error' ? <CircleHelp size={20} /> : <CheckCircle2 size={20} />}<span>{notice.text}</span><button className="icon-button" aria-label="Закрыть уведомление" onClick={dismissNotice}><X size={17} /></button></div>}
  </div>;
}

export default function App() {
  const { user, loading } = useAuth();
  if (loading) return <div className="boot-screen"><Brand /><Loading label="Открываем рабочее пространство…" /></div>;
  return user ? <Workspace key={user.id} /> : <Login />;
}
