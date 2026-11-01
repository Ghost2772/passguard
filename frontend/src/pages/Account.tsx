import { useState } from 'react';
import type { FormEvent } from 'react';
import { Fingerprint, KeyRound, ShieldCheck } from 'lucide-react';
import { errorMessage } from '../api';
import { useAuth } from '../auth';
import { Alert, Badge, Button, dateTime, PageTitle, PasswordInput } from '../components';
import { roleNames } from '../types';

export function AccountPage() {
  const { api, user, endSession } = useAuth();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  async function changePassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); const form = event.currentTarget; const data = new FormData(form);
    const body = { current_password: String(data.get('current')), new_password: String(data.get('new')) };
    if (body.new_password !== data.get('confirm')) { setError('Новые пароли не совпадают.'); return; }
    setBusy(true); setError('');
    try { await api.request('/auth/password', { method: 'POST', body }); form.reset(); endSession('Пароль изменён. Войдите с новым паролем.'); }
    catch (error) { setError(errorMessage(error)); }
    finally { body.current_password = ''; body.new_password = ''; form.reset(); setBusy(false); }
  }
  return <><PageTitle eyebrow="ЛИЧНЫЕ НАСТРОЙКИ" title="Мой аккаунт">Ваш доступ и безопасность учётной записи.</PageTitle><div className="account-layout"><section className="card padded-card account-profile"><span className="account-avatar">{user!.username.slice(0, 2).toUpperCase()}</span><h2>{user!.username}</h2><Badge tone="green">{roleNames[user!.role]}</Badge><dl className="details-list"><div><dt>Статус</dt><dd>Активен</dd></div><div><dt>Создан</dt><dd>{dateTime(user!.created_at)}</dd></div></dl><div className="account-note"><Fingerprint size={20} /><p>Права доступа назначаются администратором стенда.</p></div></section><section className="card padded-card password-card"><div className="card-heading"><div><span className="section-kicker">БЕЗОПАСНОСТЬ</span><h2>Смена пароля</h2></div><KeyRound size={21} /></div><p className="muted">После смены пароля все ваши сессии будут завершены.</p><form onSubmit={changePassword} className="form-stack">{error && <Alert>{error}</Alert>}<label>Текущий пароль<PasswordInput name="current" autoComplete="current-password" maxLength={128} required /></label><label>Новый пароль<PasswordInput name="new" autoComplete="new-password" minLength={15} maxLength={128} required /></label><p className="form-hint">Используйте уникальный пароль от 15 до 128 символов.</p><label>Повторите новый пароль<PasswordInput name="confirm" autoComplete="new-password" minLength={15} maxLength={128} required /></label><div className="form-actions"><Button type="submit" busy={busy}>Сменить пароль</Button></div></form></section></div><div className="workspace-note"><ShieldCheck size={17} /><p>Не используйте пароль от стенда для других сервисов.</p></div></>;
}
