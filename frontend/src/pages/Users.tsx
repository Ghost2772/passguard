import { useCallback, useState } from 'react';
import type { FormEvent } from 'react';
import { ChevronLeft, ChevronRight, Plus, Search, Settings2, ShieldCheck, Users } from 'lucide-react';
import { errorMessage } from '../api';
import { useAuth } from '../auth';
import { Alert, Badge, Button, dateTime, Empty, ErrorState, Loading, Modal, PageTitle, PasswordInput, useResource } from '../components';
import type { Role, User } from '../types';
import { roleNames } from '../types';

const PAGE_SIZE = 25;
const descriptions = { admin: 'Ротация, проверки, пользователи и журнал.', operator: 'Проверка исходников и доступности приложения.', auditor: 'Просмотр отчётов и журнала действий.' };

export function UsersPage() {
  const { api, user, endSession, notify } = useAuth();
  const [offset, setOffset] = useState(0);
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('');
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<User | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [newRole, setNewRole] = useState<Role>('operator');
  const load = useCallback((signal: AbortSignal) => api.request<{ items: User[] }>(`/users?limit=${PAGE_SIZE}&offset=${offset}`, { signal }), [api, offset]);
  const state = useResource(load);
  const items = state.data?.items.filter(item => item.username.toLowerCase().includes(search.toLowerCase()) && (!status || item.active === (status === 'active'))) || [];
  async function createUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); const form = event.currentTarget; const fields = new FormData(form);
    const body = { username: String(fields.get('username')), password: String(fields.get('password')), role: newRole };
    setBusy(true); setError('');
    try { await api.request<User>('/users', { method: 'POST', body }); form.reset(); setCreating(false); notify('Пользователь создан.'); state.reload(); }
    catch (error) { setError(errorMessage(error)); }
    finally { body.password = ''; const password = form.elements.namedItem('password') as HTMLInputElement | null; if (password) password.value = ''; setBusy(false); }
  }
  async function updateUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); if (!editing) return; const fields = new FormData(event.currentTarget);
    const body = { role: String(fields.get('role')) as Role, active: fields.get('active') === 'on' };
    setBusy(true); setError('');
    try {
      const result = await api.request<User>('/users/' + editing.id, { method: 'PATCH', body });
      if (result.id === user!.id && (result.role !== user!.role || !result.active)) { endSession('Ваш доступ изменён. Войдите снова.'); return; }
      setEditing(null); notify('Права пользователя обновлены.'); state.reload();
    } catch (error) { setError(errorMessage(error)); }
    finally { setBusy(false); }
  }
  return <><PageTitle eyebrow="РАЗГРАНИЧЕНИЕ ДОСТУПА" title="Пользователи" action={<Button onClick={() => { setError(''); setNewRole('operator'); setCreating(true); }}><Plus size={17} />Добавить пользователя</Button>}>Выдавайте доступ по задачам и отзывайте его, когда он больше не нужен.</PageTitle>
    <div className="role-grid">{(Object.keys(roleNames) as Role[]).map(role => <div className="role-card" key={role}><span className="role-icon">{role === 'admin' ? <ShieldCheck size={21} /> : role === 'operator' ? <Settings2 size={21} /> : <Users size={21} />}</span><h3>{roleNames[role]}</h3><p>{descriptions[role]}</p></div>)}</div>
    <section className="card"><div className="table-toolbar"><div className="search-input"><Search size={17} /><input aria-label="Поиск пользователей на странице" placeholder="Поиск по этой странице" value={search} onChange={event => setSearch(event.target.value)} /></div><select aria-label="Статус пользователя" value={status} onChange={event => setStatus(event.target.value)}><option value="">Все статусы</option><option value="active">Активные</option><option value="disabled">Отключённые</option></select></div>
      {state.loading ? <Loading /> : state.error ? <ErrorState error={state.error} retry={state.reload} /> : items.length ? <div className="table-wrap"><table><thead><tr><th>Пользователь</th><th>Роль</th><th>Статус</th><th>Дата создания</th><th aria-label="Изменить доступ" /></tr></thead><tbody>{items.map(item => <tr key={item.id}><td><div className="user-cell"><span className="table-avatar">{item.username.slice(0, 2).toUpperCase()}</span><div><strong>{item.username}</strong>{item.id === user!.id && <span className="table-subtitle">Это вы</span>}</div></div></td><td>{roleNames[item.role]}</td><td><Badge tone={item.active ? 'green' : 'neutral'} dot>{item.active ? 'Активен' : 'Отключён'}</Badge></td><td className="muted nowrap">{dateTime(item.created_at)}</td><td><button className="text-button" aria-label={`Изменить доступ ${item.username}`} onClick={() => { setError(''); setEditing(item); }}>Изменить доступ</button></td></tr>)}</tbody></table></div> : <Empty icon={<Users size={28} />} title="Пользователи по фильтру не найдены">Измените условия поиска или откройте следующую страницу.</Empty>}
      <div className="table-footer"><span>Страница {offset / PAGE_SIZE + 1}</span><div><Button variant="ghost" disabled={!offset || state.loading} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}><ChevronLeft size={15} />Назад</Button><Button variant="ghost" disabled={state.loading || !state.data || state.data.items.length < PAGE_SIZE} onClick={() => setOffset(offset + PAGE_SIZE)}>Далее<ChevronRight size={15} /></Button></div></div>
    </section><div className="workspace-note"><ShieldCheck size={17} /><p>Смена роли и отключение пользователя завершают его действующие сессии. Последнего активного администратора отключить нельзя.</p></div>
    {creating && <Modal title="Новый пользователь" onClose={() => setCreating(false)} busy={busy}><form className="form-stack" onSubmit={createUser}>{error && <Alert>{error}</Alert>}<label>Логин<input name="username" autoComplete="off" minLength={3} maxLength={64} pattern="[a-zA-Z0-9][a-zA-Z0-9_.-]*" placeholder="Например, security_operator" required /></label><label>Первоначальный пароль<PasswordInput name="password" autoComplete="new-password" minLength={15} maxLength={128} required /></label><p className="form-hint">От 15 до 128 символов. Передайте пароль пользователю по защищённому каналу.</p><label>Роль<select value={newRole} onChange={event => setNewRole(event.target.value as Role)}>{Object.entries(roleNames).map(([role, label]) => <option key={role} value={role}>{label}</option>)}</select></label><p className="role-description">{descriptions[newRole]}</p><div className="modal-footer"><Button type="button" variant="ghost" onClick={() => setCreating(false)} disabled={busy}>Отмена</Button><Button type="submit" busy={busy}>Создать пользователя</Button></div></form></Modal>}
    {editing && <Modal title="Изменение доступа" onClose={() => setEditing(null)} busy={busy}><form className="form-stack" onSubmit={updateUser}><p className="modal-description">Пользователь <strong>{editing.username}</strong></p>{error && <Alert>{error}</Alert>}<label>Роль<select name="role" defaultValue={editing.role}>{Object.entries(roleNames).map(([role, label]) => <option key={role} value={role}>{label}</option>)}</select></label><label className="checkbox-label"><input type="checkbox" name="active" defaultChecked={editing.active} />Доступ включён</label><Alert tone="info">Если изменить роль или отключить доступ, текущие сессии пользователя будут завершены.</Alert><div className="modal-footer"><Button type="button" variant="ghost" disabled={busy} onClick={() => setEditing(null)}>Отмена</Button><Button type="submit" busy={busy}>Сохранить изменения</Button></div></form></Modal>}
  </>;
}
