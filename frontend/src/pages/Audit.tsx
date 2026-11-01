import { useCallback, useState } from 'react';
import { ChevronLeft, ChevronRight, ListChecks, RefreshCw, Search } from 'lucide-react';
import { useAuth } from '../auth';
import { Badge, Button, dateTime, Empty, ErrorState, Loading, Modal, PageTitle, useResource } from '../components';
import type { AuditEvent, AuditPage } from '../types';
import { reasonNames, roleNames } from '../types';

const actionNames: Record<string, string> = {
  'auth.login': 'Вход в систему', 'auth.logout': 'Выход из системы', 'auth.password_change': 'Смена личного пароля',
  'auth.rate_limited': 'Ограничение попыток входа', 'users.bootstrap': 'Создание администратора',
  'users.create': 'Создание пользователя', 'users.update': 'Изменение доступа', 'access.denied': 'Отказ в доступе',
  'csrf.denied': 'Отклонение запроса', 'secrets.rotate': 'Замена пароля базы', 'checks.demo': 'Проверка приложения', 'scans.create': 'Проверка исходников',
};
const outcomeNames: Record<string, string> = { success: 'Успешно', denied: 'Отказано', started: 'Начато', failed: 'Ошибка', unknown: 'Не подтверждено' };
const detailNames: Record<string, string> = { operation_id: 'Операция', secret_id: 'Секрет', scan_id: 'Проверка', user_id: 'Пользователь', reason: 'Причина', role: 'Роль', active: 'Доступ включён', route: 'Запрошенная операция', code: 'Код результата', files_scanned: 'Проверено файлов', findings_count: 'Находок', skipped_count: 'Пропущено файлов' };
export function actionName(action: string) { return actionNames[action] || action; }
function detailValue(key: string, value: unknown) {
  if (value === null) return '—';
  if (typeof value === 'boolean') return value ? 'Да' : 'Нет';
  if (key === 'role' && String(value) in roleNames) return roleNames[value as keyof typeof roleNames];
  if (key === 'reason' && String(value) in reasonNames) return reasonNames[value as keyof typeof reasonNames];
  return String(value);
}

export function AuditPageView() {
  const { api } = useAuth();
  const [cursor, setCursor] = useState<number | null>(null);
  const [history, setHistory] = useState<(number | null)[]>([]);
  const [search, setSearch] = useState('');
  const [outcome, setOutcome] = useState('');
  const [selected, setSelected] = useState<AuditEvent | null>(null);
  const load = useCallback((signal: AbortSignal) => api.request<AuditPage>(`/audit?limit=25${cursor ? '&before_id=' + cursor : ''}`, { signal }), [api, cursor]);
  const state = useResource(load);
  const items = state.data?.items.filter(event => (!outcome || event.outcome === outcome) && `${actionName(event.action)} ${event.actor_username || ''} ${event.action}`.toLowerCase().includes(search.toLowerCase())) || [];
  return <><PageTitle eyebrow="ПРОЗРАЧНОСТЬ И КОНТРОЛЬ" title="Журнал действий" action={<Button variant="secondary" busy={state.loading} onClick={state.reload}><RefreshCw size={16} />Обновить</Button>}>Кто, когда и с каким результатом работал со стендом.</PageTitle>
    <section className="card"><div className="table-toolbar"><div className="search-input"><Search size={17} /><input aria-label="Поиск по журналу на странице" value={search} onChange={event => setSearch(event.target.value)} placeholder="Поиск по этой странице" /></div><select aria-label="Результат действия" value={outcome} onChange={event => setOutcome(event.target.value)}><option value="">Все результаты</option>{Object.entries(outcomeNames).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></div>
      {state.loading ? <Loading /> : state.error ? <ErrorState error={state.error} retry={state.reload} /> : items.length ? <div className="table-wrap"><table className="audit-table"><thead><tr><th>Действие</th><th>Пользователь</th><th>Время</th><th>Результат</th><th aria-label="Сведения" /></tr></thead><tbody>{items.map(event => <tr key={event.id}><td><button className="table-primary text-button" onClick={() => setSelected(event)}>{actionName(event.action)}</button><span className="table-subtitle">Событие #{event.id}</span></td><td><strong className="table-username">{event.actor_username || 'Без входа'}</strong><span className="table-subtitle">{event.actor_role ? roleNames[event.actor_role] : '—'}</span></td><td className="muted nowrap">{dateTime(event.occurred_at)}</td><td><Badge tone={event.outcome === 'success' ? 'green' : event.outcome === 'failed' ? 'red' : event.outcome === 'started' ? 'neutral' : 'warning'}>{outcomeNames[event.outcome] || event.outcome}</Badge></td><td><button className="text-button" onClick={() => setSelected(event)}>Подробнее</button></td></tr>)}</tbody></table></div> : <Empty icon={<ListChecks size={28} />} title="Событий по фильтру нет">Измените фильтр или откройте другую страницу журнала.</Empty>}
      <div className="table-footer"><span>Страница {history.length + 1} · до 25 событий</span><div><Button variant="ghost" disabled={!history.length || state.loading} onClick={() => { const previous = [...history]; setCursor(previous.pop() ?? null); setHistory(previous); }}><ChevronLeft size={15} />Новее</Button><Button variant="ghost" disabled={state.loading || !state.data?.next_before_id} onClick={() => { setHistory([...history, cursor]); setCursor(state.data!.next_before_id); }}>Ранее<ChevronRight size={15} /></Button></div></div>
    </section><div className="workspace-note"><ListChecks size={17} /><p>Журнал фиксирует успешные действия и отказы. Сервисная учётная запись может добавлять события, но не изменять существующие записи.</p></div>
    {selected && <Modal title="Сведения о событии" onClose={() => setSelected(null)}><dl className="details-list"><div><dt>Действие</dt><dd>{actionName(selected.action)}</dd></div><div><dt>Пользователь</dt><dd>{selected.actor_username || 'Без входа'}</dd></div><div><dt>Дата</dt><dd>{dateTime(selected.occurred_at)}</dd></div><div><dt>Результат</dt><dd>{outcomeNames[selected.outcome] || selected.outcome}</dd></div>{Object.entries(selected.details).map(([key, value]) => <div key={key}><dt>{detailNames[key] || key}</dt><dd className="break-all">{key === 'scan_id' ? <a className="text-link" href={`#/scans/${value}`}>{String(value)}</a> : detailValue(key, value)}</dd></div>)}</dl><div className="modal-footer"><Button onClick={() => setSelected(null)}>Закрыть</Button></div></Modal>}
  </>;
}
