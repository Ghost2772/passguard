import { useCallback, useState } from 'react';
import { ArrowDownUp, ArrowRight, ArrowUpRight, CheckCircle2, Clock3, Database, FileSearch, History, KeyRound, RefreshCw, ShieldCheck, ShieldEllipsis } from 'lucide-react';
import { errorMessage } from '../api';
import { useAuth } from '../auth';
import { Alert, Badge, Button, dateTime, Empty, ErrorState, Loading, PageTitle, period, Step, TextLink, useResource } from '../components';
import type { AuditPage, ScanSummary, Secret } from '../types';
import { roleNames } from '../types';
import { actionName } from './Audit';

function RecentActivity() {
  const { api } = useAuth();
  const load = useCallback((signal: AbortSignal) => api.request<AuditPage>('/audit?limit=4', { signal }), [api]);
  const state = useResource(load);
  return <section className="card activity-card"><div className="card-heading"><h2>Последние действия</h2><History size={18} /></div>
    {state.loading && !state.data ? <Loading /> : state.error ? <ErrorState error={state.error} retry={state.reload} /> : <div className="activity-list">{state.data?.items.map(event => <div className="activity-item" key={event.id}><span className={`activity-dot ${event.outcome === 'success' ? 'activity-success' : ''}`} /><div><strong>{actionName(event.action)}</strong><span>{event.actor_username || 'Без входа'} · {dateTime(event.occurred_at)}</span></div></div>)}</div>}
    <TextLink href="#/audit">Открыть журнал</TextLink>
  </section>;
}

export function OverviewPage() {
  const { api, user, notify } = useAuth();
  const load = useCallback(async (signal: AbortSignal) => {
    const [secrets, scans, ready] = await Promise.all([
      api.request<{ items: Secret[] }>('/secrets', { signal }), api.request<{ items: ScanSummary[] }>('/scans?limit=4', { signal }),
      api.requestAt<{ status: string }>('/ready', { signal }),
    ]);
    return { secrets: secrets.items, scans: scans.items, ready: ready.status === 'ready' };
  }, [api]);
  const state = useResource(load);
  const [checking, setChecking] = useState(false);
  const [demo, setDemo] = useState<string | null>(null);
  async function check() {
    setChecking(true);
    try { const result = await api.request<{ status: string }>('/checks/demo', { method: 'POST' }); setDemo(result.status); }
    catch (error) { notify(errorMessage(error), 'error'); }
    finally { setChecking(false); }
  }
  const canRun = user!.role !== 'auditor';
  return <>
    <PageTitle eyebrow="РАБОЧЕЕ ПРОСТРАНСТВО" title="Обзор безопасности" action={<Button variant="secondary" onClick={state.reload} busy={state.loading}><RefreshCw size={16} />Обновить</Button>}>Всё, что нужно для контроля секретов, — в одном месте.</PageTitle>
    {state.loading && !state.data ? <Loading /> : state.error ? <ErrorState error={state.error} retry={state.reload} /> : state.data && <>
      <section className="overview-hero"><div className="hero-copy"><Badge tone={state.data.ready ? 'green' : 'warning'} dot>{state.data.ready ? 'Хранилище и база доступны' : 'Требуется внимание'}</Badge><h2>Секреты под контролем<span>.</span></h2><p>Централизованное хранение, своевременная замена<br className="desktop-break" /> и проверка исходников на возможные утечки.</p><a className="hero-link" href="#/secrets">Управлять секретами <ArrowUpRight size={19} /></a></div><div className="hero-visual" aria-hidden="true"><div className="hero-grid" /><div className="hero-orbit" /><span className="hero-icon-key"><KeyRound size={21} /></span><span className="hero-icon-file"><FileSearch size={21} /></span><div className="hero-shield"><ShieldCheck size={67} strokeWidth={1.2} /></div><div className="hero-caption"><span className="status-dot" /> VAULT / КОНТРОЛЬ ДОСТУПА</div></div></section>
      <div className="stats-grid"><div className="stat-card"><div><span className="stat-label">Управляемые секреты</span><KeyRound size={18} /></div><strong>{state.data.secrets.length}<span>секрет</span></strong><p>Учётные данные в защищённом хранилище</p></div><div className="stat-card"><div><span className="stat-label">Последняя проверка</span><FileSearch size={18} /></div><strong>{state.data.scans[0]?.findings_count ?? '—'}<span>{state.data.scans.length ? 'находок' : 'нет результатов'}</span></strong><p>{state.data.scans[0] ? dateTime(state.data.scans[0].created_at) : 'Загрузите исходники для первой проверки'}</p></div><div className="stat-card"><div><span className="stat-label">Период ротации</span><ArrowDownUp size={18} /></div><strong>{state.data.secrets[0] ? period(state.data.secrets[0].rotation_period_seconds) : '—'}</strong><p>Для пароля демонстрационной базы</p></div></div>
      <div className="overview-columns"><div className="overview-primary"><section className="card"><div className="card-heading"><div><span className="section-kicker">ИСТОРИЯ ПРОВЕРОК</span><h2>Последние результаты</h2></div><TextLink href="#/scans">Все проверки</TextLink></div>
        {state.data.scans.length ? <div className="table-wrap"><table><thead><tr><th>Проверка</th><th>Дата</th><th>Результат</th><th aria-label="Открыть" /></tr></thead><tbody>{state.data.scans.map(scan => <tr key={scan.id}><td><a className="table-primary" href={`#/scans/${scan.id}`}><span className="file-cell-icon"><FileSearch size={17} /></span>Исходники <code>#{scan.id.slice(0, 6)}</code></a></td><td className="nowrap muted">{dateTime(scan.created_at)}</td><td><Badge tone={scan.findings_count ? 'warning' : 'green'}>{scan.findings_count ? `${scan.findings_count} находок` : 'Нет находок'}</Badge></td><td><a href={`#/scans/${scan.id}`} className="icon-button" aria-label={`Открыть проверку ${scan.id.slice(0, 6)}`}><ArrowUpRight size={17} /></a></td></tr>)}</tbody></table></div> : <Empty icon={<FileSearch size={28} />} title="Начните с проверки исходников" action={canRun ? <a className="button button-secondary" href="#/scans">Загрузить исходники<ArrowRight size={16} /></a> : undefined}>Здесь появятся результаты поиска паролей, ключей и токенов в коде.</Empty>}
      </section><section className="card demo-card"><div className="demo-card-icon"><Database size={23} strokeWidth={1.6} /></div><div><h2>Демонстрационное приложение</h2><p>Убедитесь, что приложение получает актуальный пароль и отвечает.</p>{demo && <Badge tone={demo === 'ready' ? 'green' : 'warning'} dot>{demo === 'ready' ? 'Приложение доступно' : 'Приложение недоступно'}</Badge>}</div>{canRun ? <Button variant="secondary" busy={checking} onClick={check}>Проверить<ArrowUpRight size={16} /></Button> : <Badge>Проверку запускает оператор</Badge>}</section></div>
        <div className="overview-secondary"><section className="card policy-card"><div className="card-heading"><h2>Ваш уровень доступа</h2><ShieldEllipsis size={19} /></div><Badge tone="green">{roleNames[user!.role]}</Badge><div className="policy-lines"><Step>Просмотр метаданных секретов</Step><Step>Чтение отчётов проверок</Step>{user!.role !== 'auditor' && <Step>Запуск проверки исходников</Step>}{user!.role === 'admin' && <Step>Ротация и управление доступом</Step>}{user!.role === 'auditor' && <Step>Просмотр журнала действий</Step>}</div><div className="policy-note"><CheckCircle2 size={16} />Права проверяются на сервере</div></section>
        {user!.role !== 'operator' ? <RecentActivity /> : <section className="card activity-card"><Clock3 size={23} className="muted" /><h2>Проверяйте перед публикацией</h2><p className="muted">Запускайте проверку исходников перед передачей кода и после изменения конфигурации.</p><TextLink href="#/scans">Перейти к проверке</TextLink></section>}
        </div></div>
      <div className="workspace-note"><ShieldCheck size={17} /><p>Панель показывает метаданные и результаты проверок. Значения секретов из хранилища в интерфейс не передаются.</p></div>
    </>}
  </>;
}
