import { useCallback, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { ArrowDownUp, CheckCircle2, Clock3, Database, KeyRound, LockKeyhole, RefreshCw, ShieldCheck } from 'lucide-react';
import { ApiError, errorMessage } from '../api';
import { useAuth } from '../auth';
import type { RotationAttempt } from '../App';
import { Alert, Badge, Button, dateTime, ErrorState, Loading, Modal, PageTitle, period, Step, useResource } from '../components';
import type { Operation, RotationReason, RotationResponse, Secret } from '../types';
import { reasonNames } from '../types';

export function SecretsPage({ attempt, onAttempt }: { attempt: RotationAttempt | null; onAttempt: (value: RotationAttempt) => void }) {
  const { api, user, notify } = useAuth();
  const load = useCallback((signal: AbortSignal) => api.request<{ items: Secret[] }>('/secrets', { signal }), [api]);
  const state = useResource(load);
  const [modal, setModal] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [checking, setChecking] = useState(false);
  const [demo, setDemo] = useState<string | null>(null);
  const inFlight = useRef(false);
  const pending = !!attempt && (attempt.uncertain || attempt.operation?.status === 'in_progress' || attempt.operation?.status === 'unknown');
  const completed = attempt?.operation?.status === 'succeeded';
  function openRotation() {
    if (!pending) onAttempt({ id: crypto.randomUUID(), reason: 'manual_test', operation: null, uncertain: false });
    setError(''); setModal(true);
  }
  async function rotate(event?: FormEvent) {
    event?.preventDefault();
    if (!attempt || inFlight.current) return;
    inFlight.current = true; setBusy(true); setError('');
    const current = { ...attempt, uncertain: true };
    onAttempt(current);
    try {
      const result = await api.request<RotationResponse>('/secrets/demo-db/rotate', { method: 'POST', body: { idempotency_key: current.id, reason: current.reason } });
      onAttempt({ ...current, operation: result.operation, uncertain: result.operation.status !== 'succeeded' && result.operation.status !== 'failed' });
      if (result.operation.status === 'succeeded') { notify('Пароль демонстрационной базы заменён.'); setDemo(null); state.reload(); }
    } catch (error) {
      const operation = error instanceof ApiError ? error.operation : undefined;
      onAttempt({ ...current, operation: operation || null, uncertain: !operation || operation.status !== 'failed' });
      setError(errorMessage(error));
    } finally { inFlight.current = false; setBusy(false); }
  }
  async function checkOperation() {
    if (!attempt || inFlight.current) return;
    inFlight.current = true; setBusy(true); setError('');
    try {
      const operation = await api.request<Operation>('/operations/' + attempt.id);
      onAttempt({ ...attempt, operation, uncertain: !['succeeded', 'failed'].includes(operation.status) });
      if (operation.status === 'succeeded') state.reload();
    } catch (error) {
      setError(error instanceof ApiError && error.status === 404 ? 'Операция пока не зарегистрирована. Можно повторить запрос с тем же идентификатором.' : errorMessage(error));
    } finally { inFlight.current = false; setBusy(false); }
  }
  async function checkDemo() {
    setChecking(true);
    try { const result = await api.request<{ status: string }>('/checks/demo', { method: 'POST' }); setDemo(result.status); }
    catch (error) { notify(errorMessage(error), 'error'); }
    finally { setChecking(false); }
  }
  return <>
    <PageTitle eyebrow="ЗАЩИЩЁННОЕ ХРАНИЛИЩЕ" title="Секреты" action={<Button variant="secondary" busy={state.loading} onClick={state.reload}><RefreshCw size={16} />Обновить</Button>}>Учётные данные и порядок их замены.</PageTitle>
    {pending && <Alert tone="info">Результат последней ротации требует проверки. Откройте статус операции, прежде чем запускать новую замену.</Alert>}
    {state.loading && !state.data ? <Loading /> : state.error ? <ErrorState error={state.error} retry={state.reload} /> : state.data?.items.map(secret => <section className="card secret-card" key={secret.id}>
      <div className="secret-heading"><span className="secret-large-icon"><Database size={31} strokeWidth={1.5} /></span><div><div className="section-kicker">ПАРОЛЬ БАЗЫ ДАННЫХ</div><h2>Демонстрационная база</h2><p><code>{secret.id}</code><span className="separator">/</span>PostgreSQL</p></div><Badge tone="green"><ShieldCheck size={13} />Под управлением Vault</Badge></div>
      <div className="secret-properties"><div><span>Учётная запись</span><strong><code>{secret.username}</code></strong></div><div><span>Период замены</span><strong><Clock3 size={17} />{period(secret.rotation_period_seconds)}</strong></div><div><span>Значение пароля</span><strong className="secret-masked"><LockKeyhole size={15} /><span>Не передаётся в панель</span></strong></div></div>
      <div className="secret-actions"><div><h3>Замена без перезапуска потребителя</h3><p>Приложение получает актуальные учётные данные из хранилища.</p></div>{user!.role === 'admin' ? <Button onClick={openRotation}><ArrowDownUp size={17} />{pending ? 'Статус замены' : 'Заменить пароль'}</Button> : <Badge>Замену выполняет администратор</Badge>}</div>
    </section>)}
    <div className="two-columns"><section className="card padded-card"><span className="section-icon"><ShieldCheck size={23} /></span><h2>Разделение прав</h2><div className="policy-lines"><Step>Приложение читает свой пароль</Step><Step>Оператор замены не читает значение</Step><Step>Действия фиксируются в журнале</Step></div></section><section className="card padded-card"><span className="section-icon"><Database size={23} /></span><h2>Проверка потребителя</h2><p className="muted">Проверьте, что демонстрационное приложение отвечает после изменения пароля.</p>{demo && <Badge tone={demo === 'ready' ? 'green' : 'warning'} dot>{demo === 'ready' ? 'Приложение доступно' : 'Приложение недоступно'}</Badge>}{user!.role !== 'auditor' && <Button variant="secondary" onClick={checkDemo} busy={checking}>Проверить приложение</Button>}</section></div>
    {modal && attempt && <Modal title={completed ? 'Пароль заменён' : 'Замена пароля'} onClose={() => setModal(false)} busy={busy}>
      {completed ? <><div className="modal-success-icon"><CheckCircle2 size={34} /></div><p>Vault подтвердил замену пароля демонстрационной базы. Можно проверить доступность приложения.</p><div className="operation-reference"><span>Операция</span><code>{attempt.id}</code><span>{attempt.operation?.finished_at && dateTime(attempt.operation.finished_at)}</span></div><div className="modal-footer"><Button onClick={() => setModal(false)}>Готово</Button></div></> : <form onSubmit={rotate} className="form-stack"><p className="modal-description">Пароль <code>demo-db</code> будет изменён в базе данных. Приложение получит новое значение из Vault.</p>
        {pending && !busy && <Alert tone="info">{attempt.operation?.status === 'in_progress' ? 'Операция выполняется. Проверьте её статус.' : 'Результат не подтверждён. Проверьте статус операции перед дальнейшими действиями.'}</Alert>}
        {attempt.operation?.status === 'failed' && <Alert>Замена не выполнена. Проверьте права доступа и журнал действий.</Alert>}
        {error && <Alert>{error}</Alert>}
        <label>Причина замены<select value={attempt.reason} disabled={busy || pending || !!attempt.operation} onChange={event => onAttempt({ ...attempt, reason: event.target.value as RotationReason })}>{Object.entries(reasonNames).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select></label>
        <div className="operation-reference"><span>Идентификатор операции</span><code>{attempt.id}</code></div>
        <p className="form-hint">Смена пароля не закрывает уже открытые соединения с базой.</p>
        <div className="modal-footer"><Button type="button" variant="ghost" onClick={() => setModal(false)} disabled={busy}>Закрыть</Button>{pending ? <><Button type="button" variant="secondary" busy={busy} onClick={checkOperation}>Проверить результат</Button>{!attempt.operation && <Button type="button" disabled={busy} onClick={() => rotate()}>Повторить запрос</Button>}</> : !attempt.operation && <Button type="submit" busy={busy}><KeyRound size={16} />Подтвердить замену</Button>}</div>
      </form>}
    </Modal>}
  </>;
}
