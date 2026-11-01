import { useCallback, useEffect, useRef, useState } from 'react';
import { ArrowLeft, ArrowRight, ArrowUpRight, ChevronLeft, ChevronRight, Download, FileArchive, FileCheck2, FileSearch, FolderOpen, RefreshCw, Search, ShieldAlert, Upload, X } from 'lucide-react';
import { errorMessage } from '../api';
import { useAuth } from '../auth';
import { Alert, Badge, Button, dateTime, Empty, ErrorState, Loading, PageTitle, useResource } from '../components';
import type { ScanReport, ScanSummary } from '../types';
import { kindNames } from '../types';

const MAX_UPLOAD = 5 * 1024 * 1024;
const PAGE_SIZE = 10;

function Report({ id }: { id: string }) {
  const { api } = useAuth();
  const validId = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id);
  const load = useCallback((signal: AbortSignal) => validId ? api.request<ScanReport>('/scans/' + id, { signal }) : Promise.reject(new Error('Invalid identifier')), [api, id, validId]);
  const state = useResource(load);
  const [search, setSearch] = useState('');
  const report = state.data;
  const findings = report?.result.findings.filter(finding => `${finding.path} ${finding.rule_id} ${kindNames[finding.kind]}`.toLowerCase().includes(search.toLowerCase())) || [];
  function download() {
    if (!report) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }));
    const link = document.createElement('a'); link.href = url; link.download = `passguard-scan-${report.id.slice(0, 8)}.json`; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  return <><a className="back-link" href="#/scans"><ArrowLeft size={16} />Ко всем проверкам</a><PageTitle eyebrow="РЕЗУЛЬТАТ ПРОВЕРКИ" title="Отчёт по исходникам" action={report && <Button variant="secondary" onClick={download}><Download size={16} />Скачать JSON</Button>}>Места возможного раскрытия учётных данных.</PageTitle>
    {!validId ? <Alert>Некорректный идентификатор отчёта.</Alert> : state.loading && !report ? <Loading /> : state.error ? <ErrorState error={state.error} retry={state.reload} /> : report && <>
      <div className={`report-summary ${report.findings_count ? 'report-warning' : 'report-clear'}`}><span className="report-summary-icon">{report.findings_count ? <ShieldAlert size={30} /> : <FileCheck2 size={30} />}</span><div><h2>{report.findings_count ? `Найдено совпадений: ${report.findings_count}` : 'Совпадений не обнаружено'}</h2><p>{report.findings_count ? 'Проверьте находки и при необходимости замените раскрытые секреты.' : 'Результат относится к поддерживаемым файлам и правилам этой проверки.'}</p></div><Badge tone={report.findings_count ? 'warning' : 'green'}>{report.findings_count ? 'Требует проверки' : 'Проверка завершена'}</Badge></div>
      <div className="report-meta"><div><span>Проверено файлов</span><strong>{report.result.files_scanned}</strong></div><div><span>Пропущено</span><strong>{report.result.skipped_files.length}</strong></div><div><span>Сканер</span><strong>{report.result.engine} {report.result.engine_version}</strong></div><div><span>Время проверки</span><strong>{dateTime(report.created_at)}</strong></div></div>
      {report.result.skipped_files.length > 0 && <Alert tone="info">Часть файлов не проверена: бинарные данные или неподдерживаемая кодировка. Список доступен ниже.</Alert>}
      <section className="card"><div className="card-heading"><h2>Находки <span className="count-pill">{report.findings_count}</span></h2><div className="search-input"><Search size={16} /><input aria-label="Поиск по находкам" value={search} onChange={event => setSearch(event.target.value)} placeholder="Файл, тип или правило" /></div></div>
        {findings.length ? <div className="table-wrap"><table className="findings-table"><thead><tr><th>Файл и строка</th><th>Тип</th><th>Правило</th><th>Статус</th></tr></thead><tbody>{findings.map(finding => <tr key={finding.id}><td><span className="finding-path">{finding.path}</span><span className="finding-location">Строка {finding.line}{finding.end_line !== finding.line ? `–${finding.end_line}` : ''}<span>·</span>{finding.file_id}</span></td><td><span className="type-chip"><KeyIcon kind={finding.kind} />{kindNames[finding.kind]}</span></td><td><code className="rule-name">{finding.rule_id}</code></td><td><Badge tone="warning">Проверить</Badge></td></tr>)}</tbody></table></div> : <Empty icon={<FileCheck2 size={27} />} title={search ? 'Совпадений по фильтру нет' : 'Список находок пуст'}>{search ? 'Попробуйте другой запрос.' : 'Сохраните отчёт как результат проверки снимка исходников.'}</Empty>}
      </section>
      {report.result.skipped_files.length > 0 && <details className="card skipped-files"><summary>Пропущенные файлы <span className="count-pill">{report.result.skipped_files.length}</span></summary><ul>{report.result.skipped_files.map(file => <li key={file.file_id}><code>{file.path}</code><span>Бинарный файл или не UTF-8</span></li>)}</ul></details>}
      <div className="workspace-note"><ShieldAlert size={17} /><p>Совпадение требует проверки человеком. Отчёт содержит путь, строку и тип находки; значения секретов и фрагменты исходников в него не включаются.</p></div>
      <div className="report-reference">Проверка <code>{report.id}</code></div>
    </>}
  </>;
}
function KeyIcon({ kind }: { kind: string }) { return kind === 'private_key' ? <ShieldAlert size={15} /> : <FileSearch size={15} />; }

export function ScansPage({ reportId }: { reportId: string }) {
  return reportId ? <Report key={reportId} id={reportId} /> : <ScanList />;
}

function ScanList() {
  const { api, user, notify } = useAuth();
  const [offset, setOffset] = useState(0);
  const load = useCallback((signal: AbortSignal) => api.request<{ items: ScanSummary[] }>(`/scans?limit=${PAGE_SIZE}&offset=${offset}`, { signal }), [api, offset]);
  const state = useResource(load);
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState('');
  const input = useRef<HTMLInputElement>(null);
  const inFlight = useRef(false);
  const upload = useRef<AbortController | null>(null);
  useEffect(() => () => upload.current?.abort(), []);
  const canRun = user!.role !== 'auditor';
  function choose(file?: File) {
    setError('');
    if (!file) return;
    if (!file.name.toLowerCase().endsWith('.zip')) { setFile(null); setError('Выберите архив в формате ZIP.'); return; }
    if (file.size > MAX_UPLOAD) { setFile(null); setError('Архив должен быть не больше 5 МиБ.'); return; }
    setFile(file);
  }
  async function scan() {
    if (!file || inFlight.current) return;
    inFlight.current = true; setBusy(true); setError('');
    const controller = new AbortController(); upload.current = controller;
    try {
      const report = await api.request<ScanReport>('/scans', { method: 'POST', body: file, timeout: 55000, signal: controller.signal });
      if (controller.signal.aborted) return;
      setFile(null); if (input.current) input.current.value = '';
      notify('Проверка исходников завершена.'); window.location.hash = '/scans/' + report.id;
    } catch (error) { if (!controller.signal.aborted) setError(`${errorMessage(error)} Если ответ потерян, обновите список результатов перед повторным запуском.`); }
    finally { inFlight.current = false; if (!controller.signal.aborted) setBusy(false); }
  }
  return <><PageTitle eyebrow="ПОИСК ВОЗМОЖНЫХ УТЕЧЕК" title="Проверка исходников" action={<Button variant="secondary" busy={state.loading} onClick={state.reload}><RefreshCw size={16} />Обновить</Button>}>Находите пароли, токены и ключи до публикации кода.</PageTitle>
    {canRun ? <section className="card upload-card"><div className="upload-info"><div className="section-kicker">НОВАЯ ПРОВЕРКА</div><h2>Дайте коду ещё одну проверку.</h2><p>Загрузите ZIP с исходниками. Мы проверим текстовые файлы и покажем места возможных утечек.</p><div className="upload-spec"><span><FileArchive size={15} /> ZIP до 5 МиБ</span><span>До 1000 файлов · UTF-8</span></div><p className="form-hint">Подготовьте архив без .git, .local, .venv и node_modules.</p></div><div className="upload-control">
      <div className={`drop-zone ${dragging ? 'dragging' : ''} ${busy ? 'upload-busy' : ''}`} onDragOver={event => { event.preventDefault(); if (!busy) setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={event => { event.preventDefault(); setDragging(false); if (!busy) choose(event.dataTransfer.files[0]); }}>
        <div className="upload-symbol">{file ? <FileArchive size={26} /> : <Upload size={26} strokeWidth={1.5} />}</div>{file ? <><strong className="chosen-file">{file.name}</strong><span>{(file.size / 1024).toFixed(1)} КиБ</span><button type="button" className="text-button" disabled={busy} onClick={() => { setFile(null); if (input.current) input.current.value = ''; }}>Выбрать другой файл</button></> : <><strong>Перетащите архив сюда</strong><span>или выберите файл на компьютере</span><Button variant="secondary" onClick={() => input.current?.click()}>Выбрать ZIP</Button></>}
        <input ref={input} type="file" accept=".zip,application/zip" className="file-input" aria-label="ZIP с исходниками" disabled={busy} onChange={event => choose(event.target.files?.[0])} />
      </div>{error && <Alert>{error}</Alert>}{file && <Button className="upload-submit" busy={busy} onClick={scan}>{busy ? 'Проверяем исходники…' : 'Проверить исходники'}{!busy && <ArrowRight size={17} />}</Button>}
    </div></section> : <Alert tone="info">Ваша роль позволяет просматривать отчёты. Новую проверку запускает оператор или администратор.</Alert>}
    <section className="card"><div className="card-heading"><div><span className="section-kicker">СОХРАНЁННЫЕ РЕЗУЛЬТАТЫ</span><h2>История проверок</h2></div><Badge>Снимок исходников</Badge></div>
      {state.loading ? <Loading /> : state.error ? <ErrorState error={state.error} retry={state.reload} /> : state.data?.items.length ? <div className="table-wrap"><table><thead><tr><th>Проверка</th><th>Дата</th><th>Файлы</th><th>Находки</th><th aria-label="Отчёт" /></tr></thead><tbody>{state.data.items.map(scan => <tr key={scan.id}><td><a className="table-primary" href={`#/scans/${scan.id}`}><span className="file-cell-icon"><FolderOpen size={17} /></span>Исходники <code>#{scan.id.slice(0, 8)}</code></a></td><td className="muted nowrap">{dateTime(scan.created_at)}</td><td>{scan.files_scanned}</td><td><Badge tone={scan.findings_count ? 'warning' : 'green'}>{scan.findings_count ? `${scan.findings_count} находок` : 'Нет находок'}</Badge></td><td><a href={`#/scans/${scan.id}`} className="icon-button" aria-label={`Открыть отчёт ${scan.id.slice(0, 8)}`}><ArrowUpRight size={17} /></a></td></tr>)}</tbody></table></div> : <Empty icon={<FileSearch size={27} />} title={offset ? 'На этой странице результатов нет' : 'Проверок пока нет'}>Сохранённые результаты появятся здесь после запуска проверки.</Empty>}
      <div className="table-footer"><span>Страница {Math.floor(offset / PAGE_SIZE) + 1}</span><div><Button variant="ghost" disabled={offset === 0 || state.loading} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}><ChevronLeft size={15} />Назад</Button><Button variant="ghost" disabled={state.loading || !state.data || state.data.items.length < PAGE_SIZE} onClick={() => setOffset(offset + PAGE_SIZE)}>Далее<ChevronRight size={15} /></Button></div></div>
    </section><div className="workspace-note"><ShieldAlert size={17} /><p>Проверка использует правила Gitleaks и не выполняет загруженный код. Для полной оценки учитывайте пропущенные файлы и возможные ложные срабатывания.</p></div>
  </>;
}
