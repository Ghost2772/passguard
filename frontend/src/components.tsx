import { useEffect, useRef, useState } from 'react';
import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode } from 'react';
import { AlertCircle, ArrowRight, Check, CheckCircle2, Eye, EyeOff, LoaderCircle, ShieldCheck, X } from 'lucide-react';
import { errorMessage } from './api';

export function Brand({ light = false }: { light?: boolean }) {
  return <a href="#/overview" className={`brand ${light ? 'brand-light' : ''}`} aria-label="PassGuard — обзор">
    <span className="brand-mark"><ShieldCheck size={25} strokeWidth={1.7} /></span><span>PassGuard<span className="brand-dot">.</span></span>
  </a>;
}
export function Button({ children, variant = 'primary', busy, className = '', ...props }:
  ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'secondary' | 'ghost' | 'danger'; busy?: boolean }) {
  return <button className={`button button-${variant} ${className}`} {...props} disabled={props.disabled || busy} aria-busy={busy || undefined}>
    {busy && <LoaderCircle size={17} className="spin" aria-hidden="true" />}{children}
  </button>;
}
export function Badge({ children, tone = 'neutral', dot = false }: { children: ReactNode; tone?: string; dot?: boolean }) {
  return <span className={`badge badge-${tone}`}>{dot && <span className="status-dot" />}{children}</span>;
}
export function Alert({ children, tone = 'error' }: { children: ReactNode; tone?: 'error' | 'success' | 'info' }) {
  return <div className={`alert alert-${tone}`} role={tone === 'error' ? 'alert' : 'status'}>
    {tone === 'success' ? <CheckCircle2 size={19} /> : <AlertCircle size={19} />}<span>{children}</span>
  </div>;
}
export function PageTitle({ eyebrow, title, children, action }: { eyebrow: string; title: string; children: ReactNode; action?: ReactNode }) {
  return <div className="page-heading"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{children}</p></div>{action}</div>;
}
export function Empty({ icon, title, children, action }: { icon?: ReactNode; title: string; children: ReactNode; action?: ReactNode }) {
  return <div className="empty-state">{icon && <span className="empty-icon">{icon}</span>}<h3>{title}</h3><p>{children}</p>{action}</div>;
}
export function Loading({ label = 'Загружаем данные…' }: { label?: string }) {
  return <div className="loading-state" role="status"><LoaderCircle size={23} className="spin" /><span>{label}</span></div>;
}
export function ErrorState({ error, retry }: { error: unknown; retry: () => void }) {
  return <div className="error-state"><Alert>{errorMessage(error)}</Alert><Button variant="secondary" onClick={retry}>Повторить</Button></div>;
}
export function PasswordInput(props: InputHTMLAttributes<HTMLInputElement>) {
  const [visible, setVisible] = useState(false);
  return <div className="password-input"><input {...props} type={visible ? 'text' : 'password'} />
    <button type="button" className="icon-button" aria-label={visible ? 'Скрыть пароль' : 'Показать пароль'} onClick={() => setVisible(!visible)}>
      {visible ? <EyeOff size={18} /> : <Eye size={18} />}
    </button></div>;
}
export function Modal({ title, children, onClose, busy = false }: { title: string; children: ReactNode; onClose: () => void; busy?: boolean }) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = 'modal-heading';
  useEffect(() => { ref.current?.showModal(); return () => ref.current?.close(); }, []);
  return <dialog ref={ref} className="modal" aria-labelledby={titleId} onCancel={event => { event.preventDefault(); if (!busy) onClose(); }}>
    <div className="modal-heading"><h2 id={titleId}>{title}</h2><button className="icon-button" aria-label="Закрыть" onClick={onClose} disabled={busy}><X size={20} /></button></div>
    {children}
  </dialog>;
}
export function TextLink({ href, children }: { href: string; children: ReactNode }) {
  return <a className="text-link" href={href}>{children}<ArrowRight size={15} /></a>;
}
export function Step({ children }: { children: ReactNode }) {
  return <div className="policy-line"><span><Check size={14} /></span>{children}</div>;
}
export function dateTime(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : new Intl.DateTimeFormat('ru-RU', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' }).format(date);
}
export function period(seconds: number) {
  if (seconds <= 0) return 'Не задан';
  if (seconds % 86400 === 0) return `${seconds / 86400} дн.`;
  if (seconds % 3600 === 0) return `${seconds / 3600} ч`;
  return `${Math.ceil(seconds / 60)} мин`;
}
export function useResource<T>(loader: (signal: AbortSignal) => Promise<T>) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true); setError(null);
    loader(controller.signal).then(value => { if (!controller.signal.aborted) setData(value); })
      .catch(error => { if (!controller.signal.aborted) setError(error); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [loader, revision]);
  return { data, error, loading, reload: () => setRevision(value => value + 1) };
}
