import { createContext, useContext, useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { ApiClient, ApiError } from './api';
import type { Session, User } from './types';

interface Notice { text: string; tone: 'success' | 'error' }
interface AuthState {
  api: ApiClient; user: User | null; loading: boolean; loginMessage: string;
  acceptSession: (session: Session) => void; endSession: (message?: string) => void;
  notice: Notice | null; notify: (text: string, tone?: Notice['tone']) => void; dismissNotice: () => void;
}
const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const api = useMemo(() => new ApiClient(), []);
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [loginMessage, setLoginMessage] = useState('');
  const [notice, setNotice] = useState<Notice | null>(null);
  function endSession(message = '') {
    api.setSession(null); setUser(null); setNotice(null); setLoginMessage(message);
  }
  api.onUnauthorized = () => endSession('Сессия завершилась. Войдите снова.');
  useEffect(() => {
    const controller = new AbortController();
    api.request<Session>('/auth/me', { signal: controller.signal, silent401: true }).then(session => {
      if (!controller.signal.aborted) { api.setSession(session); setUser(session.user); }
    }).catch(error => {
      if (!controller.signal.aborted && !(error instanceof ApiError && error.status === 401)) {
        setLoginMessage('Сервис временно недоступен. Попробуйте войти ещё раз.');
      }
    }).finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [api]);
  return <AuthContext.Provider value={{
    api, user, loading, loginMessage, notice,
    acceptSession(session) { api.setSession(session); setUser(session.user); setLoginMessage(''); },
    endSession,
    notify(text, tone = 'success') { setNotice({ text, tone }); },
    dismissNotice() { setNotice(null); },
  }}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error('AuthProvider is required');
  return value;
}
