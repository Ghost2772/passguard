export type Role = 'admin' | 'operator' | 'auditor';
export interface User { id: string; username: string; role: Role; active: boolean; created_at: string }
export interface Session { user: User; csrf_token: string }
export interface Secret { id: string; type: string; username: string; rotation_period_seconds: number }
export type RotationReason = 'manual_test' | 'scheduled' | 'suspected_exposure';
export interface Operation {
  id: string; actor_id: string; secret_id: string; reason: RotationReason;
  status: 'in_progress' | 'succeeded' | 'failed' | 'unknown'; created_at: string; finished_at: string | null;
}
export interface RotationResponse { operation: Operation; replayed: boolean }
export interface Finding {
  id: string; file_id: string; path: string; line: number; end_line: number; rule_id: string;
  kind: 'password' | 'private_key' | 'token' | 'credential'; severity: 'high'; status: 'suspected';
}
export interface ScanSummary {
  id: string; actor_id: string; created_at: string; findings_count: number;
  engine: string; engine_version: string; files_scanned: number;
}
export interface ScanReport {
  id: string; actor_id: string; created_at: string; findings_count: number;
  result: {
    engine: string; engine_version: string; scope: string; files_scanned: number; bytes_scanned: number;
    findings: Finding[]; skipped_files: { file_id: string; path: string; reason: string }[];
  };
}
export interface AuditEvent {
  id: number; occurred_at: string; actor_id: string | null; actor_username: string | null; actor_role: Role | null;
  action: string; outcome: string; details: Record<string, string | number | boolean | null>;
}
export interface AuditPage { items: AuditEvent[]; next_before_id: number | null }
export const roleNames: Record<Role, string> = { admin: 'Администратор', operator: 'Оператор', auditor: 'Аудитор' };
export const reasonNames: Record<RotationReason, string> = {
  manual_test: 'Учебная проверка', scheduled: 'Плановая замена', suspected_exposure: 'Подозрение на утечку',
};
export const kindNames: Record<Finding['kind'], string> = {
  password: 'Пароль', private_key: 'Закрытый ключ', token: 'Токен', credential: 'Учётные данные',
};
