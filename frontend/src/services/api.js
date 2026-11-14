let csrf = '';
export function setCSRF(value) { csrf = value || ''; }
export class APIError extends Error {
  constructor(code, status = 0) { super(code); this.code = code; this.status = status; }
}
export async function api(path, { method = 'GET', body, signal, blob = false } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 120000);
  const abort = () => controller.abort();
  signal?.addEventListener('abort', abort, { once: true });
  if (signal?.aborted) controller.abort();
  try {
    const headers = {};
    if (body && !(body instanceof FormData)) headers['Content-Type'] = 'application/json';
    if (method !== 'GET' && path !== '/auth/login') {
      headers['X-CSRF-Token'] = csrf || decodeURIComponent(document.cookie.split('; ').find(v => v.startsWith('cyberguard_csrf='))?.split('=')[1] || '');
    }
    const response = await fetch(`/api/v1${path}`, { method, credentials: 'include', headers, body: body instanceof FormData ? body : body ? JSON.stringify(body) : undefined, signal: controller.signal });
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      const code = data.error?.code || 'INTERNAL_ERROR';
      if (code === 'UNAUTHENTICATED' || code === 'PASSWORD_CHANGE_REQUIRED') window.dispatchEvent(new CustomEvent('auth-state', { detail: code }));
      throw new APIError(code, response.status);
    }
    if (response.status === 204) return null;
    return blob ? response.blob() : response.json();
  } catch (error) {
    if (error instanceof APIError) throw error;
    throw new APIError(error.name === 'AbortError' ? 'TIMEOUT' : 'NETWORK');
  } finally { clearTimeout(timer); signal?.removeEventListener('abort', abort); }
}
export const query = values => new URLSearchParams(Object.entries(values).filter(([, value]) => value !== '' && value != null)).toString();
export async function downloadReport(id, format, lang) {
  const blob = await api(`/analyses/${encodeURIComponent(id)}/export?${query({ format, lang })}`, { blob: true });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a'); anchor.href = url; anchor.download = `cyberguard-${id}.${format}`;
  document.body.append(anchor); anchor.click(); anchor.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}
