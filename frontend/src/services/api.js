let csrf = '';
export function setCSRF(value) { csrf = value || ''; }

export class APIError extends Error {
  constructor(code, status = 0, requestId = '') {
    super(code);
    this.code = code;
    this.status = status;
    this.requestId = requestId;
  }
}

// Analysis waits for VirusTotal and OpenAI; the backend allows 170 seconds.
export const ANALYSIS_TIMEOUT = 185000;
const DEFAULT_TIMEOUT = 35000;

// The backend always answers errors as JSON with a stable code. An error
// without that body did not come from the backend handler: typically the
// development proxy could not reach it, or a gateway cut the request.
function codeForStatus(status) {
  if (status === 401) return 'UNAUTHENTICATED';
  if (status === 404) return 'NOT_FOUND';
  if (status === 413) return 'EMAIL_TOO_LARGE';
  if (status === 429) return 'RATE_LIMITED';
  if (status === 504) return 'REQUEST_TIMEOUT';
  if (status >= 500) return 'BACKEND_UNAVAILABLE';
  return 'UNEXPECTED_RESPONSE';
}

function readCookie(name) {
  const entry = document.cookie.split('; ').find(v => v.startsWith(`${name}=`));
  return entry ? decodeURIComponent(entry.slice(name.length + 1)) : '';
}

export async function api(path, { method = 'GET', body, signal, blob = false, timeout = DEFAULT_TIMEOUT } = {}) {
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; controller.abort(); }, timeout);
  const abort = () => controller.abort();
  signal?.addEventListener('abort', abort, { once: true });
  if (signal?.aborted) controller.abort();
  try {
    const headers = {};
    if (body && !(body instanceof FormData)) headers['Content-Type'] = 'application/json';
    if (method !== 'GET' && !['/auth/login', '/auth/register'].includes(path)) {
      headers['X-CSRF-Token'] = csrf || readCookie('cyberguard_csrf');
    }
    const response = await fetch(`/api/v1${path}`, {
      method,
      credentials: 'include',
      headers,
      body: body instanceof FormData ? body : body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });
    if (!response.ok) {
      const data = await response.json().catch(() => null);
      const code = data?.error?.code || codeForStatus(response.status);
      if (code === 'UNAUTHENTICATED' || code === 'PASSWORD_CHANGE_REQUIRED') {
        window.dispatchEvent(new CustomEvent('auth-state', { detail: code }));
      }
      throw new APIError(code, response.status, data?.error?.request_id || response.headers.get('X-Request-ID') || '');
    }
    if (response.status === 204) return null;
    return blob ? await response.blob() : await response.json();
  } catch (error) {
    if (error instanceof APIError) throw error;
    if (error?.name === 'AbortError') throw new APIError(timedOut ? 'TIMEOUT' : 'CANCELLED');
    if (error instanceof SyntaxError) throw new APIError('UNEXPECTED_RESPONSE');
    throw new APIError('NETWORK');
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', abort);
  }
}

export const query = values => new URLSearchParams(Object.entries(values).filter(([, value]) => value !== '' && value != null)).toString();

export async function downloadReport(id, format, lang) {
  const blob = await api(`/analyses/${encodeURIComponent(id)}/export?${query({ format, lang })}`, { blob: true, timeout: 60000 });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `cyberguard-${id}.${format}`;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
