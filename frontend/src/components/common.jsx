import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '../services/api';
import '../i18n/app';

// ErrorMessage accepts a backend code or an { code, requestId } object and
// renders the localized explanation. Unknown codes fall back to a generic
// message and stay visible so that they can be reported.
export function ErrorMessage({ code, error }) {
  const { t, i18n } = useTranslation();
  const value = error?.code || code;
  if (!value) return null;
  const known = i18n.exists(value);
  const requestId = error?.requestId;
  return (
    <div role="alert" className="notice error">
      {known ? t(value) : t('error')}
      {!known && <small><code>{value}</code></small>}
      {requestId && <small>{t('requestId')}: <code>{requestId}</code></small>}
    </div>
  );
}

export function Loading() {
  const { t } = useTranslation();
  return <div role="status" className="skeleton">{t('loading')}</div>;
}

export function Empty({ message }) {
  const { t } = useTranslation();
  return <div className="empty">{message || t('empty')}</div>;
}

export function Badge({ value, label }) {
  const { t } = useTranslation();
  return <span className={`badge ${value}`}>{label || t(value, { defaultValue: value })}</span>;
}

export function useResource(path) {
  const [state, setState] = useState({ loading: true });
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    const c = new AbortController();
    setState({ loading: true });
    api(path, { signal: c.signal })
      .then(data => { if (!c.signal.aborted) setState({ data }); })
      .catch(e => { if (!c.signal.aborted) setState({ error: e.code, failure: { code: e.code, requestId: e.requestId } }); });
    return () => c.abort();
  }, [path, revision]);
  return { ...state, retry: () => setRevision(v => v + 1), set: data => setState({ data }) };
}

export function Resource({ resource, children }) {
  const { t } = useTranslation();
  if (resource.loading) return <Loading />;
  if (resource.error) {
    return (
      <>
        <ErrorMessage error={resource.failure} code={resource.error} />
        <button type="button" onClick={resource.retry}>{t('retry')}</button>
      </>
    );
  }
  return children(resource.data);
}

// ConfirmButton asks for a second click instead of using a browser dialog.
export function ConfirmButton({ label, question, confirmLabel, onConfirm, disabled, className = 'danger' }) {
  const { t } = useTranslation();
  const [asking, setAsking] = useState(false);
  if (!asking) return <button type="button" className={className} disabled={disabled} onClick={() => setAsking(true)}>{label}</button>;
  return (
    <span className="confirm" role="group" aria-label={question}>
      <span>{question}</span>
      <button type="button" className={className} disabled={disabled} onClick={() => { setAsking(false); onConfirm(); }}>{confirmLabel}</button>
      <button type="button" disabled={disabled} onClick={() => setAsking(false)}>{t('cancel')}</button>
    </span>
  );
}

// CopyButton copies the value it is given. Callers pass the defanged form of
// links and addresses, so what lands on the clipboard is never clickable.
export function CopyButton({ value, label }) {
  const { t } = useTranslation();
  const [state, setState] = useState('');
  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setState('copied');
    } catch {
      setState('error');
    }
    setTimeout(() => setState(''), 2000);
  }
  return (
    <button type="button" className="small" title={t('copySafeHint')} onClick={copy}>
      <span aria-live="polite">{state === 'copied' ? t('copiedSafe') : state === 'error' ? t('error') : label}</span>
    </button>
  );
}

export function Preferences() {
  const { t, i18n } = useTranslation();
  const [theme, setTheme] = useState(localStorage.getItem('cg-theme') || 'system');
  useEffect(() => {
    const media = matchMedia('(prefers-color-scheme: dark)');
    const apply = () => { document.documentElement.dataset.theme = theme === 'system' ? (media.matches ? 'dark' : 'light') : theme; };
    apply();
    media.addEventListener('change', apply);
    localStorage.setItem('cg-theme', theme);
    return () => media.removeEventListener('change', apply);
  }, [theme]);
  return (
    <div className="preferences">
      <select aria-label={t('language')} value={i18n.language} onChange={e => i18n.changeLanguage(e.target.value)}>
        <option value="en">English</option>
        <option value="ru">Русский</option>
        <option value="kk">Қазақша</option>
      </select>
      <select aria-label={t('theme')} value={theme} onChange={e => setTheme(e.target.value)}>
        {['system', 'dark', 'light'].map(v => <option key={v} value={v}>{t(v)}</option>)}
      </select>
    </div>
  );
}
