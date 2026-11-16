import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { api } from '../services/api';
import { ErrorMessage } from './common';
import { ReputationBadge, ReputationStats } from './AttachmentReputation';
import '../i18n/app';

// HashLookup asks VirusTotal for its existing report on one SHA-256. A lookup
// happens only when the button is pressed, once per press; the result is shown
// and not stored. No file is involved at any point.
export default function HashLookup({ ready }) {
  const { t, i18n } = useTranslation();
  const [value, setValue] = useState('');
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState('');
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);
  const hash = value.trim().toLowerCase();

  async function check(event) {
    event.preventDefault();
    setError(null);
    setResult(null);
    if (!/^[0-9a-f]*$/.test(hash)) return setProblem(t('hashInvalidChars'));
    if (hash.length !== 64) return setProblem(t('hashInvalid', { n: hash.length }));
    setProblem('');
    setBusy(true);
    try {
      const response = await api('/reputation/virustotal', { method: 'POST', body: { sha256: hash } });
      setResult(response.result);
    } catch (e) {
      setError({ code: e.code, requestId: e.requestId });
    } finally {
      setBusy(false);
    }
  }

  const status = result?.status;
  return (
    <details className="panel hash-lookup">
      <summary>{t('hashLookupTitle')}</summary>
      <p className="muted">{t('hashLookupIntro')}</p>
      {!ready ? <p className="notice">{t('hashNeedsProvider')} <Link to="/settings">{t('openSettings')}</Link></p> : (
        <form onSubmit={check} noValidate className="hash-form">
          <label>
            {t('hashLabel')}
            <input value={value} disabled={busy} spellCheck={false} autoComplete="off" autoCapitalize="off" maxLength={80} placeholder={t('hashPlaceholder')}
              aria-invalid={Boolean(problem)} aria-describedby="hash-problem" onChange={e => { setValue(e.target.value); setProblem(''); }} />
          </label>
          <button className="primary" disabled={busy || !hash}>{busy ? t('loading') : t('hashCheck')}</button>
        </form>
      )}
      <div id="hash-problem">{problem && <div role="alert" className="notice error">{problem}</div>}</div>
      <ErrorMessage error={error} />
      {result && (
        <div className="hash-result" role="status">
          <h4>{t(status === 'completed' ? 'hashResultKnown' : status === 'not_found' ? 'hashResultUnknown' : 'hashResultFailed')}</h4>
          <p><ReputationBadge result={result} /></p>
          <p className="hash-line"><code>{result.sha256}</code></p>
          <ReputationStats result={result} />
          {status === 'not_found' && <p>{t('hashResultUnknownHint')}</p>}
          {result.checked_at && <p className="muted">{t('hashCheckedAt')}: {new Date(result.checked_at).toLocaleString(i18n.language)}</p>}
          <p className="notice">{t('hashDisclaimer')}</p>
        </div>
      )}
    </details>
  );
}
