import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api, ANALYSIS_TIMEOUT } from '../services/api';
import { Badge, ErrorMessage } from './common';
import '../i18n/app';

const answered = status => status === 'completed' || status === 'not_found';

function tone(result) {
  if (!result || !answered(result.status)) return 'inconclusive';
  if (result.status === 'completed' && (result.statistics?.malicious > 0 || result.statistics?.suspicious > 0)) return 'phishing';
  // Neither "unknown" nor "no detections" is shown as safe.
  return 'inconclusive';
}

// AttachmentReputation renders stored VirusTotal hash lookups. With an
// analysis id it also offers to complete lookups that were not answered.
export default function AttachmentReputation({ report, analysisId, onUpdated }) {
  const { t, i18n } = useTranslation();
  const [consent, setConsent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const attachments = report.email.attachments || [];
  const results = report.attachment_reputation || [];
  const find = hash => results.find(r => r.sha256 === hash);
  // Only lookups that were attempted can be completed; "not requested" needs a new analysis with consent.
  const retryable = ['deferred_local_limit', 'rate_limited', 'timeout', 'network_error', 'provider_error'];
  const pending = attachments.filter(a => retryable.includes(find(a.sha256)?.status)).length;

  async function recheck() {
    setBusy(true);
    setError(null);
    try {
      onUpdated(await api(`/analyses/${encodeURIComponent(analysisId)}/virustotal`, { method: 'POST', body: { virustotal_consent: consent }, timeout: ANALYSIS_TIMEOUT }));
    } catch (e) {
      setError({ code: e.code, requestId: e.requestId });
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel">
      <h3>{t('attachmentsTitle')}</h3>
      {!attachments.length ? <p className="muted">{t('vtNoAttachments')}</p> : (
        <>
          <p className="notice">{t('vtUnknown')}</p>
          {attachments.map((a, i) => {
            const r = find(a.sha256);
            const status = r?.status || 'not_requested';
            return (
              <article key={`${a.sha256}-${i}`} className="attachment">
                <h4>{a.filename || t('notProvided')} <Badge value={tone(r)} label={t(status, { defaultValue: status })} /></h4>
                <p className="muted">{a.size} {t('bytes')} · {t('declaredType')}: {a.declared_mime || t('notProvided')} · {t('detectedType')}: {a.detected_mime || t('notProvided')}</p>
                <p>SHA-256: <code>{a.sha256}</code></p>
                {r?.statistics && (
                  <dl className="stats-inline">
                    {[['vtMalicious', 'malicious'], ['vtSuspicious', 'suspicious'], ['vtHarmless', 'harmless'], ['vtUndetected', 'undetected']].map(([label, field]) => (
                      <div key={field}><dt>{t(label)}</dt><dd className={field === 'malicious' && r.statistics[field] > 0 ? 'phishing' : ''}>{r.statistics[field] ?? 0}</dd></div>
                    ))}
                  </dl>
                )}
                {r?.engines?.length > 0 && <p className="muted">{t('vtDetections')}: {r.engines.slice(0, 8).map(e => `${e.name}: ${e.result || e.category}`).join('; ')}</p>}
                {r?.last_analysis_at && <p className="muted">{t('vtLastAnalysis')}: {new Date(r.last_analysis_at).toLocaleString(i18n.language)}</p>}
                {r && answered(r.status) && <p className="muted">{t('vtSource')}</p>}
              </article>
            );
          })}
          {analysisId && pending > 0 && (
            <div className="notice">
              <p>{t('vtRecheckHint', { n: pending })}</p>
              <label className="consent"><input type="checkbox" checked={consent} disabled={busy} onChange={e => setConsent(e.target.checked)} />{t('consentVT')}</label>
              <ErrorMessage error={error} />
              <button type="button" disabled={busy || !consent} onClick={recheck}>{busy ? t('loading') : t('vtRecheck')}</button>
            </div>
          )}
        </>
      )}
    </section>
  );
}
