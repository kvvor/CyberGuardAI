import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api, ANALYSIS_TIMEOUT } from '../services/api';
import { Badge, CopyButton, ErrorMessage } from './common';
import '../i18n/app';

export const answered = status => status === 'completed' || status === 'not_found';
export const detections = result => (result?.status === 'completed' ? (result.statistics?.malicious || 0) + (result.statistics?.suspicious || 0) : 0);

// File types that deserve a plain-language note. The note describes what the
// type can do; it never says that a particular file is harmful.
const TYPE_NOTES = [
  ['typeNoteProfile', ['mobileconfig', 'mobileprovision', 'reg', 'inf', 'ppkg']],
  ['typeNoteExecutable', ['exe', 'dll', 'js', 'jse', 'vbs', 'vbe', 'ps1', 'bat', 'cmd', 'scr', 'hta', 'com', 'msi', 'lnk', 'jar', 'wsf', 'iso', 'img']],
  ['typeNoteMacro', ['docm', 'xlsm', 'pptm', 'dotm', 'xlam']],
  ['typeNoteArchive', ['zip', 'rar', '7z', 'gz', 'tar', 'cab']],
  ['typeNoteWeb', ['html', 'htm', 'svg', 'shtml']],
];
export function typeNote(filename) {
  const extension = (filename || '').toLowerCase().split('.').pop();
  return TYPE_NOTES.find(([, list]) => list.includes(extension))?.[0] || '';
}

export function formatSize(bytes, t) {
  if (!Number.isFinite(bytes)) return '';
  if (bytes < 1024) return `${bytes} ${t('bytes')}`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

// The status shown next to a file. Unknown hashes and reports without
// detections use a neutral tone: neither is evidence that a file is safe.
export function ReputationBadge({ result }) {
  const { t } = useTranslation();
  const status = result?.status || 'not_requested';
  const found = detections(result);
  if (status === 'completed') {
    return <Badge value={found > 0 ? 'phishing' : 'inconclusive'} label={`VirusTotal: ${found > 0 ? t('vtDetectionsShort', { n: found }) : t('vtNoDetectionsShort')}`} />;
  }
  return <Badge value="inconclusive" label={`VirusTotal: ${t(status, { defaultValue: status })}`} />;
}

export function ReputationStats({ result }) {
  const { t, i18n } = useTranslation();
  if (!result?.statistics) return null;
  return (
    <>
      <dl className="stats-inline">
        {[['vtMalicious', 'malicious'], ['vtSuspicious', 'suspicious'], ['vtHarmless', 'harmless'], ['vtUndetected', 'undetected']].map(([label, field]) => (
          <div key={field}><dt>{t(label)}</dt><dd className={(field === 'malicious' || field === 'suspicious') && result.statistics[field] > 0 ? 'phishing' : ''}>{result.statistics[field] ?? 0}</dd></div>
        ))}
      </dl>
      {result.engines?.length > 0 && <p className="muted">{t('vtDetections')}: {result.engines.slice(0, 8).map(e => `${e.name}: ${e.result || e.category}`).join('; ')}</p>}
      {result.last_analysis_at && <p className="muted">{t('vtLastAnalysis')}: {new Date(result.last_analysis_at).toLocaleString(i18n.language)}</p>}
    </>
  );
}

// Compact row: name, size, type note and reputation status. Everything else,
// including the full hash, is one click away.
export function AttachmentRow({ attachment, result, expanded = false }) {
  const { t } = useTranslation();
  const note = typeNote(attachment.filename);
  const declared = attachment.declared_mime || t('notProvided');
  const detected = attachment.detected_mime || t('notProvided');
  return (
    <li className="attachment-row">
      <div className="attachment-main">
        <strong className="attachment-name">{attachment.filename || t('notProvided')}</strong>
        <span className="muted">{formatSize(attachment.size, t)}</span>
        <ReputationBadge result={result} />
      </div>
      {note && <p className="type-note">{t(note)} <span className="muted">{t('typeNoteDisclaimer')}</span></p>}
      <details open={expanded}>
        <summary>{t('attachmentDetails')}</summary>
        <p className="hash-line">SHA-256: <code>{attachment.sha256}</code> <CopyButton value={attachment.sha256} label={t('copyDefanged')} /></p>
        <ReputationStats result={result} />
        <h5>{t('attachmentFacts')}</h5>
        <ul className="facts">
          <li>{t('factObserved')}</li>
          <li>{t('factType', { declared, detected })}</li>
          <li>{t('factHash')}</li>
          <li>{answered(result?.status) ? t('factLookupDone') : `${t('factLookupNone')} (${t(result?.status || 'not_requested', { defaultValue: result?.status })})`}</li>
          <li>{t('factContent')}</li>
        </ul>
      </details>
    </li>
  );
}

// AttachmentReputation lists attachments with their stored VirusTotal hash
// lookups. With an analysis id it also offers to complete unanswered lookups.
export default function AttachmentReputation({ report, analysisId, onUpdated }) {
  const { t } = useTranslation();
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

  if (!attachments.length) return <p className="muted">{t('vtNoAttachments')}</p>;
  return (
    <>
      <ul className="attachment-list">
        {attachments.map((a, i) => <AttachmentRow key={`${a.sha256}-${i}`} attachment={a} result={find(a.sha256)} />)}
      </ul>
      <p className="muted">{t('vtUnknown')}</p>
      {analysisId && onUpdated && pending > 0 && (
        <div className="notice">
          <p>{t('vtRecheckHint', { n: pending })}</p>
          <label className="consent"><input type="checkbox" checked={consent} disabled={busy} onChange={e => setConsent(e.target.checked)} />{t('consentVT')}</label>
          <ErrorMessage error={error} />
          <button type="button" disabled={busy || !consent} onClick={recheck}>{busy ? t('loading') : t('vtRecheck')}</button>
        </div>
      )}
    </>
  );
}
