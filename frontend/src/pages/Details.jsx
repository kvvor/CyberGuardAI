import { useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { api, downloadReport } from '../services/api';
import { Badge, ConfirmButton, CopyButton, ErrorMessage, Resource, useResource } from '../components/common';
import EvidenceReport from '../components/EvidenceReport';
import AttachmentReputation from '../components/AttachmentReputation';
import '../i18n/app';

const CURRENT_VERSION = '3.0.0';

function Values({ values }) {
  const { t } = useTranslation();
  if (!values?.length) return null;
  return <ul>{values.map((v, i) => <li key={i}>{t(v, { defaultValue: v })}</li>)}</ul>;
}

// LegacyReport shows a report stored by the retired rule-weight detector. The
// stored data is displayed as it was, clearly labelled, without presenting the
// old score as a probability or as a current verdict.
function LegacyReport({ analysis, busy, error, onExport, onDelete }) {
  const { t, i18n } = useTranslation();
  const [filter, setFilter] = useState('');
  const r = analysis.report;
  const e = r.email;
  const local = v => v?.[i18n.language] || v?.en || '';
  return (
    <>
      <div className="toolbar">
        <Link to="/history">← {t('backToHistory')}</Link>
        <span className="spacer" />
        <button type="button" disabled={busy} onClick={() => onExport('pdf')}>{t('exportPDF')}</button>
        <button type="button" disabled={busy} onClick={() => onExport('json')}>{t('exportJSON')}</button>
        <ConfirmButton label={t('deleteReport')} question={t('deleteConfirm')} confirmLabel={t('deleteYes')} disabled={busy} onConfirm={onDelete} />
      </div>
      <ErrorMessage error={error} />
      <section className="panel">
        <h2>{t('legacyReport')}</h2>
        <p className="notice">{t('legacyNotice')}</p>
        <p><Badge value={r.verdict} /> · {t('legacyScore')}: <strong>{r.risk_score ?? 0}</strong></p>
        <h3>{e.subject || t('notProvided')}</h3>
        <p>{e.sender || t('notProvided')}</p>
        <small>{new Date(analysis.created_at).toLocaleString(i18n.language)}</small>
      </section>
      <section className="panel">
        <h3>{t('emailDetails')}</h3>
        <dl>
          {['sender', 'reply_to', 'recipients', 'subject', 'message_id', 'source_type', 'filename', 'file_sha256'].map(key => (
            <div key={key}><dt>{t(key, { defaultValue: key })}</dt><dd>{(Array.isArray(e[key]) ? e[key].join(', ') : e[key]) || t('notProvided')}</dd></div>
          ))}
        </dl>
        <Values values={e.authentication_results} />
      </section>
      <section className="panel">
        <h3>{t('observations')}</h3>
        {r.indicators?.length ? r.indicators.map(f => (
          <details key={f.id}>
            <summary>{t(f.description_code, { defaultValue: f.description_code })}</summary>
            <p>{f.evidence}</p>
          </details>
        )) : <p className="muted">{t('noObservations')}</p>}
      </section>
      <section className="panel">
        <h3>{t('iocExplorer')}</h3>
        <select aria-label={t('iocType')} value={filter} onChange={ev => setFilter(ev.target.value)}>
          {['', 'url', 'domain', 'ip', 'email', 'hash', 'sha256'].map(v => <option key={v} value={v}>{t(v === 'email' ? 'email_ioc' : v || 'all')}</option>)}
        </select>
        <div className="table-scroll">
          <table>
            <tbody>
              {r.iocs?.filter(i => !filter || i.type === filter).map((ioc, index) => (
                <tr key={index}>
                  <td>{ioc.type}</td>
                  <td><code>{ioc.value}</code><small>{ioc.source}</small></td>
                  <td><CopyButton value={ioc.defanged_value} label={t('copyDefanged')} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
      <AttachmentReputation report={r} />
      <section className="panel">
        <h3>{t('summary')}</h3>
        <p className="preserve">{local(analysis.explanations)}</p>
        <h3>{t('recommendedActions')}</h3>
        <p className="preserve">{local(analysis.recommendations)}</p>
        <h3>{t('limitationsTitle')}</h3>
        <Values values={r.limitations} />
      </section>
    </>
  );
}

export default function Details() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { i18n } = useTranslation();
  const resource = useResource(`/analyses/${encodeURIComponent(id)}`);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function run(fn) {
    setBusy(true);
    setError(null);
    try { await fn(); } catch (e) { setError({ code: e.code || 'error', requestId: e.requestId }); } finally { setBusy(false); }
  }
  const onExport = format => run(() => downloadReport(id, format, i18n.language));
  const onDelete = () => run(async () => {
    await api(`/analyses/${encodeURIComponent(id)}`, { method: 'DELETE' });
    navigate('/history');
  });

  return (
    <Resource resource={resource}>
      {analysis => analysis.report.scoring_version === CURRENT_VERSION
        ? <EvidenceReport analysis={analysis} busy={busy} error={error} onExport={onExport} onDelete={onDelete} onUpdated={resource.set} />
        : <LegacyReport analysis={analysis} busy={busy} error={error} onExport={onExport} onDelete={onDelete} />}
    </Resource>
  );
}
