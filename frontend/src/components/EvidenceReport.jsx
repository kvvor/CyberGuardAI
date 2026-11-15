import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Badge, ConfirmButton, CopyButton, ErrorMessage } from './common';
import AttachmentReputation from './AttachmentReputation';
import '../i18n/app';

// Categories a reader can act on. Everything else is page furniture (images,
// style sheets, tracking pixels) and is hidden until asked for.
const ACTIONABLE = ['form_action', 'actionable_hyperlink', 'link_host', 'attachment', 'email_address', 'email_domain', 'body_text', 'script_resource'];
const PAGE_SIZE = 20;

function parse(value) {
  try { return JSON.parse(value); } catch { return null; }
}

// EvidenceValue renders one backend evidence item as plain text. Values come
// from an untrusted email: they are never rendered as markup or as links.
function EvidenceValue({ item }) {
  const { t } = useTranslation();
  if (!item) return <span className="muted">{t('notProvided')}</span>;
  const data = item.id.startsWith('link-') || item.id.startsWith('attachment-') || item.id.startsWith('reputation-') || item.id.startsWith('resources-') ? parse(item.value) : null;
  if (data && item.id.startsWith('link-')) {
    return (
      <span>
        {data.visible_text && <>{t('linkShown')} “{data.visible_text}” · </>}
        {t('linkLeads')} <code>{data.destination}</code>
        {data.wrapper && <span className="muted"> ({t('iocWrapper')}: {t(data.wrapper, { defaultValue: data.wrapper })})</span>}
      </span>
    );
  }
  if (data && item.id.startsWith('attachment-')) return <span>{data.filename} · {data.size} {t('bytes')} · <code>{data.sha256}</code></span>;
  if (data && item.id.startsWith('reputation-')) {
    return <span>VirusTotal: {t(data.status, { defaultValue: data.status })}{data.statistics && <> · {t('vtMalicious')}: {data.statistics.malicious ?? 0}, {t('vtSuspicious')}: {data.statistics.suspicious ?? 0}</>}</span>;
  }
  if (data && item.id.startsWith('resources-')) return <span>{Object.entries(data).map(([k, n]) => `${t(k, { defaultValue: k })}: ${n}`).join(' · ')}</span>;
  const rule = item.source?.startsWith('observation:') ? item.source.slice(12) : '';
  return <span>{rule && <strong>{t(rule, { defaultValue: rule })}: </strong>}<span className="evidence-value">{item.value}</span></span>;
}

function Findings({ assessment, stance, evidence }) {
  const { t, i18n } = useTranslation();
  const local = v => v?.[i18n.language] || v?.en || '';
  const findings = (assessment.evidence_findings || []).filter(f => f.stance === stance);
  // Reports stored before per-finding explanations existed list IDs only.
  const ids = findings.length || assessment.evidence_findings?.length ? [] : (stance === 'supporting' ? assessment.supporting_evidence_ids : assessment.contradictory_evidence_ids) || [];
  const quotes = stance === 'supporting' ? (assessment.contextual_findings || []).filter(o => o.type !== 'benign_context') : (assessment.contextual_findings || []).filter(o => o.type === 'benign_context');
  if (!findings.length && !ids.length && !quotes.length) return <p className="muted">{stance === 'supporting' ? t('none') : t('noContradictory')}</p>;
  return (
    <ul className="findings">
      {findings.map((f, i) => (
        <li key={i}>
          <p>{local(f.explanation)}</p>
          <ul>{f.evidence_ids.map(id => <li key={id}><code className="id">{id}</code> <EvidenceValue item={evidence[id]} /></li>)}</ul>
        </li>
      ))}
      {ids.map(id => <li key={id}><code className="id">{id}</code> <EvidenceValue item={evidence[id]} /></li>)}
      {quotes.map((o, i) => (
        <li key={`q${i}`}>
          <blockquote>{o.quote}</blockquote>
          <p>{o.reason}</p>
          <small>{t('quotedText')} · {t('modelInterpretation')}</small>
        </li>
      ))}
    </ul>
  );
}

function IOCExplorer({ iocs, observations }) {
  const { t } = useTranslation();
  const [search, setSearch] = useState('');
  const [type, setType] = useState('');
  const [category, setCategory] = useState('');
  const [resources, setResources] = useState(false);
  const [page, setPage] = useState(0);
  const hidden = iocs.filter(v => !ACTIONABLE.includes(v.resource_category)).length;
  const visible = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return iocs.filter(v =>
      (resources || ACTIONABLE.includes(v.resource_category)) &&
      (!type || v.type === type) &&
      (!category || v.resource_category === category) &&
      (!needle || `${v.original_value || ''} ${v.normalized_value || ''} ${v.defanged_value || ''}`.toLowerCase().includes(needle)));
  }, [iocs, search, type, category, resources]);
  const pages = Math.max(1, Math.ceil(visible.length / PAGE_SIZE));
  const current = Math.min(page, pages - 1);
  const reset = fn => value => { fn(value); setPage(0); };
  const types = [...new Set(iocs.map(v => v.type))];
  const categories = [...new Set(iocs.filter(v => resources || ACTIONABLE.includes(v.resource_category)).map(v => v.resource_category).filter(Boolean))];
  const typeLabel = v => t(v === 'email' ? 'email_ioc' : v, { defaultValue: v });
  return (
    <section className="panel">
      <h3>{t('iocExplorer')}</h3>
      <p className="muted">{t('iocHint')}</p>
      <div className="filters">
        <label>{t('iocSearch')}<input type="search" value={search} onChange={e => reset(setSearch)(e.target.value)} /></label>
        <label>{t('iocType')}<select value={type} onChange={e => reset(setType)(e.target.value)}><option value="">{t('all')}</option>{types.map(v => <option key={v} value={v}>{typeLabel(v)}</option>)}</select></label>
        <label>{t('iocCategory')}<select value={category} onChange={e => reset(setCategory)(e.target.value)}><option value="">{t('all')}</option>{categories.map(v => <option key={v} value={v}>{t(v, { defaultValue: v })}</option>)}</select></label>
      </div>
      {hidden > 0 && <label className="consent"><input type="checkbox" checked={resources} onChange={e => { setResources(e.target.checked); setCategory(''); setPage(0); }} />{t('iocShowResources', { n: hidden })}</label>}
      <p className="muted" role="status">{t('iocShown', { shown: visible.length, total: iocs.length })}</p>
      {!visible.length ? <p className="muted">{t('iocNone')}</p> : (
        <ul className="ioc-list">
          {visible.slice(current * PAGE_SIZE, current * PAGE_SIZE + PAGE_SIZE).map((v, i) => (
            <li key={`${v.type}-${v.normalized_value}-${i}`} data-testid="ioc-row">
              <div className="ioc-main">
                <Badge value="ioc-type" label={typeLabel(v.type)} />
                <code className="ioc-value">{v.defanged_value}</code>
                <span className="muted">{t(v.resource_category, { defaultValue: v.resource_category })}</span>
              </div>
              <details>
                <summary>{t('iocDetails')}</summary>
                <dl>
                  <div><dt>{t('iocNormalized')}</dt><dd><code>{v.normalized_value}</code></dd></div>
                  {v.original_value && v.original_value !== v.normalized_value && <div><dt>{t('iocOriginal')}</dt><dd><code>{v.original_value}</code></dd></div>}
                  <div><dt>{t('iocSource')}</dt><dd>{v.source}</dd></div>
                  {v.wrapper && <div><dt>{t('iocWrapper')}</dt><dd>{t(v.wrapper, { defaultValue: v.wrapper })}</dd></div>}
                  {v.finding_ids?.length > 0 && <div><dt>{t('iocObservations')}</dt><dd>{v.finding_ids.map(id => t(observations[id] || id, { defaultValue: id })).join('; ')}</dd></div>}
                </dl>
                <div className="toolbar">
                  <CopyButton value={v.defanged_value} label={t('copyDefanged')} />
                  <CopyButton value={v.original_value || v.normalized_value} label={t('copyOriginal')} />
                </div>
              </details>
            </li>
          ))}
        </ul>
      )}
      {pages > 1 && (
        <div className="toolbar">
          <button type="button" disabled={current === 0} onClick={() => setPage(current - 1)}>{t('previousPage')}</button>
          <span>{t('pageOf', { page: current + 1, pages })}</span>
          <button type="button" disabled={current + 1 >= pages} onClick={() => setPage(current + 1)}>{t('nextPage')}</button>
        </div>
      )}
    </section>
  );
}

export default function EvidenceReport({ analysis, onExport, onDelete, onUpdated, busy, error }) {
  const { t, i18n } = useTranslation();
  const r = analysis.report;
  const a = analysis.ai_assessment;
  const x = analysis.ai_execution || {};
  const local = v => v?.[i18n.language] || v?.en || '';
  const evidence = useMemo(() => Object.fromEntries((r.evidence || []).map(e => [e.id, e])), [r.evidence]);
  const observations = useMemo(() => Object.fromEntries((r.indicators || []).map(f => [f.id, f.rule_id])), [r.indicators]);
  const aiStatus = x.status || r.ai_status || 'not_requested';
  const vtStatus = r.virustotal_status || 'not_requested';
  const limitations = [...new Set(r.limitations || [])];
  const date = value => value ? new Date(value).toLocaleString(i18n.language) : t('notProvided');
  const routing = (r.evidence || []).filter(e => ['Received', 'Return-Path', 'Sender'].includes(e.source));
  const ok = status => ['completed', 'skipped_no_attachments'].includes(status);

  return (
    <>
      <div className="toolbar">
        <Link to="/history">← {t('backToHistory')}</Link>
        <span className="spacer" />
        {onExport && <button type="button" disabled={busy} onClick={() => onExport('pdf')}>{t('exportPDF')}</button>}
        {onExport && <button type="button" disabled={busy} onClick={() => onExport('json')}>{t('exportJSON')}</button>}
        {onDelete && <ConfirmButton label={t('deleteReport')} question={t('deleteConfirm')} confirmLabel={t('deleteYes')} disabled={busy} onConfirm={onDelete} />}
      </div>
      <ErrorMessage error={error} />

      <section className={`panel verdict ${a ? a.proposed_verdict : 'incomplete'}`} aria-labelledby="verdict-title">
        {a ? (
          <>
            <h2 id="verdict-title"><Badge value={a.proposed_verdict} /></h2>
            <dl className="verdict-facts">
              <div><dt>{t('severity')}</dt><dd><Badge value={a.severity === 'none' ? 'low' : a.severity} label={t(a.severity === 'none' ? 'severity_none' : a.severity)} /></dd></div>
              <div><dt>{t('confidence')}</dt><dd>{t(a.confidence)}</dd></div>
            </dl>
            <h3>{t('summary')}</h3>
            <p className="preserve">{local(a.explanations)}</p>
            <small>{t('verdictNotice')}</small>
          </>
        ) : (
          <>
            <h2 id="verdict-title">{t('assessmentMissing')}</h2>
            <p><Badge value="inconclusive" label={t(aiStatus, { defaultValue: aiStatus })} /></p>
            {x.failure_code && <p>{t('reason')}: {t(x.failure_code, { defaultValue: x.failure_code })}</p>}
            <p className="notice">{t('assessmentMissingHint')}</p>
            {['not_configured', 'authentication_failed', 'quota_exceeded', 'unsupported_model'].includes(aiStatus) && <Link to="/settings">{t('openSettings')}</Link>}
          </>
        )}
        <p className="subject">{r.email.subject || t('notProvided')}<br /><span className="muted">{r.email.sender || t('notProvided')}</span></p>
      </section>

      {a && (
        <section className="panel">
          <h3>{t('recommendedActions')}</h3>
          <p className="preserve">{local(a.recommendations)}</p>
        </section>
      )}

      <section className="panel">
        <h3>{t('executionStatus')}</h3>
        <dl>
          <div>
            <dt>OpenAI</dt>
            <dd>
              <Badge value={aiStatus === 'completed' ? 'legitimate' : 'inconclusive'} label={t(aiStatus, { defaultValue: aiStatus })} />
              {x.model && <> <code>{x.model}</code></>}
              {x.duration_ms > 0 && <span className="muted"> · {t('duration', { seconds: (x.duration_ms / 1000).toFixed(1) })}</span>}
              {x.failure_code && <small>{t(x.failure_code, { defaultValue: x.failure_code })}</small>}
            </dd>
          </div>
          <div>
            <dt>VirusTotal</dt>
            <dd><Badge value={ok(vtStatus) ? 'legitimate' : 'inconclusive'} label={t(vtStatus, { defaultValue: vtStatus })} /></dd>
          </div>
          <div><dt>{t('analysedAt')}</dt><dd>{date(analysis.created_at)}</dd></div>
          <div><dt>{t('source')}</dt><dd>{t(r.email.source_type === 'paste' ? 'paste_source' : r.email.source_type, { defaultValue: r.email.source_type })}{r.email.filename && <> · {r.email.filename}</>}</dd></div>
        </dl>
      </section>

      {a && (
        <>
          <section className="panel">
            <h3>{t('supportingEvidence')}</h3>
            <Findings assessment={a} stance="supporting" evidence={evidence} />
          </section>
          <section className="panel">
            <h3>{t('contradictoryEvidence')}</h3>
            <Findings assessment={a} stance="contradictory" evidence={evidence} />
          </section>
        </>
      )}

      <section className="panel">
        <h3>{t('authentication')}</h3>
        <p className="notice">{t('authenticationNotice')}</p>
        <div className="table-scroll">
          <table>
            <thead><tr><th>{t('mechanism')}</th><th>{t('reportedResult')}</th><th>{t('trust')}</th></tr></thead>
            <tbody>
              {(r.authentication || []).map((v, i) => (
                <tr key={i}>
                  <td>{v.mechanism.toUpperCase()}</td>
                  <td>{v.reported_result === 'unavailable' ? <span className="muted">{t('unavailable')}</span> : <code>{v.reported_result}</code>}</td>
                  <td>
                    {v.trust_status !== 'unavailable' && <>{t(v.trust_status, { defaultValue: v.trust_status })}, {t(v.verification_status, { defaultValue: v.verification_status })}</>}
                    {v.reporting_server && <small>{t('reportedBy')} <code>{v.reporting_server}</code> ({v.evidence_source})</small>}
                    {v.alignment_information && !['unavailable', 'not_reported'].includes(v.alignment_information) && <small><code>{v.alignment_information}</code></small>}
                    {(v.limitations || []).map(l => <small key={l}>{t(l, { defaultValue: l })}</small>)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <AttachmentReputation report={r} analysisId={analysis.id} onUpdated={onUpdated} />

      <IOCExplorer iocs={r.iocs || []} observations={observations} />

      <section className="panel">
        <h3>{t('observations')}</h3>
        <p className="muted">{t('observationsHint')}</p>
        {!(r.indicators || []).length ? <p className="muted">{t('noObservations')}</p> : (
          <ul className="findings">
            {r.indicators.map(f => <li key={f.id}><strong>{t(f.rule_id, { defaultValue: f.rule_id })}</strong><br /><span className="evidence-value">{f.evidence}</span></li>)}
          </ul>
        )}
      </section>

      <section className="panel">
        <h3>{t('limitationsTitle')}</h3>
        <ul>{limitations.map(l => <li key={l}>{t(l, { defaultValue: l })}</li>)}</ul>
        {a?.uncertainty_notes?.length > 0 && (
          <>
            <h4>{t('modelUncertainty')}</h4>
            <ul>{a.uncertainty_notes.map((n, i) => <li key={i}>{n}</li>)}</ul>
          </>
        )}
      </section>

      <details className="panel">
        <summary>{t('emailDetails')}</summary>
        <dl>
          {['sender', 'reply_to', 'recipients', 'subject', 'message_id', 'filename', 'file_sha256'].map(k => {
            const value = Array.isArray(r.email[k]) ? r.email[k].join(', ') : r.email[k];
            return <div key={k}><dt>{t(k)}</dt><dd>{value || <span className="muted">{t('notProvided')}</span>}</dd></div>;
          })}
          <div><dt>{t('email_date')}</dt><dd>{r.email.timestamp ? date(r.email.timestamp) : <span className="muted">{t('notProvided')}</span>}</dd></div>
        </dl>
        {routing.length > 0 && (
          <>
            <h4>{t('routing')}</h4>
            <ul>{routing.map(e => <li key={e.id}><strong>{e.source}</strong>: <span className="evidence-value">{e.value}</span></li>)}</ul>
          </>
        )}
      </details>
    </>
  );
}
