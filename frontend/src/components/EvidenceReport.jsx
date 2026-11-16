import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Badge, ConfirmButton, CopyButton, ErrorMessage } from './common';
import AttachmentReputation, { ReputationBadge, formatSize, typeNote } from './AttachmentReputation';
import VerdictRing, { SeverityScale } from './VerdictRing';
import '../i18n/app';

// Categories a reader can act on. Everything else is page furniture (images,
// style sheets, tracking pixels) and is hidden until asked for.
const ACTIONABLE = ['form_action', 'actionable_hyperlink', 'link_host', 'attachment', 'email_address', 'email_domain', 'body_text', 'script_resource'];
const PAGE_SIZE = 20;

function parse(value) {
  try { return JSON.parse(value); } catch { return null; }
}

function defang(value) {
  return String(value || '').replace(/https:\/\//g, 'hxxps://').replace(/http:\/\//g, 'hxxp://').replace(/\./g, '[.]').replace(/@/g, '[@]');
}

function shorten(value, limit) {
  return value.length > limit ? `${value.slice(0, limit)}…` : value;
}

// Model text may be an object with en/ru/kk (current reports) or a single
// string (reports stored before explanations became trilingual).
function useLocal() {
  const { i18n } = useTranslation();
  return value => (typeof value === 'string' ? value : value?.[i18n.language] || value?.en || '');
}

// A quoted passage supports the verdict when it argues the same way: benign
// context for "legitimate", anything else for "phishing" and "suspicious".
// Passages that argue the other way belong to the model's own weighing.
function supportsVerdict(verdict, type) {
  if (verdict === 'legitimate') return type === 'benign_context';
  if (verdict === 'phishing' || verdict === 'suspicious') return type !== 'benign_context';
  return true;
}

// Sender fields, with a fallback for reports stored before name and address
// were kept separately.
function senderParts(email) {
  if (email.sender_name || email.sender_address) return { name: email.sender_name || '', address: email.sender_address || '' };
  const value = (email.sender || '').trim();
  const open = value.lastIndexOf('<');
  const close = value.lastIndexOf('>');
  if (open >= 0 && close > open) return { name: value.slice(0, open).trim().replace(/^"|"$/g, ''), address: value.slice(open + 1, close).trim() };
  return value.includes('@') && !/\s/.test(value) ? { name: '', address: value } : { name: value, address: '' };
}

// EvidenceValue renders one backend evidence item as plain text. Values come
// from an untrusted email: they are never rendered as markup or as links.
function EvidenceValue({ item }) {
  const { t } = useTranslation();
  if (!item) return <span className="muted">{t('notProvided')}</span>;
  const structured = ['link-', 'attachment-', 'reputation-', 'resources-'].some(prefix => item.id.startsWith(prefix));
  const data = structured ? parse(item.value) : null;
  if (data && item.id.startsWith('link-')) {
    return (
      <span>
        {data.visible_text && <>{t('linkShownAs')} “{data.visible_text}” · </>}
        {t('linkLeadsTo')} <code>{defang(data.destination)}</code>
        {data.wrapper && <span className="muted"> ({t('linkWrapped', { wrapper: t(data.wrapper, { defaultValue: data.wrapper }) })})</span>}
      </span>
    );
  }
  if (data && item.id.startsWith('attachment-')) return <span>{data.filename} · {formatSize(data.size, t)} · <code>{data.sha256}</code></span>;
  if (data && item.id.startsWith('reputation-')) {
    return <span>VirusTotal: {t(data.status, { defaultValue: data.status })}{data.statistics && <> · {t('vtMalicious')}: {data.statistics.malicious ?? 0}, {t('vtSuspicious')}: {data.statistics.suspicious ?? 0}</>}</span>;
  }
  if (data && item.id.startsWith('resources-')) return <span>{Object.entries(data).map(([k, n]) => `${t(k, { defaultValue: k })}: ${n}`).join(' · ')}</span>;
  const rule = item.source?.startsWith('observation:') ? item.source.slice(12) : '';
  return <span>{rule && <strong>{t(rule, { defaultValue: rule })}: </strong>}<span className="evidence-value">{item.value}</span></span>;
}

function EmailFields({ email }) {
  const { t, i18n } = useTranslation();
  const { name, address } = senderParts(email);
  const recipients = (email.recipients || []).filter(Boolean).join(', ');
  const rows = [
    ['subjectLabel', email.subject],
    ['displayName', name],
    ['fromAddress', address],
    ['replyTo', email.reply_to],
    ['recipientsLabel', recipients],
    ['emailDate', email.timestamp ? new Date(email.timestamp).toLocaleString(i18n.language) : ''],
  ].filter(([, value]) => value && String(value).trim());
  if (!rows.length) return <p className="muted">{t('senderUnknown')}</p>;
  return (
    <>
      <dl className="email-fields">
        {rows.map(([label, value]) => <div key={label}><dt>{t(label)}</dt><dd>{value}</dd></div>)}
      </dl>
      {name && address && <small>{t('displayNameHint')}</small>}
      {!name && !address && <small>{t('senderUnknown')}</small>}
    </>
  );
}

// The links a reader most needs to see: destinations that differ from the
// visible text and form targets first, then ordinary links, a few at most.
function keyLinks(links) {
  const flagged = links.filter(l => l.text_shows_different_host || l.kind === 'form_action');
  const ordinary = links.filter(l => !l.text_shows_different_host && l.kind !== 'form_action');
  return [...flagged, ...ordinary.slice(0, Math.max(0, 3 - flagged.length))].slice(0, 4);
}

function KeyItems({ report }) {
  const { t } = useTranslation();
  const links = report.links || [];
  const attachments = report.email.attachments || [];
  if (!links.length && !attachments.length) return null;
  const shown = keyLinks(links);
  const find = hash => (report.attachment_reputation || []).find(r => r.sha256 === hash);
  return (
    <section className="panel">
      <h3>{t('keyItemsTitle')}</h3>
      {shown.length > 0 && (
        <ul className="key-links">
          {shown.map((l, i) => (
            <li key={i} className={l.text_shows_different_host || l.kind === 'form_action' ? 'flagged' : ''}>
              {l.text_shows_different_host && l.visible_text && <div>{t('linkShownAs')}: <span className="evidence-value">“{shorten(l.visible_text, 80)}”</span></div>}
              <div>{t('linkLeadsTo')}: <code title={defang(l.destination)}>{shorten(defang(l.destination), 90)}</code></div>
              {l.text_shows_different_host && <small>{t('linkMismatch')}</small>}
              {l.kind === 'form_action' && <small>{t('linkForm')}</small>}
              {l.wrapper && <small>{t('linkWrapped', { wrapper: t(l.wrapper, { defaultValue: l.wrapper }) })}</small>}
            </li>
          ))}
        </ul>
      )}
      {links.length > shown.length && <small>{t('moreLinks', { n: links.length - shown.length })}</small>}
      {shown.length > 0 && <small>{t('linksNotOpened')}</small>}
      {attachments.length > 0 && (
        <ul className="key-attachments">
          {attachments.map((a, i) => {
            const note = typeNote(a.filename);
            return (
              <li key={`${a.sha256}-${i}`}>
                <div className="attachment-main">
                  <strong className="attachment-name">{a.filename || t('notProvided')}</strong>
                  <span className="muted">{formatSize(a.size, t)}</span>
                  <ReputationBadge result={find(a.sha256)} />
                </div>
                {note && <small>{t(note)}</small>}
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}

function Actions({ text }) {
  const { t } = useTranslation();
  const [all, setAll] = useState(false);
  const items = text.split(/\n+/).map(s => s.replace(/^\s*(?:[-•*]|\d+[.)])\s*/, '').trim()).filter(Boolean);
  if (!items.length) return null;
  const visible = all ? items : items.slice(0, 3);
  return (
    <section className="panel">
      <h3>{t('recommendedActions')}</h3>
      {items.length === 1 ? <p className="preserve">{items[0]}</p> : <ol className="actions">{visible.map((item, i) => <li key={i}>{item}</li>)}</ol>}
      {items.length > 3 && <button type="button" className="small" aria-expanded={all} onClick={() => setAll(!all)}>{t(all ? 'showLess' : 'showAll')}</button>}
    </section>
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
    <>
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
                <CopyButton value={v.defanged_value} label={t('copyDefanged')} />
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
    </>
  );
}

function Authentication({ items }) {
  const { t } = useTranslation();
  const raw = [...new Map(items.filter(v => v.raw_value).map(v => [v.raw_value, v.evidence_source])).entries()];
  return (
    <>
      <p className="notice">{t('authenticationNotice')}</p>
      <div className="table-scroll">
        <table className="auth-table">
          <thead><tr><th scope="col">{t('mechanism')}</th><th scope="col">{t('reportedResult')}</th><th scope="col">{t('authNotes')}</th></tr></thead>
          <tbody>
            {items.map((v, i) => {
              const reported = v.reported_result && v.reported_result !== 'unavailable';
              const details = v.alignment_information && !['unavailable', 'not_reported'].includes(v.alignment_information) ? v.alignment_information.replace(/^reported:\s*/, '') : '';
              // Each note is its own list item, so texts can never run together.
              const notes = [];
              if (reported) {
                notes.push(`${t(v.trust_status, { defaultValue: v.trust_status })}; ${t(v.verification_status, { defaultValue: v.verification_status })}.`);
                notes.push(v.reporting_server ? <>{t('authReportedBy')}: <code>{v.reporting_server}</code></> : t('authServerMissing'));
                if (details) notes.push(<>{t('authDetails')}: <code>{details}</code></>);
              }
              for (const l of v.limitations || []) {
                if (l !== 'UPLOADED_HEADERS_CAN_BE_FORGED') notes.push(t(l, { defaultValue: l }));
              }
              return (
                <tr key={`${v.mechanism}-${i}`}>
                  <th scope="row">{v.mechanism.toUpperCase()}</th>
                  <td>{reported ? <code>{v.reported_result}</code> : <span className="muted">{t('authNotReported')}</span>}</td>
                  <td><ul className="notes">{notes.map((n, k) => <li key={k}>{n}</li>)}</ul></td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {raw.length > 0 && (
        <details>
          <summary>{t('authRaw')}</summary>
          {raw.map(([value, source]) => <p key={value} className="raw-header"><strong>{source}:</strong> <span className="evidence-value">{value}</span></p>)}
        </details>
      )}
    </>
  );
}

function FullEvidence({ assessment, evidence }) {
  const { t } = useTranslation();
  const local = useLocal();
  const findings = (assessment.evidence_findings || []).filter(f => f.stance === 'supporting');
  // Reports stored before per-finding explanations existed list IDs only.
  const ids = assessment.evidence_findings?.length ? [] : assessment.supporting_evidence_ids || [];
  const quotes = (assessment.contextual_findings || []).filter(o => supportsVerdict(assessment.proposed_verdict, o.type));
  if (!findings.length && !ids.length && !quotes.length) return <p className="muted">{t('none')}</p>;
  return (
    <>
      <p className="muted">{t('evidenceNote')}</p>
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
            <p>{local(o.reason)}</p>
          </li>
        ))}
      </ul>
    </>
  );
}

function Section({ title, count, children }) {
  return (
    <details className="tech-section">
      <summary><span>{title}</span>{count != null && <span className="count">{count}</span>}</summary>
      <div className="tech-body">{children}</div>
    </details>
  );
}

export default function EvidenceReport({ analysis, onExport, onDelete, onUpdated, busy, error }) {
  const { t, i18n } = useTranslation();
  const local = useLocal();
  const [technical, setTechnical] = useState(false);
  const r = analysis.report;
  const a = analysis.ai_assessment;
  const x = analysis.ai_execution || {};
  const evidence = useMemo(() => Object.fromEntries((r.evidence || []).map(e => [e.id, e])), [r.evidence]);
  const observations = useMemo(() => Object.fromEntries((r.indicators || []).map(f => [f.id, f.rule_id])), [r.indicators]);
  const aiStatus = x.status || r.ai_status || 'not_requested';
  const vtStatus = r.virustotal_status || 'not_requested';
  const limitations = [...new Set(r.limitations || [])];
  const date = value => (value ? new Date(value).toLocaleString(i18n.language) : '');
  const routing = (r.evidence || []).filter(e => ['Received', 'Return-Path', 'Sender'].includes(e.source));
  const ok = status => ['completed', 'skipped_no_attachments'].includes(status);
  const source = r.email.source_type;
  const sourceLabel = t(source === 'paste' ? 'paste_source' : source, { defaultValue: source });
  // Reports stored before the fix carry "." as the file name of pasted text.
  const filename = r.email.filename && r.email.filename !== '.' ? r.email.filename : '';

  // Reasons for the simple view: the model's explanations of its strongest
  // evidence, without identifiers, plus at most two verified quotes.
  const supporting = a ? (a.evidence_findings || []).filter(f => f.stance === 'supporting') : [];
  const supportingQuotes = a ? (a.contextual_findings || []).filter(o => supportsVerdict(a.proposed_verdict, o.type)) : [];
  const reasons = supporting.slice(0, 4);
  const quotes = supportingQuotes.slice(0, reasons.length >= 3 ? 1 : 2);
  const totalEvidence = supporting.length + supportingQuotes.length;
  // Considerations the model weighed against its verdict are shown as notes
  // on the limits of the analysis, not as a section of their own.
  const considerations = a ? [
    ...(a.evidence_findings || []).filter(f => f.stance === 'contradictory').map(f => local(f.explanation)),
    ...(a.uncertainty_notes || []).map(local),
  ].filter(Boolean) : [];
  const identifiers = [['message_id', r.email.message_id], ['filename', filename], ['file_sha256', r.email.file_sha256]].filter(([, value]) => value);
  const rawHeaders = [['subjectLabel', r.email.subject_raw], ['fromAddress', r.email.sender_raw]].filter(([, value]) => value);

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

      <section className={`panel verdict verdict-${a ? a.proposed_verdict : 'incomplete'}`} aria-labelledby="verdict-title">
        <div className="verdict-head">
          <VerdictRing verdict={a ? a.proposed_verdict : 'incomplete'} severity={a?.severity} />
          <div className="verdict-text">
            {a ? (
              <>
                <h2 id="verdict-title" className={`verdict-word ${a.proposed_verdict}`}>{t(a.proposed_verdict)}</h2>
                <SeverityScale severity={a.severity} />
                <p className="confidence">{t('confidenceLabel')}: <strong>{t(a.confidence)}</strong></p>
              </>
            ) : (
              <>
                <h2 id="verdict-title">{t('assessmentMissing')}</h2>
                <p><Badge value="inconclusive" label={t(aiStatus, { defaultValue: aiStatus })} /></p>
              </>
            )}
          </div>
        </div>
        {a ? (
          <>
            <p className="summary preserve">{local(a.explanations)}</p>
            {a.proposed_verdict === 'legitimate' && (
              <p className="notice">{t('legitimateNotice')}{!r.email.sender_address && !r.email.sender && <> {t('legitimateNoHeaders')}</>}</p>
            )}
            <small>{t('verdictNotice')}</small>
          </>
        ) : (
          <>
            {x.failure_code && <p>{t('reason')}: {t(x.failure_code, { defaultValue: x.failure_code })}</p>}
            <p className="notice">{t('assessmentMissingHint')}</p>
            {['not_configured', 'authentication_failed', 'quota_exceeded', 'unsupported_model'].includes(aiStatus) && <Link to="/settings">{t('openSettings')}</Link>}
          </>
        )}
      </section>

      <section className="panel">
        <h3>{t('emailTitle')}</h3>
        <EmailFields email={r.email} />
      </section>

      {a && (reasons.length > 0 || quotes.length > 0) && (
        <section className="panel">
          <h3>{t('whyTitle')}</h3>
          <ul className="reasons">
            {reasons.map((f, i) => <li key={i}>{local(f.explanation)}</li>)}
            {quotes.map((o, i) => (
              <li key={`q${i}`}>
                <blockquote><span className="quote-label">{t('quoteFromEmail')}: </span>{shorten(o.quote, 240)}</blockquote>
                {local(o.reason)}
              </li>
            ))}
          </ul>
          {totalEvidence > reasons.length + quotes.length && <small>{t('whyMore')}</small>}
        </section>
      )}

      <KeyItems report={r} />

      {a && <Actions text={local(a.recommendations)} />}

      <section className="panel technical" aria-labelledby="technical-title">
        <div className="technical-head">
          <div>
            <h3 id="technical-title">{t('technicalTitle')}</h3>
            <p className="muted">{t('technicalHint')}</p>
          </div>
          <button type="button" aria-expanded={technical} aria-controls="technical-body" onClick={() => setTechnical(!technical)}>{t(technical ? 'technicalHide' : 'technicalShow')}</button>
        </div>
        {technical && (
          <div id="technical-body">
            {a && <Section title={t('evidenceFull')} count={totalEvidence}><FullEvidence assessment={a} evidence={evidence} /></Section>}
            <Section title={t('authenticationFull')}><Authentication items={r.authentication || []} /></Section>
            {(r.email.attachments || []).length > 0 && (
              <Section title={t('attachmentsTitle')} count={r.email.attachments.length}>
                <AttachmentReputation report={r} analysisId={analysis.id} onUpdated={onUpdated} />
              </Section>
            )}
            {(r.iocs || []).length > 0 && <Section title={t('iocExplorer')} count={r.iocs.length}><IOCExplorer iocs={r.iocs} observations={observations} /></Section>}
            {(r.indicators || []).length > 0 && (
              <Section title={t('observations')} count={r.indicators.length}>
                <p className="muted">{t('observationsHint')}</p>
                <ul className="findings">
                  {r.indicators.map(f => <li key={f.id}><strong>{t(f.rule_id, { defaultValue: f.rule_id })}</strong><br /><span className="evidence-value">{f.evidence}</span></li>)}
                </ul>
              </Section>
            )}
            <Section title={t('runTitle')}>
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
                <div><dt>VirusTotal</dt><dd><Badge value={ok(vtStatus) ? 'legitimate' : 'inconclusive'} label={t(vtStatus, { defaultValue: vtStatus })} /></dd></div>
                <div><dt>{t('analysedAt')}</dt><dd>{date(analysis.created_at)}</dd></div>
                <div><dt>{t('source')}</dt><dd>{[sourceLabel, filename].filter(Boolean).join(' · ')}</dd></div>
              </dl>
            </Section>
            <Section title={t('limitationsTitle')}>
              <ul>
                {limitations.map(l => <li key={l}>{t(l, { defaultValue: l })}</li>)}
                <li>{t('caveatNotGuarantee')}</li>
              </ul>
              {considerations.length > 0 && (
                <>
                  <h4>{t('modelNotes')}</h4>
                  <ul>{considerations.map((n, i) => <li key={i}>{n}</li>)}</ul>
                </>
              )}
            </Section>
            {(identifiers.length > 0 || routing.length > 0 || rawHeaders.length > 0) && (
              <Section title={t('headersTitle')}>
                {identifiers.length > 0 && <dl>{identifiers.map(([k, value]) => <div key={k}><dt>{t(k)}</dt><dd><code>{value}</code></dd></div>)}</dl>}
                {rawHeaders.length > 0 && (
                  <>
                    <h4>{t('rawHeaderValue')}</h4>
                    <ul>{rawHeaders.map(([label, value]) => <li key={label}><strong>{t(label)}:</strong> <span className="evidence-value">{value}</span></li>)}</ul>
                  </>
                )}
                {routing.length > 0 && (
                  <>
                    <h4>{t('routing')}</h4>
                    <ul>{routing.map(e => <li key={e.id}><strong>{e.source}:</strong> <span className="evidence-value">{e.value}</span></li>)}</ul>
                  </>
                )}
              </Section>
            )}
          </div>
        )}
      </section>
    </>
  );
}
