import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip } from 'recharts';
import { query } from '../services/api';
import { Badge, Empty, Resource, useResource } from '../components/common';
import '../i18n/app';

const CURRENT_VERSION = '3.0.0';

// Chart bars grow in once when data arrives, unless the user asked the system
// to reduce motion.
const reducedMotion = () => typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)')?.matches === true;

// One row per stored analysis. A verdict is shown only for a validated
// assessment; incomplete and historical reports are labelled as such.
export function AnalysisTable({ items = [], emptyMessage }) {
  const { t, i18n } = useTranslation();
  if (!items.length) return <Empty message={emptyMessage} />;
  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>{['subject', 'sender', 'verdict', 'severity', 'source', 'assessment'].map(k => <th key={k} scope="col">{t(k)}</th>)}</tr>
        </thead>
        <tbody>
          {items.map(a => {
            const current = a.report.scoring_version === CURRENT_VERSION;
            const assessed = current && a.ai_assessment;
            const status = a.ai_execution?.status || a.report.ai_status || 'not_requested';
            const source = a.report.email.source_type;
            return (
              <tr key={a.id}>
                <td>
                  <Link to={`/analyses/${a.id}`}>{a.report.email.subject || t('notProvided')}</Link>
                  <small>{new Date(a.created_at).toLocaleString(i18n.language)}</small>
                </td>
                <td>{a.report.email.sender || <span className="muted">{t('notProvided')}</span>}</td>
                <td>
                  {assessed ? <Badge value={a.ai_assessment.proposed_verdict} />
                    : current ? <Badge value="inconclusive" label={t('noVerdict')} />
                      : <><Badge value="inconclusive" label={t('historical')} /><small>{t(a.report.verdict, { defaultValue: a.report.verdict })}</small></>}
                </td>
                <td>{assessed ? <Badge value={a.ai_assessment.severity === 'none' ? 'low' : a.ai_assessment.severity} label={t(a.ai_assessment.severity)} /> : <span className="muted">—</span>}</td>
                <td>{t(source === 'paste' ? 'paste_source' : source, { defaultValue: source })}</td>
                <td>{current ? t(status, { defaultValue: status }) : <span className="muted">—</span>}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function Chart({ title, data }) {
  const { t } = useTranslation();
  const hasData = data?.some(d => d.count > 0);
  return (
    <section className="panel chart enter">
      <h3>{t(title)}</h3>
      {hasData ? (
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={data}>
            <XAxis dataKey="name" tick={{ fill: 'var(--muted)', fontSize: 11 }} />
            <YAxis allowDecimals={false} tick={{ fill: 'var(--muted)' }} />
            <Tooltip contentStyle={{ background: 'var(--surface)', borderColor: 'var(--border)' }} />
            <Bar dataKey="count" name={t('count')} fill="#22b8cf" radius={[4, 4, 0, 0]} isAnimationActive={!reducedMotion()} animationDuration={500} animationEasing="ease-out" />
          </BarChart>
        </ResponsiveContainer>
      ) : <p className="muted">{t('noData')}</p>}
    </section>
  );
}

export default function Dashboard() {
  const { t } = useTranslation();
  const [period, setPeriod] = useState('30');
  const resource = useResource(`/dashboard/stats?${query({ period })}`);
  const cards = d => [
    ['total', d.total_analyses], ['completedCount', d.completed_count],
    ['phishing', d.phishing_count], ['suspicious', d.suspicious_count], ['legitimate', d.legitimate_count], ['inconclusive', d.inconclusive_count],
    ['incomplete', d.incomplete_count], ['legacy', d.legacy_count],
  ];
  return (
    <>
      <div className="toolbar">
        <label className="inline">{t('period')}
          <select value={period} onChange={e => setPeriod(e.target.value)}>
            {['7', '30', '90', 'all'].map(v => <option key={v} value={v}>{v === 'all' ? t('all') : `${v} ${t('days')}`}</option>)}
          </select>
        </label>
        <span className="spacer" />
        <Link className="primary" to="/analyze">{t('newAnalysis')}</Link>
      </div>
      <Resource resource={resource}>
        {d => (
          <>
            <div className="stats">
              {cards(d).map(([key, value]) => (
                <div className="panel stat enter" key={key}><span>{t(key)}</span><strong>{value ?? 0}</strong></div>
              ))}
            </div>
            <p className="muted">{t('dashboardNote')}</p>
            <div className="chart-grid">
              <Chart title="activityChart" data={d.activity_series?.map(v => ({ name: v.date, count: v.count }))} />
              <Chart title="verdictChart" data={['phishing', 'suspicious', 'legitimate', 'inconclusive'].map(k => ({ name: t(k), count: d.verdict_distribution?.[k] || 0 }))} />
              <Chart title="severityChart" data={['none', 'low', 'medium', 'high', 'critical'].map(k => ({ name: t(k), count: d.severity_distribution?.[k] || 0 }))} />
              <Chart title="categoryChart" data={(d.common_attack_types || []).map(v => ({ name: t(v.name, { defaultValue: v.name }), count: v.count }))} />
            </div>
            <section className="panel">
              <h3>{t('recent')}</h3>
              <AnalysisTable items={d.recent_analyses} />
            </section>
          </>
        )}
      </Resource>
    </>
  );
}

export function History() {
  const { t } = useTranslation();
  const [filters, setFilters] = useState({ page: 1, page_size: 20, search: '', verdict: '', status: '', sort: 'newest', date_from: '', date_to: '' });
  const resource = useResource(`/analyses?${query(filters)}`);
  const change = (key, value) => setFilters({ ...filters, [key]: value, page: 1 });
  const selects = [
    ['verdict', 'verdict', [['', 'all'], ['phishing', 'phishing'], ['suspicious', 'suspicious'], ['legitimate', 'legitimate'], ['inconclusive', 'inconclusive']]],
    ['status', 'statusFilter', [['', 'all'], ['complete', 'statusComplete'], ['partial', 'statusPartial'], ['legacy', 'statusLegacy']]],
    ['sort', 'sort', [['newest', 'newest'], ['oldest', 'oldest']]],
  ];
  return (
    <>
      <div className="filters">
        <label>{t('search')}<input type="search" value={filters.search} maxLength={256} onChange={e => change('search', e.target.value)} /></label>
        {selects.map(([key, label, options]) => (
          <label key={key}>{t(label)}
            <select value={filters[key]} onChange={e => change(key, e.target.value)}>
              {options.map(([value, text]) => <option key={value} value={value}>{t(text)}</option>)}
            </select>
          </label>
        ))}
        {['date_from', 'date_to'].map(k => <label key={k}>{t(k)}<input type="date" value={filters[k]} onChange={e => change(k, e.target.value)} /></label>)}
      </div>
      <Resource resource={resource}>
        {d => {
          const pages = Math.max(1, Math.ceil(d.total / d.page_size));
          return (
            <section className="panel">
              <AnalysisTable items={d.items} emptyMessage={d.total === 0 && (filters.search || filters.verdict || filters.status || filters.date_from || filters.date_to) ? t('historyEmpty') : undefined} />
              <div className="toolbar">
                <button type="button" disabled={filters.page === 1} onClick={() => setFilters({ ...filters, page: filters.page - 1 })}>{t('previous')}</button>
                <span>{t('pageOf', { page: d.page, pages })} · {d.total}</span>
                <button type="button" disabled={filters.page >= pages} onClick={() => setFilters({ ...filters, page: filters.page + 1 })}>{t('next')}</button>
              </div>
            </section>
          );
        }}
      </Resource>
    </>
  );
}
