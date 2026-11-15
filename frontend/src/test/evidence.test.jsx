import { it, expect, vi, describe } from 'vitest';
import { render, screen, fireEvent, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import EvidenceReport from '../components/EvidenceReport';
import i18n from '../i18n';
import '../i18n/app';

const loc = s => ({ en: s, ru: `ru:${s}`, kk: `kk:${s}` });
const base = {
  id: 'a1', created_at: '2026-03-03T09:00:00Z',
  ai_execution: { status: 'completed', model: 'model-x', duration_ms: 2300 },
  report: {
    scoring_version: '3.0.0', virustotal_status: 'skipped_no_attachments',
    email: { subject: '<img src=x onerror=alert(1)>', sender: 'Sender <sender@example.test>', source_type: 'eml', attachments: [] },
    iocs: [],
    indicators: [{ id: 'observation-1', rule_id: 'LINK_TEXT_SHOWS_DIFFERENT_HOST', evidence: 'bank.example -> http://198.51.100.7/' }],
    evidence: [
      { id: 'sender-1', source: 'from', value: 'Sender <sender@example.test>' },
      { id: 'observation-1', source: 'observation:LINK_TEXT_SHOWS_DIFFERENT_HOST', value: 'bank.example -> http://198.51.100.7/' },
      { id: 'link-1', source: 'hyperlink', value: JSON.stringify({ visible_text: 'bank.example', destination: 'http://198.51.100.7/', wrapper: 'microsoft_safelinks' }) },
    ],
    authentication: [
      { mechanism: 'spf', reported_result: 'pass', reporting_server: 'mx.example.test', evidence_source: 'Authentication-Results', trust_status: 'untrusted_reported', verification_status: 'unable_to_verify', alignment_information: 'reported: smtp.mailfrom=example.test', limitations: ['UPLOADED_HEADERS_CAN_BE_FORGED'] },
      { mechanism: 'dkim', reported_result: 'unavailable', trust_status: 'unavailable', verification_status: 'unavailable', alignment_information: 'unavailable', limitations: ['NO_REPORTED_RESULT'] },
    ],
    limitations: ['AUTHENTICATION_NOT_INDEPENDENTLY_VERIFIED', 'AUTHENTICATION_NOT_INDEPENDENTLY_VERIFIED', 'FUTURE_CODE'],
  },
};
const assessment = {
  proposed_verdict: 'phishing', severity: 'high', confidence: 'medium',
  evidence_findings: [
    { stance: 'supporting', evidence_ids: ['observation-1', 'link-1'], explanation: loc('The link leads somewhere else.') },
    { stance: 'contradictory', evidence_ids: ['sender-1'], explanation: loc('The sender looks ordinary.') },
  ],
  contextual_findings: [{ type: 'credential_theft', quote: 'confirm your password', reason: 'asks for a secret' }],
  uncertainty_notes: ['Headers are unverified.'],
  explanations: loc('Deceptive link.'), recommendations: loc('Do not sign in.'),
};
const show = (analysis, props = {}) => render(<MemoryRouter><EvidenceReport analysis={analysis} onExport={vi.fn()} onDelete={vi.fn()} onUpdated={vi.fn()} {...props} /></MemoryRouter>);

describe('evidence report', () => {
  it('shows verdict, severity, qualitative confidence and grounded evidence without a score', () => {
    show({ ...base, ai_assessment: assessment });
    expect(screen.getByRole('heading', { name: 'Phishing' })).toBeInTheDocument();
    expect(screen.getByText('High')).toBeInTheDocument();
    expect(screen.getByText('Deceptive link.')).toBeInTheDocument();
    expect(screen.getByText('Do not sign in.')).toBeInTheDocument();
    expect(screen.getByText(/not a probability/)).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/\/ 100|%\s*risk|risk score/i);
    // Supporting and contradictory evidence are separate and resolve their references.
    const supporting = screen.getByRole('heading', { name: 'Evidence supporting the verdict' }).closest('section');
    expect(within(supporting).getByText('The link leads somewhere else.')).toBeInTheDocument();
    expect(within(supporting).getByText('http://198.51.100.7/')).toBeInTheDocument();
    expect(within(supporting).getByText(/Microsoft Safe Links/)).toBeInTheDocument();
    expect(within(supporting).getByText('confirm your password')).toBeInTheDocument();
    const contradictory = screen.getByRole('heading', { name: 'Evidence pointing the other way' }).closest('section');
    expect(within(contradictory).getByText('The sender looks ordinary.')).toBeInTheDocument();
    // Provider execution status and limits are visible, duplicates removed.
    expect(screen.getByText('model-x')).toBeInTheDocument();
    expect(screen.getByText('No attachments to check')).toBeInTheDocument();
    expect(screen.getAllByText(/were not independently verified/)).toHaveLength(1);
    expect(screen.getByText('FUTURE_CODE')).toBeInTheDocument();
    expect(screen.getByText('Headers are unverified.')).toBeInTheDocument();
  });

  it('describes authentication as reported, never as verified', () => {
    show({ ...base, ai_assessment: assessment });
    const section = screen.getByRole('heading', { name: 'Email authentication' }).closest('section');
    expect(within(section).getByText(/did not repeat SPF, DKIM or DMARC checks/)).toBeInTheDocument();
    expect(within(section).getByText(/Reported by a header that cannot be trusted, not independently verified/)).toBeInTheDocument();
    expect(within(section).getByText('mx.example.test')).toBeInTheDocument();
    expect(within(section).getByText('Not available')).toBeInTheDocument();
    expect(within(section).queryByText(/^independently verified/)).not.toBeInTheDocument();
  });

  it.each([
    ['quota_exceeded', 'PROVIDER_INSUFFICIENT_QUOTA', /no remaining quota/],
    ['invalid_response', 'PROVIDER_UNSUPPORTED_CLAIM', /evidence does not support/],
    ['not_configured', 'PROVIDER_NOT_CONFIGURED', /No key is saved/],
    ['timeout', 'PROVIDER_TIMEOUT', /did not answer in time/],
    ['not_requested', 'AI_CONSENT_REQUIRED', /Consent to send evidence/],
  ])('shows %s as an incomplete assessment with its reason and no verdict', (status, failure_code, text) => {
    show({ ...base, ai_execution: { status, failure_code } });
    expect(screen.getByRole('heading', { name: 'No verdict: the AI assessment was not completed' })).toBeInTheDocument();
    expect(screen.getAllByText(text).length).toBeGreaterThan(0);
    expect(screen.getByText(/must not be read as “safe”/)).toBeInTheDocument();
    for (const verdict of ['Phishing', 'Suspicious', 'Inconclusive']) expect(screen.queryByRole('heading', { name: verdict })).not.toBeInTheDocument();
    expect(screen.queryByText('Recommended actions')).not.toBeInTheDocument();
    // Evidence is still shown.
    expect(screen.getByText('The visible link text shows a different site than the destination')).toBeInTheDocument();
  });

  it('renders untrusted email content as text only', () => {
    show({ ...base, ai_assessment: assessment });
    expect(screen.getAllByText(/<img src=x onerror=alert\(1\)>/).length).toBeGreaterThan(0);
    expect(document.querySelector('img')).toBeNull();
    const links = screen.getAllByRole('link').map(a => a.getAttribute('href'));
    expect(links.every(href => href.startsWith('/'))).toBe(true);
  });

  it('prioritises actionable indicators, hides page resources, searches, filters and paginates', () => {
    const iocs = [
      ...Array.from({ length: 45 }, (_, i) => ({ type: 'url', resource_category: 'actionable_hyperlink', source: 'html_link', normalized_value: `https://example.test/${i}`, original_value: `https://wrapper.test/?url=${i}`, defanged_value: `hxxps://example[.]test/${i}`, wrapper: 'microsoft_safelinks', finding_ids: i === 0 ? ['observation-1'] : [] })),
      { type: 'domain', resource_category: 'link_host', source: 'url', normalized_value: 'example.test', defanged_value: 'example[.]test' },
      ...Array.from({ length: 30 }, (_, i) => ({ type: 'url', resource_category: i % 2 ? 'embedded_image' : 'tracking_url', source: 'html_resource', normalized_value: `https://cdn.test/${i}.png`, defanged_value: `hxxps://cdn[.]test/${i}.png` })),
    ];
    show({ ...base, report: { ...base.report, iocs } });
    expect(screen.getByText('46 of 76 indicators')).toBeInTheDocument();
    expect(screen.getAllByTestId('ioc-row')).toHaveLength(20);
    expect(screen.queryByText(/cdn\[\.\]test/)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Next page' }));
    expect(screen.getByText('hxxps://example[.]test/20')).toBeInTheDocument();
    expect(screen.getByText('Page 2 of 3')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Search indicators'), { target: { value: '/44' } });
    expect(screen.getAllByTestId('ioc-row')).toHaveLength(1);
    // Expandable details keep original and normalized forensic values.
    expect(screen.getByText('https://wrapper.test/?url=44')).toBeInTheDocument();
    expect(screen.getByText('https://example.test/44')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Search indicators'), { target: { value: '' } });
    fireEvent.change(screen.getByLabelText('Type'), { target: { value: 'domain' } });
    expect(screen.getAllByTestId('ioc-row')).toHaveLength(1);
    fireEvent.change(screen.getByLabelText('Type'), { target: { value: '' } });
    fireEvent.click(screen.getByLabelText('Show embedded resources (30)'));
    expect(screen.getByText('76 of 76 indicators')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Category'), { target: { value: 'tracking_url' } });
    expect(screen.getAllByTestId('ioc-row')).toHaveLength(15);
    // No indicator is ever an active link.
    expect(screen.getAllByRole('link').every(a => a.getAttribute('href').startsWith('/'))).toBe(true);
  });

  it('copies the defanged value by default', async () => {
    const writeText = vi.fn().mockResolvedValue();
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } });
    show({ ...base, report: { ...base.report, iocs: [{ type: 'url', resource_category: 'actionable_hyperlink', normalized_value: 'https://a.test/', defanged_value: 'hxxps://a[.]test/' }] } });
    fireEvent.click(screen.getByRole('button', { name: 'Copy defanged' }));
    expect(writeText).toHaveBeenCalledWith('hxxps://a[.]test/');
    expect(await screen.findByText('Copied')).toBeInTheDocument();
  });

  it('asks before deleting and exports in both formats', () => {
    const onDelete = vi.fn(), onExport = vi.fn();
    show({ ...base, ai_assessment: assessment }, { onDelete, onExport });
    fireEvent.click(screen.getByRole('button', { name: 'Export PDF' }));
    fireEvent.click(screen.getByRole('button', { name: 'Export JSON' }));
    expect(onExport.mock.calls).toEqual([['pdf'], ['json']]);
    fireEvent.click(screen.getByRole('button', { name: 'Delete report' }));
    expect(onDelete).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Yes, delete' }));
    expect(onDelete).toHaveBeenCalled();
  });

  it.each(['ru', 'kk'])('localizes the report in %s', async lang => {
    await i18n.changeLanguage(lang);
    show({ ...base, ai_assessment: assessment });
    expect(screen.getByText(`${lang}:Deceptive link.`)).toBeInTheDocument();
    expect(screen.getByText(`${lang}:The link leads somewhere else.`)).toBeInTheDocument();
    expect(screen.getByText(i18n.t('authenticationNotice'))).toBeInTheDocument();
    expect(screen.getByText(i18n.t('LINK_TEXT_SHOWS_DIFFERENT_HOST'))).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/Evidence supporting|Recommended actions|Not available/);
    await i18n.changeLanguage('en');
  });
});
