import { it, expect, vi, describe, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import Analyzer from '../pages/Analyzer';
import Dashboard, { History } from '../pages/Dashboard';
import Details from '../pages/Details';
import { api, setCSRF } from '../services/api';
import i18n from '../i18n';
import { messageKeys, untranslated } from '../i18n/app';

vi.mock('recharts', () => ({
  ResponsiveContainer: ({ children }) => <div>{children}</div>,
  BarChart: ({ data }) => <ul>{data.map(d => <li key={d.name}>{d.name}: {d.count}</li>)}</ul>,
  Bar: () => null, XAxis: () => null, YAxis: () => null, Tooltip: () => null,
}));

const json = (body, status = 200) => Promise.resolve(new Response(JSON.stringify(body), { status }));
const configured = extra => ({ has_credential: true, enabled: true, model: 'model-x', ...extra });

function mockBackend({ openai = { has_credential: false, enabled: false }, vt = { has_credential: false, enabled: false }, analyse }) {
  return vi.spyOn(window, 'fetch').mockImplementation((url, options = {}) => {
    if (options.method === 'POST' && url.endsWith('/analyses')) return analyse ? analyse(options) : json({ id: 'new-id' }, 201);
    if (url.includes('/settings/ai-provider')) return json(openai);
    if (url.includes('/settings/virustotal')) return json(vt);
    return json({ max_email_size: 10485760 });
  });
}
const analyzer = () => render(<MemoryRouter initialEntries={['/analyze']}><Routes><Route path="/analyze" element={<Analyzer />} /><Route path="/analyses/:id" element={<p>report opened</p>} /><Route path="/settings" element={<p>settings</p>} /></Routes></MemoryRouter>);
const posted = fetch => fetch.mock.calls.find(([url, o]) => o?.method === 'POST' && url.endsWith('/analyses'));

beforeEach(() => setCSRF('csrf'));

describe('email analyzer', () => {
  it('offers exactly two input modes: upload and paste', async () => {
    mockBackend({});
    analyzer();
    expect(screen.getAllByRole('tab').map(t => t.textContent)).toEqual(['Upload email', 'Paste email']);
    expect(document.body.textContent).not.toMatch(/demo|sample/i);
  });

  it('explains missing providers, disables consent and links to Settings', async () => {
    mockBackend({});
    analyzer();
    expect(await screen.findAllByText('Not configured')).toHaveLength(2);
    expect(screen.getByLabelText(/Send the extracted evidence/)).toBeDisabled();
    expect(screen.getByLabelText(/Look up the SHA-256 hashes/)).toBeDisabled();
    expect(screen.getByText(/no verdict/)).toBeInTheDocument();
    expect(screen.getAllByRole('link', { name: 'Open Settings' })).toHaveLength(3);
  });

  it('uploads an EML with separate, explicit consents and opens the stored report', async () => {
    const fetch = mockBackend({ openai: configured(), vt: configured({ model: '' }) });
    analyzer();
    expect(await screen.findByText('model-x')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Upload email'), { target: { files: [new File(['From: a@example.test\r\n\r\nx'], 'mail.eml')] } });
    // Consent is never pre-selected.
    expect(screen.getByLabelText(/Send the extracted evidence/)).not.toBeChecked();
    fireEvent.click(screen.getByLabelText(/Send the extracted evidence/));
    fireEvent.click(screen.getByRole('button', { name: 'Analyze email' }));
    expect(await screen.findByText('report opened')).toBeInTheDocument();
    const body = posted(fetch)[1].body;
    expect(body.get('file').name).toBe('mail.eml');
    expect(body.get('external_processing_consent')).toBe('true');
    expect(body.get('virustotal_consent')).toBe('false');
  });

  it('submits pasted text without consent by default', async () => {
    const fetch = mockBackend({ openai: configured() });
    analyzer();
    fireEvent.click(screen.getByRole('tab', { name: 'Paste email' }));
    fireEvent.change(screen.getByLabelText('Email content'), { target: { value: 'Investigate this message' } });
    fireEvent.change(screen.getByLabelText('Sender (optional)'), { target: { value: 'a@example.test' } });
    fireEvent.click(screen.getByRole('button', { name: 'Analyze email' }));
    await screen.findByText('report opened');
    expect(JSON.parse(posted(fetch)[1].body)).toEqual({ source_type: 'paste', text: 'Investigate this message', sender: 'a@example.test', subject: '', external_processing_consent: false, virustotal_consent: false });
  });

  it('shows honest progress while waiting and can be cancelled', async () => {
    mockBackend({ openai: configured(), analyse: options => new Promise((_, reject) => options.signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')))) });
    analyzer();
    await screen.findByText('model-x');
    fireEvent.click(screen.getByRole('tab', { name: 'Paste email' }));
    fireEvent.change(screen.getByLabelText('Email content'), { target: { value: 'text' } });
    fireEvent.click(screen.getByLabelText(/Send the extracted evidence/));
    fireEvent.click(screen.getByRole('button', { name: 'Analyze email' }));
    const progress = await screen.findByRole('status');
    expect(progress).toHaveAttribute('aria-busy', 'true');
    expect(progress).toHaveTextContent('Analysing the email');
    // All five activities are listed for orientation; none is marked done and
    // there is no percentage, because the page cannot observe the server.
    expect([...progress.querySelectorAll('.progress-steps li')].map(li => li.textContent)).toEqual([
      'Preparing the email', 'Extracting technical evidence', 'Checking attachment hashes at VirusTotal — not requested', 'Waiting for the AI assessment', 'Preparing the results',
    ]);
    expect(progress).toHaveTextContent('the page cannot see which one is running');
    expect(progress.textContent).not.toMatch(/\d+\s?%|done|completed|✓/i);
    expect(progress.querySelector('progress, [role=progressbar]')).toBeNull();
    expect(progress).toHaveTextContent('Elapsed: 0 s');
    // No second submission is possible while the request is running.
    expect(screen.queryByRole('button', { name: 'Analyze email' })).not.toBeInTheDocument();
    expect(screen.getByLabelText('Email content')).toBeDisabled();
    expect(screen.queryByText('report opened')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(await screen.findByRole('button', { name: 'Analyze email' })).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.queryByRole('status', { busy: true })).not.toBeInTheDocument();
  });

  it('leaves the loading state and reports a timeout or provider failure cleanly', async () => {
    let attempt = 0;
    const fetch = mockBackend({ openai: configured(), analyse: () => (++attempt === 1 ? Promise.reject(new DOMException('timeout', 'AbortError')) : json({ error: { code: 'REQUEST_TIMEOUT' } }, 504)) });
    analyzer();
    await screen.findByText('model-x');
    fireEvent.click(screen.getByRole('tab', { name: 'Paste email' }));
    fireEvent.change(screen.getByLabelText('Email content'), { target: { value: 'text' } });
    fireEvent.click(screen.getByRole('button', { name: 'Analyze email' }));
    // An aborted request that the user did not cancel is not silently ignored twice.
    await screen.findByRole('button', { name: 'Analyze email' });
    fireEvent.change(screen.getByLabelText('Email content'), { target: { value: 'text' } });
    fireEvent.click(screen.getByRole('button', { name: 'Analyze email' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('took too long');
    expect(screen.getByRole('button', { name: 'Analyze email' })).toBeEnabled();
    expect(fetch.mock.calls.filter(([url, o]) => o?.method === 'POST' && url.endsWith('/analyses'))).toHaveLength(2);
  });

  it.each(['eml', 'msg'])('shows the selected %s file as ready and supports replace and remove', async extension => {
    const fetch = mockBackend({});
    analyzer();
    const picker = screen.getByLabelText('Upload email');
    expect(screen.getByText('No file selected')).toBeInTheDocument();
    expect(screen.getByText('Choose file')).toBeInTheDocument();
    fireEvent.change(picker, { target: { files: [new File(['x'.repeat(3072)], `first.${extension}`)] } });
    const selected = screen.getByRole('status');
    expect(selected).toHaveTextContent(`first.${extension}`);
    expect(selected).toHaveTextContent('3.0 KB');
    expect(selected).toHaveTextContent('Ready to analyze');
    expect(screen.queryByText('No file selected')).not.toBeInTheDocument();
    // Replace through the picker.
    expect(screen.getByText('Choose another file')).toBeInTheDocument();
    fireEvent.change(picker, { target: { files: [new File(['y'], `second.${extension}`)] } });
    expect(screen.getByRole('status')).toHaveTextContent(`second.${extension}`);
    expect(screen.queryByText(`first.${extension}`)).not.toBeInTheDocument();
    // Switching to Paste and back keeps what the page says is selected.
    fireEvent.click(screen.getByRole('tab', { name: 'Paste email' }));
    fireEvent.click(screen.getByRole('tab', { name: 'Upload email' }));
    expect(screen.getByRole('status')).toHaveTextContent(`second.${extension}`);
    // An invalid replacement clears the selection instead of keeping a stale one.
    fireEvent.change(screen.getByLabelText('Upload email'), { target: { files: [new File(['z'], 'notes.txt')] } });
    expect(screen.getByRole('alert')).toHaveTextContent('Choose an EML or MSG');
    expect(screen.getByText('No file selected')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Upload email'), { target: { files: [new File(['y'], `third.${extension}`)] } });
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    // Remove.
    fireEvent.click(screen.getByRole('button', { name: 'Remove file' }));
    expect(screen.getByText('No file selected')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Analyze email' }));
    expect(screen.getByRole('alert')).toHaveTextContent('Choose an EML or MSG');
    expect(posted(fetch)).toBeUndefined();
  });

  it('shows a dropped file exactly like a browsed one and uploads it', async () => {
    const fetch = mockBackend({});
    analyzer();
    const zone = document.querySelector('.dropzone');
    fireEvent.dragOver(zone);
    expect(zone.className).toContain('dragging');
    fireEvent.drop(zone, { dataTransfer: { files: [new File(['From: a@example.test\r\n\r\nx'], 'dropped.eml')] } });
    expect(zone.className).not.toContain('dragging');
    expect(screen.getByRole('status')).toHaveTextContent('dropped.eml');
    expect(screen.getByRole('status')).toHaveTextContent('Ready to analyze');
    fireEvent.click(screen.getByRole('button', { name: 'Analyze email' }));
    expect(await screen.findByText('report opened')).toBeInTheDocument();
    expect(posted(fetch)[1].body.get('file').name).toBe('dropped.eml');
  });

  it.each([
    ['INVALID_EMAIL', 400, /not a readable email/],
    ['UNAUTHENTICATED', 401, /session expired/],
    ['DATABASE_SCHEMA_OUTDATED', 503, /setup\.ps1/],
    ['SERVER_BUSY', 503, /too many requests/],
  ])('reports backend error %s and does not open a report', async (code, status, text) => {
    mockBackend({ analyse: () => json({ error: { code } }, status) });
    analyzer();
    fireEvent.click(screen.getByRole('tab', { name: 'Paste email' }));
    fireEvent.change(screen.getByLabelText('Email content'), { target: { value: 'text' } });
    fireEvent.click(screen.getByRole('button', { name: 'Analyze email' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(text);
    expect(screen.queryByText('report opened')).not.toBeInTheDocument();
  });

  it('rejects wrong and oversized files before uploading', async () => {
    const fetch = mockBackend({});
    analyzer();
    const input = screen.getByLabelText('Upload email');
    fireEvent.change(input, { target: { files: [new File(['x'], 'tool.exe')] } });
    expect(screen.getByRole('alert')).toHaveTextContent('Choose an EML or MSG');
    const big = new File(['x'], 'big.eml');
    Object.defineProperty(big, 'size', { value: 11 * 1024 * 1024 });
    fireEvent.change(input, { target: { files: [big] } });
    expect(screen.getByRole('alert')).toHaveTextContent('larger than 10 MB');
    fireEvent.click(screen.getByRole('button', { name: 'Analyze email' }));
    expect(posted(fetch)).toBeUndefined();
  });
});

const item = (id, extra) => ({ id, created_at: '2026-03-03T09:00:00Z', status: 'complete', ai_execution: { status: 'completed' }, report: { scoring_version: '3.0.0', verdict: 'phishing', email: { subject: `Subject ${id}`, sender: 's@example.test', source_type: 'eml' } }, ...extra });
const rows = [
  item('done', { ai_assessment: { proposed_verdict: 'phishing', severity: 'high' } }),
  item('failed', { status: 'partial', ai_execution: { status: 'quota_exceeded' }, report: { scoring_version: '3.0.0', verdict: 'inconclusive', email: { subject: 'Subject failed', sender: '', source_type: 'paste' } } }),
  item('old', { report: { scoring_version: '2.0.0', verdict: 'phishing', risk_score: 85, email: { subject: 'Subject old', sender: 'o@example.test', source_type: 'eml' } } }),
];

describe('dashboard and history', () => {
  it('shows accurate statistics and separates incomplete and historical reports', async () => {
    vi.spyOn(window, 'fetch').mockImplementation(() => json({ total_analyses: 9, completed_count: 5, incomplete_count: 3, legacy_count: 1, phishing_count: 2, suspicious_count: 1, legitimate_count: 2, inconclusive_count: 0, verdict_distribution: { phishing: 2, suspicious: 1, legitimate: 2, inconclusive: 0 }, severity_distribution: { none: 2, high: 2, medium: 1 }, activity_series: [{ date: '2026-03-03', count: 9 }], common_attack_types: [{ name: 'credential_phishing', count: 2 }], recent_analyses: rows }));
    render(<MemoryRouter><Dashboard /></MemoryRouter>);
    for (const [label, value] of [['All analyses', '9'], ['With a verdict', '5'], ['Without a verdict', '3'], ['Historical (old detector)', '1']]) {
      expect((await screen.findByText(label)).parentElement).toHaveTextContent(value);
    }
    expect(screen.getByText('Credential phishing: 2')).toBeInTheDocument();
    expect(screen.getByText(/counted separately/)).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/MITRE|ATT&CK|T1566|demo/i);
    // A failed analysis is not shown as "inconclusive" and an old score is not a verdict.
    expect(screen.getByText('No verdict')).toBeInTheDocument();
    expect(screen.getByText('Quota exhausted')).toBeInTheDocument();
    expect(screen.getByText('Historical')).toBeInTheDocument();
    expect(document.body.textContent).not.toContain('85');
  });

  it('passes search, verdict, result and date filters to the backend and paginates', async () => {
    const fetch = vi.spyOn(window, 'fetch').mockImplementation(() => json({ items: rows, total: 45, page: 1, page_size: 20 }));
    render(<MemoryRouter><History /></MemoryRouter>);
    await screen.findByText('Subject done');
    fireEvent.change(screen.getByLabelText('Search'), { target: { value: 'invoice' } });
    fireEvent.change(screen.getByLabelText('Verdict'), { target: { value: 'phishing' } });
    fireEvent.change(screen.getByLabelText('Result'), { target: { value: 'partial' } });
    await waitFor(() => expect(fetch.mock.calls.some(([url]) => url.includes('search=invoice') && url.includes('verdict=phishing') && url.includes('status=partial'))).toBe(true));
    expect(await screen.findByText(/Page 1 of 3/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    await waitFor(() => expect(fetch.mock.calls.some(([url]) => url.includes('page=2'))).toBe(true));
    expect(screen.getByRole('link', { name: 'Subject old' })).toHaveAttribute('href', '/analyses/old');
  });

  it('opens a historical report with a clear label and no probability', async () => {
    vi.spyOn(window, 'fetch').mockImplementation(() => json({ id: 'old', created_at: '2026-01-01T00:00:00Z', explanations: { en: 'Old explanation' }, recommendations: { en: 'Old advice' }, report: { scoring_version: '2.0.0', verdict: 'phishing', risk_level: 'high', risk_score: 75, email: { subject: 'Old', sender: 'o@example.test', attachments: [] }, iocs: [{ type: 'url', value: 'https://suspicious.invalid', defanged_value: 'hxxps://suspicious[.]invalid', source: 'body' }], mitre_mappings: [{ technique_id: 'T1566.002' }], indicators: [], limitations: ['HEURISTIC_NOT_PROBABILITY'] } }));
    render(<MemoryRouter initialEntries={['/analyses/old']}><Routes><Route path="/analyses/:id" element={<Details />} /></Routes></MemoryRouter>);
    expect(await screen.findByText('Historical report from the earlier rule-weight detector')).toBeInTheDocument();
    expect(screen.getByText(/not a probability and is not comparable/)).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/T1566|MITRE|\/ 100|75%/);
    expect(screen.queryByRole('link', { name: /suspicious/ })).not.toBeInTheDocument();
  });
});

describe('localization and API errors', () => {
  it('has English, Russian and Kazakh text for every interface key', () => {
    expect(untranslated).toEqual([]);
    for (const lang of ['ru', 'kk']) {
      const same = messageKeys.filter(k => i18n.getResource(lang, 'translation', k) === i18n.getResource('en', 'translation', k) && /[a-z]{4,} [a-z]{4,}/.test(i18n.getResource('en', 'translation', k)));
      // Product names are identical in every language; ordinary sentences are not.
      expect(same.filter(k => !['microsoft_safelinks', 'proofpoint_urldefense', 'barracuda_linkprotect'].includes(k))).toEqual([]);
    }
  });

  it.each([
    [new Response('', { status: 500 }), 'BACKEND_UNAVAILABLE'],
    [new Response('<html>Bad gateway</html>', { status: 502 }), 'BACKEND_UNAVAILABLE'],
    [new Response('', { status: 504 }), 'REQUEST_TIMEOUT'],
    [new Response('too large', { status: 413 }), 'EMAIL_TOO_LARGE'],
    [new Response(JSON.stringify({ error: { code: 'INTERNAL_ERROR', request_id: 'r-9' } }), { status: 500 }), 'INTERNAL_ERROR'],
    [new Response('not json', { status: 200 }), 'UNEXPECTED_RESPONSE'],
  ])('maps a non-contract response to a specific code (%#)', async (response, code) => {
    vi.spyOn(window, 'fetch').mockResolvedValue(response);
    await expect(api('/settings/ai-provider', { method: 'POST', body: {} })).rejects.toMatchObject({ code });
    expect(i18n.exists(code)).toBe(true);
  });

  it('keeps the request ID of a server error and distinguishes timeout from offline', async () => {
    vi.spyOn(window, 'fetch').mockResolvedValue(new Response(JSON.stringify({ error: { code: 'INTERNAL_ERROR', request_id: 'r-9' } }), { status: 500 }));
    await expect(api('/x')).rejects.toMatchObject({ requestId: 'r-9', status: 500 });
    vi.spyOn(window, 'fetch').mockImplementation((_, o) => new Promise((_, reject) => o.signal.addEventListener('abort', () => reject(new DOMException('a', 'AbortError')))));
    await expect(api('/x', { timeout: 10 })).rejects.toMatchObject({ code: 'TIMEOUT' });
    vi.spyOn(window, 'fetch').mockRejectedValue(new TypeError('failed to fetch'));
    await expect(api('/x')).rejects.toMatchObject({ code: 'NETWORK' });
  });
});
