import { it, expect, vi, describe } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import AttachmentReputation from '../components/AttachmentReputation';
import HashLookup from '../components/HashLookup';
import i18n from '../i18n';
import '../i18n/app';

const json = (body, status = 200) => Promise.resolve(new Response(JSON.stringify(body), { status }));

describe('attachment reputation', () => {
  const report = (status, filename = 'report.pdf') => ({
    email: { attachments: [{ filename, sha256: 'abc', size: 2048 }] },
    attachment_reputation: [{ sha256: 'abc', status, ...(status === 'completed' ? { statistics: { malicious: 0, suspicious: 0, harmless: 2, undetected: 60 } } : {}) }],
  });

  it.each(['en', 'ru', 'kk'])('never presents an unknown or undetected file as safe (%s)', async lang => {
    await i18n.changeLanguage(lang);
    const { unmount } = render(<AttachmentReputation report={report('not_found')} />);
    expect(screen.getByText(`VirusTotal: ${i18n.t('not_found')}`)).toBeInTheDocument();
    expect(screen.getByText(i18n.t('vtUnknown'))).toBeInTheDocument();
    unmount();
    render(<AttachmentReputation report={report('completed')} />);
    expect(screen.getByText(`VirusTotal: ${i18n.t('vtNoDetectionsShort')}`)).toBeInTheDocument();
    expect(screen.getByText(i18n.t('vtUnknown'))).toBeInTheDocument();
    expect(screen.getByText(i18n.t('factContent'))).toBeInTheDocument();
    expect(document.querySelector('.badge.legitimate')).toBeNull();
    await i18n.changeLanguage('en');
  });

  it('shows a compact row and keeps the full hash in collapsed details', () => {
    render(<AttachmentReputation report={report('completed')} />);
    expect(screen.getByText('report.pdf')).toBeInTheDocument();
    expect(screen.getByText('2.0 KB')).toBeInTheDocument();
    const details = document.querySelector('.attachment-row details');
    expect(details.open).toBe(false);
    expect(details).toHaveTextContent('SHA-256: abc');
    expect(screen.queryByText(/Configuration profile/)).not.toBeInTheDocument();
  });

  it.each([
    ['Wi-Fi.mobileconfig', /Configuration profile/],
    ['invoice.pdf.exe', /Program or script/],
    ['report.xlsm', /can contain macros/],
    ['files.zip', /contents were not inspected/],
    ['login.html', /Web page file/],
  ])('explains the file type of %s without calling it harmful', (filename, text) => {
    render(<AttachmentReputation report={report('not_requested', filename)} />);
    expect(screen.getByText(text)).toBeInTheDocument();
    expect(screen.getByText(/file type alone does not show that a file is harmful/)).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/malicious file|is dangerous|infected/i);
    expect(screen.getByText(/Reputation was not looked up/)).toBeInTheDocument();
  });

  it('offers to complete deferred lookups only with consent', async () => {
    const updated = vi.fn();
    const fetch = vi.spyOn(window, 'fetch').mockImplementation(() => json({ id: 'a', report: report('not_found') }));
    render(<AttachmentReputation report={report('deferred_local_limit')} analysisId="a" onUpdated={updated} />);
    const button = screen.getByRole('button', { name: 'Check the remaining hashes now' });
    expect(button).toBeDisabled();
    fireEvent.click(screen.getByRole('checkbox'));
    fireEvent.click(button);
    await waitFor(() => expect(updated).toHaveBeenCalled());
    expect(fetch.mock.calls[0][0]).toBe('/api/v1/analyses/a/virustotal');
    expect(JSON.parse(fetch.mock.calls[0][1].body)).toEqual({ virustotal_consent: true });
  });

  it('shows no recheck for lookups that were never requested and nothing for no attachments', () => {
    const { unmount } = render(<AttachmentReputation report={report('not_requested')} analysisId="a" onUpdated={vi.fn()} />);
    expect(screen.queryByRole('button', { name: 'Check the remaining hashes now' })).not.toBeInTheDocument();
    unmount();
    render(<AttachmentReputation report={{ email: { attachments: [] } }} />);
    expect(screen.getByText('This email has no attachments.')).toBeInTheDocument();
  });
});

describe('manual hash lookup', () => {
  const HASH = 'ab'.repeat(32);
  const open = ready => render(<MemoryRouter><HashLookup ready={ready} /></MemoryRouter>);
  const check = () => fireEvent.click(screen.getByRole('button', { name: 'Check reputation' }));
  const type = value => fireEvent.change(screen.getByLabelText('SHA-256 hash'), { target: { value } });

  it('needs a configured provider and makes no request by itself', () => {
    const fetch = vi.spyOn(window, 'fetch');
    open(false);
    expect(screen.getByText(/Add and enable a VirusTotal key/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Check reputation' })).not.toBeInTheDocument();
    expect(fetch).not.toHaveBeenCalled();
  });

  it('validates the hash before calling the backend', () => {
    const fetch = vi.spyOn(window, 'fetch');
    open(true);
    expect(screen.getByRole('button', { name: 'Check reputation' })).toBeDisabled();
    type('abc123');
    check();
    expect(screen.getByRole('alert')).toHaveTextContent('exactly 64 characters');
    expect(screen.getByRole('alert')).toHaveTextContent('You entered 6');
    type('z'.repeat(64));
    check();
    expect(screen.getByRole('alert')).toHaveTextContent('only digits 0–9 and letters a–f');
    expect(screen.getByLabelText('SHA-256 hash')).toHaveAttribute('aria-invalid', 'true');
    expect(fetch).not.toHaveBeenCalled();
  });

  it('looks up once per click and qualifies a report without detections', async () => {
    const fetch = vi.spyOn(window, 'fetch').mockImplementation(() => json({ result: { sha256: HASH, status: 'completed', statistics: { malicious: 0, suspicious: 0, harmless: 3, undetected: 61 }, last_analysis_at: '2026-01-05T10:00:00Z', checked_at: '2026-03-03T09:00:00Z' } }));
    open(true);
    type(`  ${HASH.toUpperCase()} `);
    check();
    expect(await screen.findByText('VirusTotal has a report for this file')).toBeInTheDocument();
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch.mock.calls[0][0]).toBe('/api/v1/reputation/virustotal');
    expect(JSON.parse(fetch.mock.calls[0][1].body)).toEqual({ sha256: HASH });
    expect(fetch.mock.calls[0][1].method).toBe('POST');
    expect(fetch.mock.calls[0][1].headers).toHaveProperty('X-CSRF-Token');
    expect(screen.getByText('VirusTotal: no detections reported')).toBeInTheDocument();
    expect(screen.getByText('Undetected').nextSibling).toHaveTextContent('61');
    expect(screen.getByText(/Last analysed by the provider/)).toBeInTheDocument();
    expect(screen.getByText(/not a scan of file contents/)).toBeInTheDocument();
    expect(screen.getByText(/Zero detections do not prove safety/)).toBeInTheDocument();
    expect(document.querySelector('.badge.legitimate')).toBeNull();
  });

  it.each([
    [{ status: 'completed', statistics: { malicious: 41, suspicious: 2, harmless: 0, undetected: 20 }, engines: [{ name: 'EngineA', category: 'malicious', result: 'Trojan.Test' }] }, 'VirusTotal has a report for this file', 'VirusTotal: 43 detections'],
    [{ status: 'not_found' }, 'VirusTotal has no report for this hash', 'says nothing about whether the file is safe'],
    [{ status: 'rate_limited' }, 'The lookup did not return a result', 'Request limit reached at the provider'],
    [{ status: 'deferred_local_limit' }, 'The lookup did not return a result', 'request allowance reached'],
    [{ status: 'authentication_failed' }, 'The lookup did not return a result', 'Key rejected'],
    [{ status: 'timeout' }, 'The lookup did not return a result', 'Timed out'],
  ])('reports %o', async (result, heading, detail) => {
    vi.spyOn(window, 'fetch').mockImplementation(() => json({ result: { sha256: HASH, ...result } }));
    open(true);
    type(HASH);
    check();
    const box = await screen.findByRole('status');
    expect(box).toHaveTextContent(heading);
    expect(box).toHaveTextContent(detail);
    expect(box).toHaveTextContent('Zero detections do not prove safety');
  });

  it('explains backend errors', async () => {
    vi.spyOn(window, 'fetch').mockImplementation(() => json({ error: { code: 'PROVIDER_DISABLED' } }, 409));
    open(true);
    type(HASH);
    check();
    expect(await screen.findByRole('alert')).toHaveTextContent('switched off');
  });

  it.each(['ru', 'kk'])('is translated (%s)', async lang => {
    await i18n.changeLanguage(lang);
    open(true);
    expect(screen.getByText(i18n.t('hashLookupTitle'))).toBeInTheDocument();
    expect(screen.getByRole('button', { name: i18n.t('hashCheck') })).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/Check reputation|SHA-256 hash/);
    await i18n.changeLanguage('en');
  });
});
