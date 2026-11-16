import { it, expect, vi, describe } from 'vitest';
import { render, screen, fireEvent, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import EvidenceReport from '../components/EvidenceReport';
import i18n from '../i18n';
import '../i18n/app';

const loc = s => ({ en: s, ru: `ru:${s}`, kk: `kk:${s}` });
const SHA = 'a'.repeat(64);
const longUrl = `http://198.51.100.7/owa/login.php?token=${'x'.repeat(300)}`;
const base = {
  id: 'a1', created_at: '2026-03-03T09:00:00Z',
  ai_execution: { status: 'completed', model: 'model-x', duration_ms: 2300 },
  report: {
    scoring_version: '3.0.0', virustotal_status: 'completed',
    email: {
      subject: 'Verdächtige DEX-Aktivität erkannt', subject_raw: '=?utf-8?Q?Verd=C3=A4chtige?=',
      sender: 'Noreply@ledger.example | (ledger.example) <web3@ledgermail.onmicrosoft.example>',
      sender_name: 'Noreply@ledger.example | (ledger.example)', sender_address: 'web3@ledgermail.onmicrosoft.example',
      reply_to: '', recipients: [''], source_type: 'eml', filename: 'mail.eml', file_sha256: 'f'.repeat(64), message_id: '<m1@example.test>',
      attachments: [{ filename: 'Security.mobileconfig', size: 4096, declared_mime: 'application/octet-stream', detected_mime: 'text/xml', sha256: SHA }],
    },
    attachment_reputation: [{ sha256: SHA, status: 'not_found', source: 'VirusTotal API v3' }],
    links: [
      { visible_text: 'https://account.microsoft.com', destination: longUrl, original_value: longUrl, text_shows_different_host: true, kind: 'html_link' },
      { visible_text: 'Help', destination: 'https://help.example.test/a', original_value: 'https://help.example.test/a', kind: 'html_link', wrapper: 'microsoft_safelinks' },
    ],
    iocs: [{ type: 'url', resource_category: 'actionable_hyperlink', source: 'html_link', normalized_value: 'https://a.test/', original_value: 'https://a.test/', defanged_value: 'hxxps://a[.]test/' }],
    indicators: [{ id: 'observation-1', rule_id: 'LINK_TEXT_SHOWS_DIFFERENT_HOST', evidence: 'account.microsoft.com -> 198.51.100.7' }],
    evidence: [
      { id: 'sender-1', source: 'from', value: 'web3@ledgermail.onmicrosoft.example' },
      { id: 'observation-1', source: 'observation:LINK_TEXT_SHOWS_DIFFERENT_HOST', value: 'account.microsoft.com -> 198.51.100.7' },
      { id: 'received-1', source: 'Received', value: 'from a.test by b.test' },
    ],
    authentication: [
      { mechanism: 'spf', reported_result: 'pass', reporting_server: '', evidence_source: 'Authentication-Results', trust_status: 'untrusted_reported', verification_status: 'unable_to_verify', alignment_information: 'reported: smtp.mailfrom=ledgermail.onmicrosoft.example', limitations: ['UPLOADED_HEADERS_CAN_BE_FORGED'], raw_value: 'spf=pass smtp.mailfrom=ledgermail.onmicrosoft.example; dkim=none; dmarc=bestguesspass' },
      { mechanism: 'dkim', reported_result: 'none', reporting_server: '', evidence_source: 'Authentication-Results', trust_status: 'untrusted_reported', verification_status: 'unable_to_verify', alignment_information: 'not_reported', limitations: ['UPLOADED_HEADERS_CAN_BE_FORGED'], raw_value: 'spf=pass smtp.mailfrom=ledgermail.onmicrosoft.example; dkim=none; dmarc=bestguesspass' },
      { mechanism: 'dmarc', reported_result: 'bestguesspass', reporting_server: 'mx.example.test', evidence_source: 'Authentication-Results', trust_status: 'untrusted_reported', verification_status: 'unable_to_verify', alignment_information: 'not_reported', limitations: ['UPLOADED_HEADERS_CAN_BE_FORGED', 'DMARC_BESTGUESS_IS_NOT_A_POLICY_PASS'] },
    ],
    limitations: ['AUTHENTICATION_NOT_INDEPENDENTLY_VERIFIED', 'AUTHENTICATION_NOT_INDEPENDENTLY_VERIFIED', 'FUTURE_CODE'],
  },
};
const assessment = {
  proposed_verdict: 'phishing', severity: 'high', confidence: 'medium',
  evidence_findings: [
    ...['one', 'two', 'three', 'four', 'five'].map(n => ({ stance: 'supporting', evidence_ids: ['observation-1'], explanation: loc(`Reason ${n}.`) })),
    { stance: 'contradictory', evidence_ids: ['sender-1'], explanation: loc('The address is an ordinary cloud address.') },
  ],
  contextual_findings: [
    { type: 'credential_theft', quote: 'Bitte bestätigen Sie Ihre Wallet', reason: loc('Asks for wallet confirmation.') },
    { type: 'coercion', quote: 'innerhalb von 24 Stunden', reason: loc('Sets a deadline.') },
    { type: 'benign_context', quote: 'Mit freundlichen Grüßen', reason: loc('Polite closing.') },
  ],
  uncertainty_notes: [loc('Headers are unverified.')],
  explanations: loc('Deceptive link and impersonated brand.'),
  recommendations: loc('Do not sign in.\nDelete the email.\nReport it to IT.\nChange the password if you entered it.'),
};
const show = (analysis, props = {}) => render(<MemoryRouter><EvidenceReport analysis={analysis} onExport={vi.fn()} onDelete={vi.fn()} onUpdated={vi.fn()} {...props} /></MemoryRouter>);
const openTechnical = () => fireEvent.click(screen.getByRole('button', { name: 'Show technical details' }));
const sectionOf = title => screen.getByText(title).closest('details');

describe('simple view', () => {
  it('leads with verdict, severity, confidence, summary, a few reasons, key items and actions', () => {
    show({ ...base, ai_assessment: assessment });
    expect(screen.getByRole('heading', { name: 'Phishing' })).toBeInTheDocument();
    expect(screen.getByText('Severity: High (level 3 of 4)')).toBeInTheDocument();
    expect(screen.getByText('Model confidence:')).toHaveTextContent('Medium');
    expect(screen.getByText('Deceptive link and impersonated brand.')).toBeInTheDocument();
    // At most four reasons plus one quote; the rest waits in Technical details.
    const why = screen.getByRole('heading', { name: 'Main reasons' }).closest('section');
    expect(within(why).getAllByRole('listitem')).toHaveLength(5);
    expect(within(why).queryByText('Reason five.')).not.toBeInTheDocument();
    expect(within(why).getByText(/Bitte bestätigen Sie Ihre Wallet/)).toBeInTheDocument();
    expect(within(why).getByText(/All evidence with references/)).toBeInTheDocument();
    // Actions: three shown, the rest expandable.
    const actions = screen.getByRole('heading', { name: 'What to do' }).closest('section');
    expect(within(actions).getAllByRole('listitem')).toHaveLength(3);
    fireEvent.click(within(actions).getByRole('button', { name: 'Show all' }));
    expect(within(actions).getAllByRole('listitem')).toHaveLength(4);
  });

  it('keeps identifiers, hashes and technical sections out of the simple view', () => {
    show({ ...base, ai_assessment: assessment });
    const text = document.body.textContent;
    expect(text).not.toContain(SHA);
    expect(text).not.toContain('observation-1');
    expect(text).not.toMatch(/SPF|DKIM|IOC|Indicator explorer|How this analysis ran|model-x/);
    expect(screen.queryByText('Evidence pointing the other way')).not.toBeInTheDocument();
    expect(text).not.toContain('The address is an ordinary cloud address.');
    expect(text).not.toMatch(/\/ 100|\d+\s?%/);
    expect(screen.getByRole('button', { name: 'Show technical details' })).toHaveAttribute('aria-expanded', 'false');
  });

  it('shows a plain verdict icon with no ring, gauge or number around it', () => {
    show({ ...base, ai_assessment: assessment });
    const icon = screen.getByRole('img', { name: 'Verdict: Phishing. Severity: High.' });
    expect(icon.className).toContain('ring-phishing');
    expect(icon.textContent).toBe('');
    // Exactly one graphic, the icon itself: no decorative circle around it.
    expect(icon.querySelectorAll('svg')).toHaveLength(1);
    expect(icon.querySelector('.ring-track, .ring-line')).toBeNull();
    expect(icon.querySelector('[stroke-dasharray], [stroke-dashoffset], progress, [role=progressbar]')).toBeNull();
    // Verdict text, severity and confidence stay next to it.
    const head = icon.closest('.verdict-head');
    expect(head).toHaveTextContent('Phishing');
    expect(head).toHaveTextContent('Severity: High (level 3 of 4)');
    expect(head).toHaveTextContent('Model confidence: Medium');
  });

  it.each(['phishing', 'suspicious', 'legitimate', 'inconclusive'])('uses the same ring-free icon for %s', verdict => {
    show({ ...base, ai_assessment: { ...assessment, proposed_verdict: verdict } });
    const icon = document.querySelector('.verdict-ring');
    expect(icon.className).toContain(`ring-${verdict}`);
    expect(icon.querySelectorAll('svg')).toHaveLength(1);
    expect(icon.querySelector('.ring-track, .ring-line')).toBeNull();
  });

  it('labels subject, display name and sending address separately and hides empty fields', () => {
    show({ ...base, ai_assessment: assessment });
    const email = screen.getByRole('heading', { name: 'Email' }).closest('section');
    const rows = [...email.querySelectorAll('dl > div')].map(d => [d.querySelector('dt').textContent, d.querySelector('dd').textContent]);
    expect(rows).toEqual([
      ['Subject', 'Verdächtige DEX-Aktivität erkannt'],
      ['Display name', 'Noreply@ledger.example | (ledger.example)'],
      ['From address', 'web3@ledgermail.onmicrosoft.example'],
    ]);
    expect(within(email).getByText(/free text chosen by the sender/)).toBeInTheDocument();
  });

  it('never prints empty separators for pasted text without metadata', () => {
    const pasted = { ...base, report: { ...base.report, email: { subject: '', sender: '', source_type: 'paste', filename: '.', attachments: [] }, links: [], attachment_reputation: [], authentication: [], evidence: [] } };
    show({ ...pasted, ai_assessment: { ...assessment, proposed_verdict: 'legitimate', severity: 'none', contextual_findings: [] } });
    expect(screen.getAllByText('No sender information was provided.').length).toBeGreaterThan(0);
    expect(screen.queryByText('Important links and attachments')).not.toBeInTheDocument();
    openTechnical();
    fireEvent.click(screen.getByText('How this analysis ran'));
    expect(sectionOf('How this analysis ran').textContent).toContain('Pasted text');
    expect(document.body.textContent).not.toMatch(/Pasted text\s*·|·\s*\.(\s|$)/);
    expect(screen.queryByText('Email headers and identifiers')).not.toBeInTheDocument();
  });

  it('shows important links defanged, shortened and never clickable, with compact attachments', () => {
    show({ ...base, ai_assessment: assessment });
    const items = screen.getByRole('heading', { name: 'Important links and attachments' }).closest('section');
    expect(within(items).getByText('“https://account.microsoft.com”')).toBeInTheDocument();
    const destination = within(items).getByTitle(/hxxp:\/\/198\[\.\]51/);
    expect(destination.textContent.length).toBeLessThan(100);
    expect(destination.textContent).toMatch(/^hxxp:\/\/198\[\.\]51\[\.\]100\[\.\]7/);
    expect(within(items).getByText(/different site than the real destination/)).toBeInTheDocument();
    expect(within(items).getByText(/unwrapped from Microsoft Safe Links/)).toBeInTheDocument();
    expect(within(items).getByText('Security.mobileconfig')).toBeInTheDocument();
    expect(within(items).getByText('4.0 KB')).toBeInTheDocument();
    expect(within(items).getByText(/Configuration profile: installing it can change device settings/)).toBeInTheDocument();
    expect(within(items).getByText('VirusTotal: Hash unknown to VirusTotal')).toBeInTheDocument();
    expect(document.querySelector('.badge.legitimate')).toBeNull();
    expect(screen.getAllByRole('link').every(a => a.getAttribute('href').startsWith('/'))).toBe(true);
  });

  it('qualifies a legitimate verdict without turning it into a warning', () => {
    show({ ...base, ai_assessment: { ...assessment, proposed_verdict: 'legitimate', severity: 'none', confidence: 'medium' } });
    expect(screen.getByRole('heading', { name: /Legitimate/ })).toBeInTheDocument();
    expect(screen.getByText(/appears legitimate based on the available evidence/)).toBeInTheDocument();
    expect(screen.getByText(/have not been independently verified/)).toBeInTheDocument();
    expect(screen.getByText('Severity: no impact expected')).toBeInTheDocument();
    // For a legitimate verdict the supporting quote is the benign one.
    const why = screen.getByRole('heading', { name: 'Main reasons' }).closest('section');
    expect(within(why).getByText(/Mit freundlichen Grüßen/)).toBeInTheDocument();
    expect(within(why).queryByText(/Bitte bestätigen/)).not.toBeInTheDocument();
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
    expect(screen.getByRole('img', { name: 'No verdict: the AI assessment was not completed' })).toBeInTheDocument();
    expect(screen.getAllByText(text).length).toBeGreaterThan(0);
    expect(screen.getByText(/must not be read as “safe”/)).toBeInTheDocument();
    for (const verdict of ['Phishing', 'Suspicious', 'Inconclusive']) expect(screen.queryByRole('heading', { name: verdict })).not.toBeInTheDocument();
    expect(screen.queryByText('What to do')).not.toBeInTheDocument();
    expect(screen.queryByText('Main reasons')).not.toBeInTheDocument();
    // Evidence is still available.
    openTechnical();
    expect(screen.getByText('Technical observations')).toBeInTheDocument();
  });
});

describe('technical details', () => {
  it('opens on demand with every technical section collapsed', () => {
    show({ ...base, ai_assessment: assessment });
    openTechnical();
    expect(screen.getByRole('button', { name: 'Hide technical details' })).toHaveAttribute('aria-expanded', 'true');
    const sections = [...document.querySelectorAll('details.tech-section')];
    expect(sections.map(s => s.querySelector('summary span').textContent)).toEqual([
      'Evidence behind the verdict', 'Email authentication (SPF, DKIM, DMARC)', 'Attachments', 'Indicator explorer',
      'Technical observations', 'How this analysis ran', 'Limits of this analysis', 'Email headers and identifiers',
    ]);
    expect(sections.every(s => !s.open)).toBe(true);
    fireEvent.click(screen.getByRole('button', { name: 'Hide technical details' }));
    expect(document.querySelector('details.tech-section')).toBeNull();
  });

  it('holds the complete evidence with references and all supporting quotes', () => {
    show({ ...base, ai_assessment: assessment });
    openTechnical();
    const evidence = sectionOf('Evidence behind the verdict');
    expect(within(evidence).getByText('Reason five.')).toBeInTheDocument();
    expect(within(evidence).getAllByText('observation-1')).toHaveLength(5);
    expect(within(evidence).getByText('innerhalb von 24 Stunden')).toBeInTheDocument();
    expect(within(evidence).getByText('Sets a deadline.')).toBeInTheDocument();
    expect(within(evidence).getAllByText(/checked against it/)).toHaveLength(1);
    expect(within(evidence).queryByText('Mit freundlichen Grüßen')).not.toBeInTheDocument();
    // What the model weighed against its verdict appears as a note on limits.
    const limits = sectionOf('Limits of this analysis');
    expect(within(limits).getByText('The address is an ordinary cloud address.')).toBeInTheDocument();
    expect(within(limits).getByText('Headers are unverified.')).toBeInTheDocument();
    expect(within(limits).getAllByText(/were not independently verified/)).toHaveLength(1);
    expect(within(limits).getByText('FUTURE_CODE')).toBeInTheDocument();
    expect(within(limits).getByText(/not a guarantee of security/)).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/pointing the other way|Contradict/i);
    const run = sectionOf('How this analysis ran');
    expect(within(run).getByText('model-x')).toBeInTheDocument();
    expect(run.textContent).toContain('EML file · mail.eml');
    const headers = sectionOf('Email headers and identifiers');
    expect(within(headers).getByText('=?utf-8?Q?Verd=C3=A4chtige?=')).toBeInTheDocument();
    expect(within(headers).getByText('from a.test by b.test')).toBeInTheDocument();
  });

  it('shows SPF, DKIM and DMARC separately with correctly separated notes', () => {
    show({ ...base, ai_assessment: assessment });
    openTechnical();
    const auth = sectionOf('Email authentication (SPF, DKIM, DMARC)');
    const rows = [...auth.querySelectorAll('tbody tr')];
    expect(rows.map(r => [r.querySelector('th').textContent, r.querySelector('td').textContent])).toEqual([['SPF', 'pass'], ['DKIM', 'none'], ['DMARC', 'bestguesspass']]);
    const notes = row => [...row.querySelectorAll('ul.notes > li')].map(li => li.textContent);
    expect(notes(rows[0])).toEqual([
      'Reported by a header that cannot be trusted; not independently verified.',
      'The header does not name the server that reported it.',
      'Reported details: smtp.mailfrom=ledgermail.onmicrosoft.example',
    ]);
    // No other method's details leak into DKIM, and no result is shown as a server name.
    expect(notes(rows[1]).join(' ')).not.toMatch(/mailfrom|spf=|pass/);
    expect(notes(rows[2])).toContain('Reported by server: mx.example.test');
    expect(notes(rows[2]).join(' ')).toMatch(/It is not a DMARC pass/);
    // Notes are separate list items (separate lines), never one run-on sentence.
    expect(rows.every(r => r.querySelectorAll('ul.notes > li').length >= 2)).toBe(true);
    expect(auth.textContent).not.toMatch(/verifiedreported|reported by spf=pass|server: spf=/i);
    expect(within(auth).getByText(/did not repeat SPF, DKIM or DMARC checks/)).toBeInTheDocument();
    // The raw header is available once, as text.
    expect(within(auth).getAllByText(/spf=pass smtp\.mailfrom=ledgermail\.onmicrosoft\.example; dkim=none/)).toHaveLength(1);
    expect(auth.querySelector('a')).toBeNull();
  });

  it('marks missing authentication explicitly', () => {
    const missing = ['spf', 'dkim', 'dmarc'].map(mechanism => ({ mechanism, reported_result: 'unavailable', trust_status: 'unavailable', verification_status: 'unavailable', alignment_information: 'unavailable', limitations: [mechanism === 'dkim' ? 'DKIM_SIGNATURE_PRESENT_NOT_VERIFIED' : 'NO_REPORTED_RESULT'] }));
    show({ ...base, report: { ...base.report, authentication: missing }, ai_assessment: assessment });
    openTechnical();
    const auth = sectionOf('Email authentication (SPF, DKIM, DMARC)');
    expect(within(auth).getAllByText('No result reported')).toHaveLength(3);
    expect(within(auth).getByText(/DKIM signature is present but was not verified/)).toBeInTheDocument();
    expect(auth.textContent).not.toMatch(/cannot be trusted/);
  });

  it('lists attachments compactly with the full hash and established facts on demand', () => {
    show({ ...base, ai_assessment: assessment });
    openTechnical();
    const attachments = sectionOf('Attachments');
    expect(within(attachments).getAllByText(SHA)).toHaveLength(1);
    expect(attachments.querySelector('.attachment-row details').open).toBe(false);
    for (const fact of ['Attachment present in the email', 'SHA-256 calculated', 'Reputation looked up at VirusTotal by hash', 'File contents were not opened or inspected']) {
      expect(within(attachments).getByText(fact)).toBeInTheDocument();
    }
    expect(within(attachments).getByText(/file type alone does not show that a file is harmful/)).toBeInTheDocument();
    expect(within(attachments).getByText(/do not prove that a file is safe/)).toBeInTheDocument();
  });

  it('keeps the indicator explorer searchable, filtered and paginated', () => {
    const iocs = [
      ...Array.from({ length: 45 }, (_, i) => ({ type: 'url', resource_category: 'actionable_hyperlink', source: 'html_link', normalized_value: `https://example.test/${i}`, original_value: `https://wrapper.test/?url=${i}`, defanged_value: `hxxps://example[.]test/${i}`, wrapper: 'microsoft_safelinks', finding_ids: i === 0 ? ['observation-1'] : [] })),
      { type: 'domain', resource_category: 'link_host', source: 'url', normalized_value: 'example.test', defanged_value: 'example[.]test' },
      ...Array.from({ length: 30 }, (_, i) => ({ type: 'url', resource_category: i % 2 ? 'embedded_image' : 'tracking_url', source: 'html_resource', normalized_value: `https://cdn.test/${i}.png`, defanged_value: `hxxps://cdn[.]test/${i}.png` })),
    ];
    show({ ...base, report: { ...base.report, iocs } });
    openTechnical();
    expect(screen.getByText('46 of 76 indicators')).toBeInTheDocument();
    expect(screen.getAllByTestId('ioc-row')).toHaveLength(20);
    expect(screen.queryByText(/cdn\[\.\]test/)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Next page' }));
    expect(screen.getByText('hxxps://example[.]test/20')).toBeInTheDocument();
    expect(screen.getByText('Page 2 of 3')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Search indicators'), { target: { value: '/44' } });
    expect(screen.getAllByTestId('ioc-row')).toHaveLength(1);
    expect(screen.getByText('https://wrapper.test/?url=44')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Search indicators'), { target: { value: '' } });
    fireEvent.change(screen.getByLabelText('Type'), { target: { value: 'domain' } });
    expect(screen.getAllByTestId('ioc-row')).toHaveLength(1);
    fireEvent.change(screen.getByLabelText('Type'), { target: { value: '' } });
    fireEvent.click(screen.getByLabelText('Show embedded resources (30)'));
    expect(screen.getByText('76 of 76 indicators')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Category'), { target: { value: 'tracking_url' } });
    expect(screen.getAllByTestId('ioc-row')).toHaveLength(15);
    expect(screen.getAllByRole('link').every(a => a.getAttribute('href').startsWith('/'))).toBe(true);
  });

  it('labels the button "Copy" and still copies the defanged value', async () => {
    const writeText = vi.fn().mockResolvedValue();
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } });
    show({ ...base, attachment_reputation: [], report: { ...base.report, email: { ...base.report.email, attachments: [] } } });
    openTechnical();
    expect(screen.queryByText('Copy defanged')).not.toBeInTheDocument();
    const button = within(sectionOf('Indicator explorer')).getByRole('button', { name: 'Copy' });
    expect(button).toHaveAttribute('title', 'Copies the safe, non-clickable form');
    fireEvent.click(button);
    expect(writeText).toHaveBeenCalledWith('hxxps://a[.]test/');
    expect(writeText).not.toHaveBeenCalledWith('https://a.test/');
    expect(await screen.findByText('Safe form copied')).toBeInTheDocument();
  });
});

describe('report behaviour', () => {
  it('renders untrusted email content as text only', () => {
    const hostile = { ...base, report: { ...base.report, email: { ...base.report.email, subject: '<img src=x onerror=alert(1)>', sender_name: '<script>alert(1)</script>' } } };
    show({ ...hostile, ai_assessment: assessment });
    expect(screen.getByText('<img src=x onerror=alert(1)>')).toBeInTheDocument();
    expect(document.querySelector('main img, section img')).toBeNull();
    expect(document.querySelector('script')).toBeNull();
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

  it.each(['ru', 'kk'])('shows explanations in %s and leaves quotes in the original language', async lang => {
    await i18n.changeLanguage(lang);
    show({ ...base, ai_assessment: assessment });
    expect(screen.getByText(`${lang}:Deceptive link and impersonated brand.`)).toBeInTheDocument();
    expect(screen.getByText(`${lang}:Reason one.`)).toBeInTheDocument();
    // The quote explanation follows the interface language; the quote does not change.
    expect(screen.getByText(`${lang}:Asks for wallet confirmation.`, { exact: false })).toBeInTheDocument();
    expect(screen.getByText(/Bitte bestätigen Sie Ihre Wallet/)).toBeInTheDocument();
    expect(screen.getByText('Verdächtige DEX-Aktivität erkannt')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: i18n.t('technicalShow') }));
    for (const s of document.querySelectorAll('details.tech-section')) s.open = true;
    expect(screen.getByText(`${lang}:Sets a deadline.`)).toBeInTheDocument();
    expect(screen.getByText(`${lang}:Headers are unverified.`)).toBeInTheDocument();
    expect(screen.getByText(i18n.t('authenticationNotice'))).toBeInTheDocument();
    // No English interface text and no English model text is left on the page.
    expect(document.body.textContent).not.toMatch(/Main reasons|What to do|Technical details|No result reported|Asks for wallet confirmation\.(?!.)|^Reason one\./);
    expect(document.body.textContent).not.toContain(' Sets a deadline.');
    await i18n.changeLanguage('en');
  });

  it('reads reports stored with single-language explanations', () => {
    const old = { ...assessment, contextual_findings: [{ type: 'coercion', quote: 'old quote text', reason: 'Old English reason.' }], uncertainty_notes: ['Old note.'], evidence_findings: undefined, supporting_evidence_ids: ['sender-1'] };
    show({ ...base, ai_assessment: old });
    expect(screen.getByText(/Old English reason\./)).toBeInTheDocument();
    openTechnical();
    expect(within(sectionOf('Limits of this analysis')).getByText('Old note.')).toBeInTheDocument();
    expect(within(sectionOf('Evidence behind the verdict')).getByText('sender-1')).toBeInTheDocument();
  });
});
