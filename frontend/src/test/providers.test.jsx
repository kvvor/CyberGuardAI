import { it, expect, vi, describe } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { ProviderSettings } from '../components/ProviderSettings';
import i18n from '../i18n';
import '../i18n/app';

const json = (body, status = 200) => Promise.resolve(new Response(body === null ? null : JSON.stringify(body), { status }));

// A minimal in-memory backend following the documented settings contract.
function backend({ provider, initial = {}, test = { success: true, failure_code: '' }, save, models }) {
  let config = { provider, model: '', enabled: false, has_credential: false, connection_status: 'not_configured', last_success_at: null, source: 'user', ...initial };
  const calls = [];
  vi.spyOn(window, 'fetch').mockImplementation((url, options = {}) => {
    const method = options.method || 'GET';
    const body = options.body ? JSON.parse(options.body) : undefined;
    calls.push({ url, method, body, options });
    if (url.endsWith('/models')) return json(models || { success: true, models: [{ id: 'model-new' }, { id: 'model-old' }], selected: config.model });
    if (url.endsWith('/test')) return json(test);
    if (method === 'DELETE') { config = { ...config, has_credential: false, enabled: false, connection_status: 'not_configured' }; return json(null, 204); }
    if (method === 'POST') {
      if (save) return save(body);
      config = { ...config, model: body.model, enabled: body.enabled, has_credential: config.has_credential || Boolean(body.api_key), connection_status: 'untested' };
    }
    return json(config);
  });
  return calls;
}

describe('provider settings', () => {
  it('loads models with an unsaved key, saves OpenAI settings and never keeps the key', async () => {
    const calls = backend({ provider: 'openai' });
    render(<ProviderSettings provider="openai" />);
    expect(await screen.findByText('Not configured')).toBeInTheDocument();
    const key = screen.getByLabelText(/API key/);
    expect(screen.getByRole('button', { name: 'Load available models' })).toBeDisabled();
    fireEvent.change(key, { target: { value: 'synthetic-secret' } });
    fireEvent.click(screen.getByRole('button', { name: 'Load available models' }));
    await waitFor(() => expect(screen.getByRole('combobox', { name: /Model/ })).toHaveValue('model-new'));
    const select = screen.getByRole('combobox', { name: /Model/ });
    fireEvent.change(select, { target: { value: 'model-old' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText('Configured')).toBeInTheDocument();
    expect(screen.getByText(/Saved\./)).toBeInTheDocument();
    const save = calls.find(c => c.method === 'POST' && c.url.endsWith('/settings/ai-provider'));
    expect(save.body).toEqual({ provider: 'openai', model: 'model-old', api_key: 'synthetic-secret', enabled: true });
    expect(save.options.credentials).toBe('include');
    expect(calls.find(c => c.url.endsWith('/models')).body).toEqual({ api_key: 'synthetic-secret' });
    // The secret is gone from the form and was never written to browser storage.
    expect(screen.getByLabelText(/API key/)).toHaveValue('');
    expect(JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage })).not.toContain('synthetic-secret');
    expect(document.body.innerHTML).not.toContain('synthetic-secret');
  });

  it('shows the saved state after a reload and keeps the key when only the model changes', async () => {
    const calls = backend({ provider: 'openai', initial: { has_credential: true, enabled: true, model: 'model-old', connection_status: 'credential_validated', last_success_at: '2026-03-03T09:00:00Z' } });
    render(<ProviderSettings provider="openai" />);
    expect(await screen.findByText('Configured')).toBeInTheDocument();
    expect(screen.getByText(/succeeded/)).toBeInTheDocument();
    expect(screen.getByLabelText(/API key/)).toHaveValue('');
    fireEvent.change(screen.getByRole('combobox', { name: /Model/ }), { target: { value: 'model-new' } });
    // An unsaved change must be saved before it can be tested.
    expect(screen.getByRole('button', { name: 'Test connection' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(calls.some(c => c.method === 'POST')).toBe(true));
    expect(calls.find(c => c.method === 'POST').body).toMatchObject({ model: 'model-new', api_key: '' });
    await waitFor(() => expect(screen.getByRole('button', { name: 'Test connection' })).toBeEnabled());
  });

  it.each([
    ['PROVIDER_INVALID_CREDENTIALS', /rejected the API key/],
    ['PROVIDER_INSUFFICIENT_QUOTA', /no remaining quota/],
    ['PROVIDER_RATE_LIMITED', /limiting requests/],
    ['PROVIDER_UNSUPPORTED_MODEL', /Choose another model/],
    ['PROVIDER_NETWORK_FAILURE', /could not reach OpenAI/],
    ['PROVIDER_TIMEOUT', /did not answer in time/],
  ])('explains connection test failure %s', async (code, text) => {
    backend({ provider: 'openai', initial: { has_credential: true, enabled: true, model: 'm' }, test: { success: false, failure_code: code } });
    render(<ProviderSettings provider="openai" />);
    fireEvent.click(await screen.findByRole('button', { name: 'Test connection' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(text);
  });

  it.each([
    ['DATABASE_SCHEMA_OUTDATED', 503, /scripts\\setup\.ps1/],
    ['PROVIDER_ENCRYPTION_UNAVAILABLE', 503, /PROVIDER_MASTER_KEY/],
    ['PROVIDER_KEY_MALFORMED', 400, /Copy it again/],
    ['CSRF_INVALID', 403, /Reload/],
    ['RATE_LIMITED', 429, /Too many attempts/],
  ])('explains save failure %s instead of a generic server error', async (code, status, text) => {
    backend({ provider: 'openai', save: () => json({ error: { code, request_id: 'req-1' } }, status) });
    render(<ProviderSettings provider="openai" />);
    fireEvent.change(await screen.findByLabelText(/API key/), { target: { value: 'k' } });
    fireEvent.change(screen.getByRole('combobox', { name: /Model/ }), { target: { value: 'm' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(text);
    expect(alert).not.toHaveTextContent('The server could not complete the request');
    expect(screen.getByLabelText(/API key/)).toHaveValue('k');
  });

  it('reports an unreachable backend and a missing key or model without calling the API', async () => {
    const calls = backend({ provider: 'openai', save: () => Promise.resolve(new Response('', { status: 500 })) });
    render(<ProviderSettings provider="openai" />);
    fireEvent.click(await screen.findByRole('button', { name: 'Save' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Enter an API key');
    fireEvent.change(screen.getByLabelText(/API key/), { target: { value: 'k' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Enter a model ID');
    expect(calls.filter(c => c.method === 'POST')).toHaveLength(0);
    fireEvent.change(screen.getByRole('combobox', { name: /Model/ }), { target: { value: 'm' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('The backend did not answer'));
  });

  it('configures, tests, disables and removes VirusTotal with confirmation', async () => {
    const calls = backend({ provider: 'virustotal', initial: { lookups_per_minute: 4, lookups_per_day: 500 }, test: { success: false, failure_code: 'authentication_failed' } });
    render(<ProviderSettings provider="virustotal" />);
    expect(await screen.findByText(/4 per minute, 500 per day/)).toBeInTheDocument();
    expect(screen.queryByRole('combobox', { name: /Model/ })).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/API key/), { target: { value: 'vt-secret' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText('Configured')).toBeInTheDocument();
    expect(calls.find(c => c.method === 'POST').body).toEqual({ provider: 'virustotal', model: '', api_key: 'vt-secret', enabled: true });
    fireEvent.click(screen.getByRole('button', { name: 'Test connection' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Key rejected');
    fireEvent.click(screen.getByRole('checkbox'));
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText('Key saved, provider disabled')).toBeInTheDocument();
    // Removal needs an explicit second click.
    fireEvent.click(screen.getByRole('button', { name: 'Remove key' }));
    expect(calls.some(c => c.method === 'DELETE')).toBe(false);
    fireEvent.click(screen.getByRole('button', { name: 'Yes, remove' }));
    expect(await screen.findByText('Not configured')).toBeInTheDocument();
    expect(calls.some(c => c.method === 'DELETE')).toBe(true);
  });
});

