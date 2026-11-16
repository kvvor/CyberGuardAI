import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '../services/api';
import { Badge, ConfirmButton, ErrorMessage, Resource, useResource } from './common';
import '../i18n/app';

const paths = { openai: '/settings/ai-provider', virustotal: '/settings/virustotal' };

function ConnectionStatus({ config }) {
  const { t, i18n } = useTranslation();
  if (!config.has_credential) return null;
  const status = config.connection_status || 'untested';
  const failed = status !== 'untested' && status !== 'credential_validated';
  return (
    <p className="muted">
      {t('connectionStatus')}: <span className={failed ? 'danger' : ''}>{t(status, { defaultValue: status })}</span>
      {config.last_success_at && <> · {t('lastSuccess')}: {new Date(config.last_success_at).toLocaleString(i18n.language)}</>}
    </p>
  );
}

function ProviderForm({ provider, config, onSaved }) {
  const { t } = useTranslation();
  const path = paths[provider];
  const [key, setKey] = useState('');
  const [model, setModel] = useState(config.model || '');
  // A provider that has never been configured is enabled by default: a saved
  // but disabled key looked configured while analyses silently skipped it.
  const [enabled, setEnabled] = useState(config.has_credential ? config.enabled : true);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState(null);
  const [message, setMessage] = useState('');
  const [models, setModels] = useState(null);
  const operator = config.source === 'operator';

  function begin(action) { setBusy(action); setError(null); setMessage(''); }
  function fail(e) { setError({ code: e.code || 'error', requestId: e.requestId }); }

  async function save(event) {
    event.preventDefault();
    if (!key.trim() && (!config.has_credential || operator)) return setError({ code: 'PROVIDER_KEY_REQUIRED' });
    if (provider === 'openai' && !model.trim()) return setError({ code: 'PROVIDER_MODEL_INVALID' });
    begin('save');
    try {
      const saved = await api(path, { method: 'POST', body: { provider, model: provider === 'openai' ? model.trim() : '', api_key: key, enabled } });
      // The key leaves component state as soon as the server confirms it.
      setKey('');
      setModel(saved.model || '');
      setEnabled(saved.enabled);
      setMessage('providerSaved');
      onSaved(saved);
    } catch (e) { fail(e); } finally { setBusy(''); }
  }

  async function remove() {
    begin('remove');
    try {
      await api(path, { method: 'DELETE' });
      setKey('');
      setModels(null);
      setEnabled(true);
      setMessage('providerRemoved');
      onSaved({ ...config, has_credential: false, enabled: false, connection_status: 'not_configured', last_success_at: null, source: 'user' });
    } catch (e) { fail(e); } finally { setBusy(''); }
  }

  async function test() {
    begin('test');
    try {
      const result = await api(`${path}/test`, { method: 'POST' });
      if (result.success) setMessage(provider === 'openai' ? 'providerTestOK' : 'vtTestOK');
      else setError({ code: result.failure_code || 'provider_error' });
      onSaved({ ...config, connection_status: result.success ? 'credential_validated' : result.failure_code, last_success_at: result.success ? new Date().toISOString() : config.last_success_at });
    } catch (e) { fail(e); } finally { setBusy(''); }
  }

  async function loadModels() {
    begin('models');
    try {
      // A typed but unsaved key is used once for this metadata request so the
      // model can be chosen before the first save.
      const result = key.trim()
        ? await api(`${path}/models`, { method: 'POST', body: { api_key: key } })
        : await api(`${path}/models`);
      if (!result.success) { setModels(null); setError({ code: result.failure_code || 'provider_error' }); return; }
      setModels(result.models);
      if (!model && result.models.length) setModel(result.models[0].id);
    } catch (e) { fail(e); } finally { setBusy(''); }
  }

  const state = !config.has_credential ? 'providerMissing' : config.enabled ? 'providerConfigured' : 'providerConfiguredDisabled';
  const dirty = key !== '' || model !== (config.model || '') || enabled !== config.enabled;
  const canList = Boolean(key.trim()) || config.has_credential;
  const inList = models?.some(m => m.id === model);

  return (
    <form onSubmit={save} noValidate>
      <p role="status" className="provider-state">
        <Badge value={config.has_credential && config.enabled ? 'legitimate' : 'inconclusive'} label={t(state)} />
        {provider === 'openai' && config.has_credential && config.model && <span className="muted"> {t('usingModel')}: <code>{config.model}</code></span>}
      </p>
      <ConnectionStatus config={config} />
      {operator && <p className="notice">{t('providerOperator')}</p>}
      <p className="muted">{t(provider === 'openai' ? 'openaiPrivacy' : 'vtPrivacy')}</p>
      {provider === 'virustotal' && config.lookups_per_minute && <p className="muted">{t('vtLimits', { minute: config.lookups_per_minute, day: config.lookups_per_day })}</p>}

      <label>
        {t('providerKey')}
        <input type="password" name={`${provider}-api-key`} autoComplete="off" spellCheck={false} value={key} maxLength={4096} disabled={Boolean(busy)}
          placeholder={config.has_credential && !operator ? '••••••••••••••••' : ''} aria-describedby={`${provider}-key-hint`} onChange={e => setKey(e.target.value)} />
        <small id={`${provider}-key-hint`}>{t(config.has_credential && !operator ? 'providerKeyKeep' : 'providerKeyNew')}</small>
      </label>

      {provider === 'openai' && (
        <div className="field">
          <label htmlFor="openai-model">{t('providerModel')}</label>
          {/* Input and button share one row and one height; the hint sits below both. */}
          <div className="control-row">
            {models && inList
              ? <select id="openai-model" value={model} disabled={Boolean(busy)} onChange={e => setModel(e.target.value)}>{models.map(m => <option key={m.id} value={m.id}>{m.id}</option>)}</select>
              : <input id="openai-model" list="openai-models" value={model} maxLength={128} spellCheck={false} autoComplete="off" disabled={Boolean(busy)} onChange={e => setModel(e.target.value)} />}
            {models && !inList && <datalist id="openai-models">{models.map(m => <option key={m.id} value={m.id} />)}</datalist>}
            {models && inList && <button type="button" disabled={Boolean(busy)} aria-label={t('providerModelManual')} title={t('providerModelManual')} onClick={() => setModels(null)}>✎</button>}
            <button type="button" disabled={Boolean(busy) || !canList} onClick={loadModels}>{busy === 'models' ? t('loading') : t('providerLoadModels')}</button>
          </div>
          <small>{models ? t('providerModelsLoaded', { n: models.length }) : t(canList ? 'providerModelHint' : 'providerModelsNeedKey')}</small>
        </div>
      )}

      <label className="consent">
        <input type="checkbox" checked={enabled} disabled={Boolean(busy)} onChange={e => setEnabled(e.target.checked)} />
        {t('providerEnabled')}
      </label>

      <ErrorMessage error={error} />
      {message && <p role="status" className="notice success">{t(message)}</p>}

      <div className="toolbar">
        <button className="primary" disabled={Boolean(busy)}>{busy === 'save' ? t('loading') : t('providerSave')}</button>
        <button type="button" disabled={Boolean(busy) || !config.has_credential || dirty} title={dirty ? t('providerSave') : undefined} onClick={test}>{busy === 'test' ? t('loading') : t('providerTest')}</button>
        {config.has_credential && !operator && <ConfirmButton label={t('providerRemove')} question={t('providerRemoveConfirm')} confirmLabel={t('providerRemoveYes')} disabled={Boolean(busy)} onConfirm={remove} />}
      </div>
    </form>
  );
}

export function ProviderSettings({ provider }) {
  const resource = useResource(paths[provider]);
  return (
    <section className="panel" aria-labelledby={`${provider}-title`}>
      <h2 id={`${provider}-title`}>{provider === 'openai' ? 'OpenAI' : 'VirusTotal'}</h2>
      <Resource resource={resource}>
        {config => <ProviderForm provider={provider} config={config} onSaved={resource.set} />}
      </Resource>
    </section>
  );
}
