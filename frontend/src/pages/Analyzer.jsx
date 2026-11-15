import { useEffect, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { UploadCloud, ScanLine } from 'lucide-react';
import { api, ANALYSIS_TIMEOUT } from '../services/api';
import { Badge, ErrorMessage, useResource } from '../components/common';
import '../i18n/app';

function usable(resource) {
  return Boolean(resource.data?.has_credential && resource.data?.enabled);
}

function ProviderLine({ name, resource }) {
  const { t } = useTranslation();
  if (resource.loading) return <p className="muted">{name}: {t('loading')}</p>;
  if (resource.error) return <ErrorMessage error={resource.failure} code={resource.error} />;
  const d = resource.data;
  const ready = usable(resource);
  const state = !d.has_credential ? 'providerMissing' : d.enabled ? 'providerConfigured' : 'providerConfiguredDisabled';
  return (
    <p>
      <strong>{name}</strong>: <Badge value={ready ? 'legitimate' : 'inconclusive'} label={t(state)} />
      {ready && d.model && <span className="muted"> {t('usingModel')}: <code>{d.model}</code></span>}
      {!ready && <> <Link to="/settings">{t('openSettings')}</Link></>}
    </p>
  );
}

// Progress shows what the server was asked to do and how long it has been
// working. The request is a single call, so no per-step completion is claimed.
function Progress({ steps, onCancel }) {
  const { t } = useTranslation();
  const [seconds, setSeconds] = useState(0);
  useEffect(() => {
    const started = Date.now();
    const timer = setInterval(() => setSeconds(Math.round((Date.now() - started) / 1000)), 1000);
    return () => clearInterval(timer);
  }, []);
  return (
    <div role="status" aria-live="polite" className="notice progress">
      <strong>{t('analysisRunning')}</strong>
      <p>{t('analysisRunningHint')}</p>
      <ol>
        {steps.map(([key, requested]) => <li key={key} className={requested ? '' : 'muted'}>{t(key)}{!requested && <> — {t('stepSkipped')}</>}</li>)}
      </ol>
      <p className="muted">{t('elapsed', { seconds })}</p>
      <button type="button" onClick={onCancel}>{t('cancel')}</button>
    </div>
  );
}

export default function Analyzer() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [tab, setTab] = useState('upload');
  const [file, setFile] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [consent, setConsent] = useState(false);
  const [vtConsent, setVtConsent] = useState(false);
  const request = useRef(null);
  const config = useResource('/config/public');
  const openai = useResource('/settings/ai-provider');
  const vt = useResource('/settings/virustotal');
  const openaiReady = usable(openai);
  const vtReady = usable(vt);
  const limit = config.data?.max_email_size || 10485760;

  useEffect(() => () => request.current?.abort(), []);

  function select(candidate) {
    setError(null);
    if (!candidate) return setFile(null);
    if (!/\.(eml|msg)$/i.test(candidate.name)) { setFile(null); return setError({ code: 'INVALID_UPLOAD' }); }
    if (candidate.size > limit) { setFile(null); return setError({ code: 'EMAIL_TOO_LARGE' }); }
    setFile(candidate);
  }

  async function submit(event) {
    event.preventDefault();
    setError(null);
    const fields = Object.fromEntries(new FormData(event.currentTarget));
    const ai = consent && openaiReady;
    const reputation = vtConsent && vtReady;
    let body;
    if (tab === 'upload') {
      if (!file) return setError({ code: 'INVALID_UPLOAD' });
      body = new FormData();
      body.set('file', file);
      body.set('external_processing_consent', String(ai));
      body.set('virustotal_consent', String(reputation));
    } else {
      if (!fields.text?.trim()) return setError({ code: 'invalid' });
      body = { source_type: 'paste', text: fields.text, sender: fields.sender || '', subject: fields.subject || '', external_processing_consent: ai, virustotal_consent: reputation };
    }
    request.current = new AbortController();
    setBusy(true);
    try {
      const result = await api('/analyses', { method: 'POST', body, timeout: ANALYSIS_TIMEOUT, signal: request.current.signal });
      // Navigate only after the backend confirmed and stored the analysis.
      navigate(`/analyses/${result.id}`);
    } catch (e) {
      if (e.code !== 'CANCELLED') setError({ code: e.code, requestId: e.requestId });
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className="page-intro">
        <ScanLine size={32} />
        <h2>{t('analyze')}</h2>
        <p>{t('analyzeIntro')}</p>
      </div>
      <section className="panel">
        <div className="tabs" role="tablist">
          {['upload', 'paste'].map(v => (
            <button key={v} type="button" role="tab" aria-selected={tab === v} aria-pressed={tab === v} disabled={busy} onClick={() => { setTab(v); setError(null); }}>{t(v)}</button>
          ))}
        </div>
        <form key={tab} onSubmit={submit} noValidate>
          {tab === 'upload' ? (
            <div className="dropzone" onDragOver={e => e.preventDefault()} onDrop={e => { e.preventDefault(); if (!busy) select(e.dataTransfer.files[0]); }}>
              <UploadCloud size={42} />
              <label>
                {t('uploadHint')}
                <input aria-label={t('upload')} type="file" accept=".eml,.msg" disabled={busy} onChange={e => select(e.target.files[0])} />
              </label>
              {file && <p>{file.name} · {(file.size / 1024).toFixed(1)} KiB <button type="button" disabled={busy} onClick={() => setFile(null)}>{t('remove')}</button></p>}
            </div>
          ) : (
            <>
              <p className="muted">{t('pasteHint')}</p>
              <label>{t('senderOptional')}<input name="sender" maxLength={1024} disabled={busy} autoComplete="off" /></label>
              <label>{t('subjectOptional')}<input name="subject" maxLength={4096} disabled={busy} autoComplete="off" /></label>
              <label>{t('text')}<textarea name="text" rows={12} required disabled={busy} spellCheck={false} /></label>
            </>
          )}

          <fieldset className="providers" disabled={busy}>
            <legend>{t('providersForAnalysis')}</legend>
            <ProviderLine name="OpenAI" resource={openai} />
            <label className="consent">
              <input type="checkbox" name="consent" checked={consent && openaiReady} disabled={!openaiReady} onChange={e => setConsent(e.target.checked)} />
              {t('consentOpenAI')}
            </label>
            {!(consent && openaiReady) && <p className="notice">{t('noVerdictNotice')}</p>}
            <ProviderLine name="VirusTotal" resource={vt} />
            <label className="consent">
              <input type="checkbox" name="vtConsent" checked={vtConsent && vtReady} disabled={!vtReady} onChange={e => setVtConsent(e.target.checked)} />
              {t('consentVT')}
            </label>
          </fieldset>

          <ErrorMessage error={error} />
          {busy
            ? <Progress steps={[['stepParse', true], ['stepVT', vtConsent && vtReady], ['stepAI', consent && openaiReady], ['stepSave', true]]} onCancel={() => request.current?.abort()} />
            : <button className="primary">{t('startAnalysis')}</button>}
        </form>
      </section>
    </>
  );
}
