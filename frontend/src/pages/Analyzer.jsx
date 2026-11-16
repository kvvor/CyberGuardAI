import { useEffect, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { UploadCloud, ScanLine, FileCheck2 } from 'lucide-react';
import { api, ANALYSIS_TIMEOUT } from '../services/api';
import { Badge, ErrorMessage, useResource } from '../components/common';
import { formatSize } from '../components/AttachmentReputation';
import HashLookup from '../components/HashLookup';
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

// Progress tells the truth about a single long request: the activities the
// server was asked to perform, an indeterminate indicator and the elapsed
// time. It does not mark steps as finished, because the page cannot know.
function Progress({ steps, onCancel }) {
  const { t } = useTranslation();
  const [seconds, setSeconds] = useState(0);
  useEffect(() => {
    const started = Date.now();
    const timer = setInterval(() => setSeconds(Math.round((Date.now() - started) / 1000)), 1000);
    return () => clearInterval(timer);
  }, []);
  return (
    <div role="status" aria-live="polite" aria-busy="true" className="progress">
      <div className="progress-head">
        <span className="spinner" aria-hidden="true" />
        <strong>{t('analysisRunning')}</strong>
        <span className="muted">{t('elapsed', { seconds })}</span>
      </div>
      <div className="progress-bar" aria-hidden="true"><span /></div>
      <p className="muted">{t('analysisRunningHint')}</p>
      <ul className="progress-steps">
        {steps.map(([key, requested]) => <li key={key} className={requested ? '' : 'skipped'}>{t(key)}{!requested && <span className="muted"> — {t('stepSkipped')}</span>}</li>)}
      </ul>
      {seconds >= 30 && <p className="notice">{t('analysisSlow')}</p>}
      <button type="button" onClick={onCancel}>{t('cancelAnalysis')}</button>
    </div>
  );
}

export default function Analyzer() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [tab, setTab] = useState('upload');
  const [file, setFile] = useState(null);
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [consent, setConsent] = useState(false);
  const [vtConsent, setVtConsent] = useState(false);
  const request = useRef(null);
  const input = useRef(null);
  const config = useResource('/config/public');
  const openai = useResource('/settings/ai-provider');
  const vt = useResource('/settings/virustotal');
  const openaiReady = usable(openai);
  const vtReady = usable(vt);
  const limit = config.data?.max_email_size || 10485760;

  useEffect(() => () => request.current?.abort(), []);

  // The selected file lives in component state and is what the page displays.
  // The native input is only a picker: it is cleared after every choice so the
  // same file can be chosen again and so it can never disagree with the state
  // (it used to show "No file selected" after drag-and-drop or a re-render).
  function select(candidate) {
    if (input.current) input.current.value = '';
    setError(null);
    if (!candidate) return;
    if (!/\.(eml|msg)$/i.test(candidate.name)) { setFile(null); return setError({ code: 'INVALID_UPLOAD' }); }
    if (candidate.size > limit) { setFile(null); return setError({ code: 'EMAIL_TOO_LARGE' }); }
    setFile(candidate);
  }
  function clear() {
    if (input.current) input.current.value = '';
    setFile(null);
    setError(null);
  }

  async function submit(event) {
    event.preventDefault();
    if (busy) return;
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
        <form onSubmit={submit} noValidate aria-busy={busy}>
          {tab === 'upload' ? (
            <div className={`dropzone${dragging ? ' dragging' : ''}${file ? ' has-file' : ''}`}
              onDragOver={e => { e.preventDefault(); if (!busy) setDragging(true); }}
              onDragLeave={() => setDragging(false)}
              onDrop={e => { e.preventDefault(); setDragging(false); if (!busy) select(e.dataTransfer.files[0]); }}>
              {file ? <FileCheck2 size={42} /> : <UploadCloud size={42} />}
              {file ? (
                <div className="selected-file" role="status">
                  <span className="muted">{t('uploadSelected')}</span>
                  <strong className="file-name">{file.name}</strong>
                  <span>{formatSize(file.size, t)} · <span className="ready">{t('uploadReady')}</span></span>
                </div>
              ) : (
                <p className="selected-file"><strong>{t('uploadNone')}</strong><span className="muted">{t('uploadDrop')}</span></p>
              )}
              <div className="toolbar file-actions">
                <label className={`file-button${busy ? ' disabled' : ''}`}>
                  {t(file ? 'uploadReplace' : 'uploadChoose')}
                  <input ref={input} className="visually-hidden" aria-label={t('upload')} type="file" accept=".eml,.msg" disabled={busy} onChange={e => select(e.target.files[0])} />
                </label>
                {file && <button type="button" disabled={busy} onClick={clear}>{t('uploadRemove')}</button>}
              </div>
              <small>{t('uploadHintOriginal')}</small>
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
            ? <Progress steps={[['stepPrepare', true], ['stepParse', true], ['stepVT', vtConsent && vtReady], ['stepAI', consent && openaiReady], ['stepSave', true]]} onCancel={() => request.current?.abort()} />
            : <button className="primary">{t('startAnalysis')}</button>}
        </form>
      </section>
      <HashLookup ready={vtReady} />
    </>
  );
}
