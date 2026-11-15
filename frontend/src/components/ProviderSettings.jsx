import {useState} from 'react';
import {useTranslation} from 'react-i18next';
import {api} from '../services/api';
import {ErrorMessage,Resource,useResource} from './common';
import '../i18n/providers';

function ProviderForm({provider,config,onRefresh}) {
 const {t}=useTranslation();
 const [key,setKey]=useState('');
 const [model,setModel]=useState(config.model||'gpt-4.1-mini');
 const [enabled,setEnabled]=useState(config.enabled);
 const [busy,setBusy]=useState(false);
 const [error,setError]=useState('');
 const [message,setMessage]=useState('');
 const path=`/settings/${provider==='openai'?'ai-provider':'virustotal'}`;
 async function perform(action) {
  setBusy(true);setError('');setMessage('');
  try {
   if(action==='save') { await api(path,{method:'POST',body:{provider,model:provider==='openai'?model:'',api_key:key,enabled}});setKey('');setMessage('providerSaved');onRefresh(); }
   if(action==='remove') { await api(path,{method:'DELETE'});setKey('');onRefresh(); }
   if(action==='test') { const result=await api(`${path}/test`,{method:'POST'});if(result.success)setMessage('providerTestOK');else setError(result.failure_code||'provider_error'); }
  } catch(e) {setError(e.code);} finally {setBusy(false);}
 }
 return <form onSubmit={e=>{e.preventDefault();perform('save');}}>
  <p role="status">{t(config.has_credential?'providerConfigured':'providerMissing')}</p>
  <p>{t(provider==='openai'?'openaiPrivacy':'vtPrivacy')}</p>
  <label>{t('providerKey')}<input type="password" autoComplete="new-password" value={key} maxLength={4096} disabled={busy} onChange={e=>setKey(e.target.value)}/></label>
  {provider==='openai'&&<label>{t('providerModel')}<input list="openai-models" value={model} required maxLength={128} disabled={busy} onChange={e=>setModel(e.target.value)}/><datalist id="openai-models"><option value="gpt-4.1-mini"/><option value="gpt-4.1"/></datalist></label>}
  <label className="consent"><input type="checkbox" checked={enabled} disabled={busy} onChange={e=>setEnabled(e.target.checked)}/>{t('providerEnabled')}</label>
  <ErrorMessage code={error}/>{message&&<p role="status">{t(message)}</p>}
  <div className="toolbar"><button className="primary" disabled={busy}>{t('providerSave')}</button><button type="button" disabled={busy||!config.has_credential} onClick={()=>perform('test')}>{t('providerTest')}</button><button type="button" disabled={busy||!config.has_credential} onClick={()=>perform('remove')}>{t('providerRemove')}</button></div>
 </form>;
}
export function ProviderSettings({provider}) {
 const resource=useResource(`/settings/${provider==='openai'?'ai-provider':'virustotal'}`);
 return <section className="panel"><h2>{provider==='openai'?'OpenAI':'VirusTotal'}</h2><Resource resource={resource}>{config=><ProviderForm provider={provider} config={config} onRefresh={resource.retry}/>}</Resource></section>;
}
