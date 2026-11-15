import {useState} from 'react';
import {useTranslation} from 'react-i18next';
import {Badge} from './common';
import AttachmentReputation from './AttachmentReputation';
import i18n from '../i18n';
const labels={
 assessmentMissing:['Assessment incomplete — no AI verdict','Анализ не завершён — вердикта ИИ нет','Талдау аяқталмады — ЖИ қорытындысы жоқ'],
 confidence:['Confidence (qualitative)','Уверенность (качественная)','Сенімділік (сапалық)'],
 authentication:['Email authentication','Аутентификация письма','Хат аутентификациясы'],
 evidence:['Supporting evidence','Подтверждающие данные','Растаушы деректер'],
 evidenceSearch:['Search evidence','Поиск данных','Деректерді іздеу'],
 previousPage:['Previous page','Предыдущая страница','Алдыңғы бет'],
 nextPage:['Next page','Следующая страница','Келесі бет'],
 untrusted_reported:['Reported in an untrusted header','Заявлено в недоверенном заголовке','Сенімсіз тақырыпта көрсетілген'],
 unable_to_verify:['Not independently verified','Независимая проверка не выполнена','Тәуелсіз тексерілмеген'],
 modelInterpretation:['Model interpretation; cited text checked','Интерпретация модели; цитата проверена','Модель түсіндірмесі; дәйексөз тексерілді'],
 none:['None','Нет','Жоқ'],
 legacyReport:['Historical report — legacy detector','Исторический отчёт — прежний детектор','Тарихи есеп — бұрынғы детектор']
};
for(const [i,l] of ['en','ru','kk'].entries())i18n.addResourceBundle(l,'translation',Object.fromEntries(Object.entries(labels).map(([k,v])=>[k,v[i]])),true,true);

export default function EvidenceReport({analysis,onExport,onDelete,busy}) {
 const {t,i18n}=useTranslation();const [search,setSearch]=useState('');const [category,setCategory]=useState('');const [page,setPage]=useState(0);const [copied,setCopied]=useState(false);
 const r=analysis.report,a=analysis.ai_assessment;
 const local=v=>v?.[i18n.language]||v?.en||'';
 const entries=(r.iocs||[]).filter(v=>(!category||v.resource_category===category)&&`${v.original_value} ${v.normalized_value}`.toLowerCase().includes(search.toLowerCase()));
 const evidence=(id)=>r.evidence?.find(e=>e.id===id);
 const refs=ids=><ul>{ids?.map(id=><li key={id}><code>{id}</code>: {evidence(id)?.value}</li>)}</ul>;
 return <>
  <div className="toolbar">{['pdf','json'].map(format=><button key={format} disabled={busy} onClick={()=>onExport(format)}>{t('export')} {format.toUpperCase()}</button>)}<button className="danger" disabled={busy} onClick={onDelete}>{t('delete')}</button></div>
  <section className="panel"><h2>{a?t(a.proposed_verdict):t('assessmentMissing')}</h2><Badge value={analysis.ai_execution?.status||r.ai_status}/>{a&&<><Badge value={a.severity}/><p>{t('confidence')}: {t(a.confidence)}</p><p>{local(a.explanations)}</p></>}{analysis.ai_execution?.failure_code&&<p>{t(analysis.ai_execution.failure_code,{defaultValue:t('provider_error')})}</p>}<p>{r.email.subject}</p></section>
  {a&&<><section className="panel"><h3>{t('evidence')}</h3>{refs(a.supporting_evidence_ids)}{a.contextual_findings?.map((o,i)=><article key={i}><blockquote>{o.quote}</blockquote><p>{o.reason}</p><small>{t('modelInterpretation')}</small></article>)}</section><section className="panel"><h3>{t('recommendations')}</h3><p>{local(a.recommendations)}</p></section></>}
  <details className="panel"><summary>{t('ai')}</summary><h4>{t('contradictory_evidence_ids')}</h4>{refs(a?.contradictory_evidence_ids)}<h4>{t('limitations')}</h4><ul>{[...(a?.uncertainty_notes||[]),...(r.limitations||[])].map((v,i)=><li key={i}>{t(v,{defaultValue:v})}</li>)}</ul></details>
  <details className="panel"><summary>{t('authentication')}</summary>{r.authentication?.map((v,i)=><article key={i}><h4>{v.mechanism.toUpperCase()}: {v.reported_result}</h4><p>{t(v.trust_status)} · {t(v.verification_status)}</p><p>{v.reporting_server} · {v.evidence_source}</p></article>)}</details>
  <details className="panel"><summary>{t('iocs')} ({entries.length})</summary><label>{t('evidenceSearch')}<input value={search} onChange={e=>{setSearch(e.target.value);setPage(0);}}/></label><select aria-label={t('iocs')} value={category} onChange={e=>{setCategory(e.target.value);setPage(0);}}><option value="">{t('all')}</option>{[...new Set(r.iocs?.map(v=>v.resource_category).filter(Boolean))].map(c=><option key={c}>{c}</option>)}</select>{copied&&<p role="status">{t('copied')}</p>}<div className="table-scroll"><table><tbody>{entries.slice(page*20,page*20+20).map((v,i)=><tr key={i}><td>{v.type}</td><td><code style={{overflowWrap:'anywhere'}}>{v.defanged_value}</code><details><summary>{t('source')}</summary><code>{v.original_value}</code></details></td><td><button onClick={async()=>{try{await navigator.clipboard.writeText(v.defanged_value);setCopied(true);}catch{setCopied(false);}}}>{t('copy')}</button></td></tr>)}</tbody></table></div><button disabled={page===0} onClick={()=>setPage(page-1)}>{t('previousPage')}</button><button disabled={(page+1)*20>=entries.length} onClick={()=>setPage(page+1)}>{t('nextPage')}</button></details>
  <AttachmentReputation report={r}/>
  <details className="panel"><summary>{t('metadata')}</summary><dl>{['sender','reply_to','recipients','subject','message_id','filename'].map(k=><div key={k}><dt>{t(k)}</dt><dd>{Array.isArray(r.email[k])?r.email[k].join(', '):r.email[k]}</dd></div>)}</dl>{r.evidence?.filter(e=>['Received','Return-Path','Sender'].includes(e.source)).map(e=><p key={e.id}>{e.source}: {e.value} ({t('untrusted_reported')})</p>)}</details>
 </>;
}
