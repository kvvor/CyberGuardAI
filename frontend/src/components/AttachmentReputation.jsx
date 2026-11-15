import {useTranslation} from 'react-i18next';
import {Badge} from './common';
import '../i18n/providers';
export default function AttachmentReputation({report}) {
 const {t,i18n}=useTranslation();
 return <section className="panel"><h3>{t('attachments')} / VirusTotal</h3><p>{t('vtUnknown')}</p>{!report.email.attachments?.length?<p>{t('vtNoAttachments')}</p>:report.email.attachments.map((a,i)=>{
 const r=report.attachment_reputation?.find(r=>r.sha256===a.sha256);
 return <details key={i}><summary>{a.filename} · <Badge value={r?.status||'not_requested'}/></summary><p>{a.size} {t('bytes')} · {a.declared_mime} · {a.detected_mime}</p><code style={{overflowWrap:'anywhere'}}>{a.sha256}</code>{r?.statistics&&<p>{t('vtMalicious')}: {r.statistics.malicious} · {t('vtSuspicious')}: {r.statistics.suspicious} · {t('vtUndetected')}: {r.statistics.undetected}</p>}{r?.last_analysis_at&&<p>{t('vtLastAnalysis')}: {new Date(r.last_analysis_at).toLocaleString(i18n.language)}</p>}</details>;
 })}</section>;
}
