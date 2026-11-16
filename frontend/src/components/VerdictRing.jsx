import { useTranslation } from 'react-i18next';
import { ShieldAlert, ShieldCheck, ShieldQuestion, TriangleAlert, CircleSlash } from 'lucide-react';
import '../i18n/app';

const ICONS = { phishing: ShieldAlert, suspicious: TriangleAlert, legitimate: ShieldCheck, inconclusive: ShieldQuestion, incomplete: CircleSlash };
const LEVELS = ['low', 'medium', 'high', 'critical'];

// VerdictRing is a categorical indicator. The ring is always complete and
// carries no quantity: its colour and icon stand for the verdict category.
// Severity is shown beside it as a labelled four-step scale ("level 3 of 4"),
// which is an ordered category, not a measured percentage or probability.
export default function VerdictRing({ verdict, severity }) {
  const { t } = useTranslation();
  const kind = ICONS[verdict] ? verdict : 'incomplete';
  const Icon = ICONS[kind];
  const severityLabel = severity === 'none' ? t('severity_none') : severity ? t(severity) : '';
  const label = verdict && verdict !== 'incomplete'
    ? t('verdictRingLabel', { verdict: t(verdict), severity: severityLabel })
    : t('assessmentMissing');
  return (
    <div className={`verdict-ring ring-${kind}`} role="img" aria-label={label}>
      <svg viewBox="0 0 120 120" aria-hidden="true" focusable="false">
        <circle className="ring-track" cx="60" cy="60" r="52" />
        <circle className="ring-line" cx="60" cy="60" r="52" />
      </svg>
      <Icon className="ring-icon" size={46} aria-hidden="true" />
    </div>
  );
}

export function SeverityScale({ severity }) {
  const { t } = useTranslation();
  if (!severity) return null;
  const level = LEVELS.indexOf(severity) + 1;
  const text = severity === 'none' ? t('severityScaleNone') : t('severityScale', { label: t(severity), level });
  return (
    <div className="severity-scale" title={t('severityHint')}>
      <span className="steps" aria-hidden="true">
        {LEVELS.map((name, i) => <span key={name} className={i < level ? `step on ${severity}` : 'step'} />)}
      </span>
      <span>{text}</span>
    </div>
  );
}
