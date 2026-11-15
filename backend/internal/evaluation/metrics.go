package evaluation

import "fmt"

// Outcome pairs a ground-truth label with the verdict an assessment produced.
// Verdict is "" when no assessment was produced (provider failure).
type Outcome struct {
	ID, Label, Verdict string
}

// Metrics is a binary confusion matrix. "suspicious" and "phishing" verdicts
// count as positive, "legitimate" as negative. "inconclusive" and missing
// verdicts are abstentions and are never counted as correct negatives.
// Ambiguous cases have no single right answer and are reported separately.
type Metrics struct {
	TP, FP, TN, FN int
	Abstained      int
	Ambiguous      map[string]int
	Evaluated      int
}

func Score(outcomes []Outcome) Metrics {
	m := Metrics{Ambiguous: map[string]int{}}
	for _, o := range outcomes {
		if o.Label == "ambiguous" {
			verdict := o.Verdict
			if verdict == "" {
				verdict = "no_assessment"
			}
			m.Ambiguous[verdict]++
			continue
		}
		m.Evaluated++
		positive := o.Verdict == "phishing" || o.Verdict == "suspicious"
		negative := o.Verdict == "legitimate"
		switch {
		case !positive && !negative:
			m.Abstained++
		case o.Label == "phishing" && positive:
			m.TP++
		case o.Label == "phishing":
			m.FN++
		case positive:
			m.FP++
		default:
			m.TN++
		}
	}
	return m
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

func (m Metrics) Precision() float64         { return ratio(m.TP, m.TP+m.FP) }
func (m Metrics) Recall() float64            { return ratio(m.TP, m.TP+m.FN) }
func (m Metrics) FalsePositiveRate() float64 { return ratio(m.FP, m.FP+m.TN) }
func (m Metrics) FalseNegativeRate() float64 { return ratio(m.FN, m.FN+m.TP) }
func (m Metrics) Coverage() float64          { return ratio(m.Evaluated-m.Abstained, m.Evaluated) }
func (m Metrics) F1() float64 {
	p, r := m.Precision(), m.Recall()
	if p+r == 0 {
		return 0
	}
	return 2 * p * r / (p + r)
}

func (m Metrics) String() string {
	return fmt.Sprintf("confusion matrix (positive = phishing or suspicious): TP=%d FP=%d TN=%d FN=%d abstained=%d of %d labelled cases\nprecision=%.2f recall=%.2f F1=%.2f false-positive rate=%.2f false-negative rate=%.2f coverage=%.2f\nambiguous cases by verdict: %v",
		m.TP, m.FP, m.TN, m.FN, m.Abstained, m.Evaluated, m.Precision(), m.Recall(), m.F1(), m.FalsePositiveRate(), m.FalseNegativeRate(), m.Coverage(), m.Ambiguous)
}
