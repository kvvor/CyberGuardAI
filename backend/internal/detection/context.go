package detection

// ApplyContext applies a bounded adjustment only when contextual claims cite
// existing evidence. Model verdicts never directly overwrite the static score.
func ApplyContext(r *Report, verdict string, support, contradict []string) {
	known := map[string]bool{}
	for _, f := range r.Indicators {
		known[f.ID] = true
	}
	used := map[string]bool{}
	positive, negative := 0, 0
	for _, id := range support {
		if known[id] && !used[id] {
			positive++
			used[id] = true
		}
	}
	for _, id := range contradict {
		if known[id] && !used[id] {
			negative++
			used[id] = true
		}
	}
	delta := 0
	if verdict == "phishing" || verdict == "suspicious" {
		delta = positive * 3
		if delta > 10 {
			delta = 10
		}
	}
	if negative > 0 {
		delta -= 5
	}
	r.Score += delta
	if r.Score < 0 {
		r.Score = 0
	}
	if r.Score > 100 {
		r.Score = 100
	}
	r.Level = "low"
	r.Verdict = "inconclusive"
	if r.Score >= 20 {
		r.Level = "medium"
		r.Verdict = "suspicious"
	}
	if r.Score >= 45 {
		r.Level = "high"
	}
	if r.Score >= 60 {
		r.Verdict = "phishing"
	}
	if r.Score >= 70 {
		r.Level = "critical"
	}
	r.Limitations = append(r.Limitations, "AI_ADJUSTMENT_CAPPED_AT_10")
	if len(r.Indicators) == 0 && verdict == "legitimate" {
		r.Limitations = append(r.Limitations, "AI_BENIGN_OPINION_NOT_VERIFIED")
	}
}
func Narrative(lang string) (string, string) {
	switch lang {
	case "ru":
		return "Оценка основана на наблюдаемых признаках. Отсутствие признаков не гарантирует безопасность. Проверка человеком обязательна.", "Не открывайте подозрительные ссылки или вложения. Подтвердите запрос через известный независимый канал связи."
	case "kk":
		return "Бағалау байқалған белгілерге негізделген. Белгілердің болмауы қауіпсіздікке кепілдік бермейді. Адамның тексеруі қажет.", "Күдікті сілтемелерді немесе тіркемелерді ашпаңыз. Сұрауды белгілі тәуелсіз байланыс арнасы арқылы растаңыз."
	default:
		return "The assessment uses observed indicators. Absence of indicators does not guarantee safety. Human review is required.", "Do not open suspicious links or attachments. Verify the request through a known independent contact channel."
	}
}
