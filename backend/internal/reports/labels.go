package reports

// Label localizes presentation only. Forensic evidence is never translated.
func Label(lang, key string) string {
	labels := map[string][3]string{
		"id": {"Report ID", "Идентификатор отчёта", "Есеп идентификаторы"}, "date": {"Date (UTC)", "Дата (UTC)", "Күні (UTC)"}, "subject": {"Subject", "Тема", "Тақырып"}, "sender": {"Sender", "Отправитель", "Жіберуші"}, "verdict": {"Verdict", "Вердикт", "Қорытынды"}, "risk": {"Risk score / level", "Оценка / уровень риска", "Қауіп бағасы / деңгейі"}, "indicators": {"Observed indicators", "Наблюдаемые признаки", "Байқалған белгілер"}, "iocs": {"Indicators of compromise", "Индикаторы компрометации", "Бұзылу индикаторлары"}, "attachments": {"Attachments (static inspection)", "Вложения (статическая проверка)", "Тіркемелер (статикалық тексеру)"}, "mitre": {"MITRE ATT&CK (suspected)", "MITRE ATT&CK (предположительно)", "MITRE ATT&CK (болжам)"}, "explanation": {"Explanation", "Объяснение", "Түсіндірме"}, "recommendations": {"Recommendations", "Рекомендации", "Ұсыныстар"}, "limitations": {"Limitations", "Ограничения", "Шектеулер"}, "synthetic": {"SYNTHETIC DEMO — no model executed", "СИНТЕТИЧЕСКИЙ ПРИМЕР — модель не запускалась", "ЖАСАНДЫ МЫСАЛ — модель іске қосылмаған"}, "legitimate": {"Legitimate (not a safety guarantee)", "Легитимное (не гарантия безопасности)", "Заңды (қауіпсіздік кепілдігі емес)"}, "suspicious": {"Suspicious", "Подозрительное", "Күдікті"}, "phishing": {"Phishing", "Фишинг", "Фишинг"}, "inconclusive": {"Inconclusive", "Недостаточно данных", "Деректер жеткіліксіз"}, "low": {"Low", "Низкий", "Төмен"}, "medium": {"Medium", "Средний", "Орташа"}, "high": {"High", "Высокий", "Жоғары"}, "critical": {"Critical", "Критический", "Аса жоғары"}}
	index := 0
	if lang == "ru" {
		index = 1
	} else if lang == "kk" {
		index = 2
	}
	if values, ok := labels[key]; ok {
		return values[index]
	}
	return key
}
