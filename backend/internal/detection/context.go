package detection

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
