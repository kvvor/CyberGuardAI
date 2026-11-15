package reports

// labels localizes presentation only (en, ru, kk). Forensic evidence and
// model prose are never translated here.
var labels = map[string][3]string{
	"title":                  {"Email security report", "Отчёт о проверке письма", "Хатты тексеру есебі"},
	"section_identity":       {"Analysis", "Анализ", "Талдау"},
	"section_email":          {"Email", "Письмо", "Хат"},
	"section_assessment":     {"Assessment", "Оценка", "Бағалау"},
	"section_providers":      {"Provider execution status", "Состояние провайдеров", "Провайдерлер күйі"},
	"section_supporting":     {"Supporting evidence", "Подтверждающие данные", "Растаушы деректер"},
	"section_contradictory":  {"Contradictory evidence", "Противоречащие данные", "Қайшы деректер"},
	"section_authentication": {"Email authentication (reported)", "Аутентификация письма (заявленная)", "Хат аутентификациясы (мәлімделген)"},
	"id":                     {"Report ID", "Идентификатор отчёта", "Есеп идентификаторы"},
	"date":                   {"Analysed at (UTC)", "Время анализа (UTC)", "Талдау уақыты (UTC)"},
	"email_date":             {"Email date (UTC, from header)", "Дата письма (UTC, из заголовка)", "Хат күні (UTC, тақырыптан)"},
	"source_type":            {"Source", "Источник", "Дереккөз"},
	"filename":               {"File name", "Имя файла", "Файл атауы"},
	"file_sha256":            {"Submitted file SHA-256", "SHA-256 загруженного файла", "Жүктелген файлдың SHA-256"},
	"subject":                {"Subject", "Тема", "Тақырып"},
	"sender":                 {"Sender (From)", "Отправитель (From)", "Жіберуші (From)"},
	"reply_to":               {"Reply-To", "Адрес ответа", "Жауап мекенжайы"},
	"recipients":             {"Recipients", "Получатели", "Алушылар"},
	"message_id":             {"Message-ID", "Message-ID", "Message-ID"},
	"verdict":                {"Verdict", "Вердикт", "Қорытынды"},
	"severity":               {"Severity", "Серьёзность", "Маңыздылық"},
	"confidence":             {"Confidence (qualitative)", "Уверенность (качественная)", "Сенімділік (сапалық)"},
	"confidence_notice":      {"Verdict, severity and confidence are a model assessment of the evidence in this report. They are not a probability.", "Вердикт, серьёзность и уверенность — оценка модели по данным этого отчёта. Это не вероятность.", "Қорытынды, маңыздылық және сенімділік — осы есептегі деректер бойынша модель бағасы. Бұл ықтималдық емес."},
	"incomplete_notice":      {"Assessment incomplete: no AI verdict was produced. The technical evidence below was still extracted.", "Оценка не завершена: вердикт ИИ не получен. Технические данные ниже извлечены.", "Бағалау аяқталмады: ЖИ қорытындысы алынбады. Төмендегі техникалық деректер алынды."},
	"legacy_notice":          {"Historical report created by the earlier rule-weight detector. Its score is not a probability and is not comparable with current assessments.", "Исторический отчёт прежнего детектора с весами правил. Его оценка не является вероятностью и несопоставима с текущими оценками.", "Ереже салмақтары бар бұрынғы детектордың тарихи есебі. Оның бағасы ықтималдық емес және қазіргі бағалаулармен салыстырылмайды."},
	"risk":                   {"Legacy score / level", "Прежняя оценка / уровень", "Бұрынғы баға / деңгей"},
	"model":                  {"model", "модель", "модель"},
	"failure":                {"Reason", "Причина", "Себебі"},
	"summary":                {"Summary", "Краткое объяснение", "Қысқаша түсіндірме"},
	"recommendations":        {"Recommended actions", "Рекомендуемые действия", "Ұсынылатын әрекеттер"},
	"uncertainty":            {"Uncertainty stated by the model", "Неопределённость, указанная моделью", "Модель көрсеткен белгісіздік"},
	"quote_notice":           {"quoted text verified, interpretation by the model", "цитата проверена, интерпретация модели", "дәйексөз тексерілді, түсіндірме модельдікі"},
	"authentication_notice":  {"Results are what the uploaded headers report. CyberGuard did not repeat SPF, DKIM or DMARC checks; uploaded headers can be forged.", "Результаты взяты из заголовков загруженного письма. CyberGuard не повторял проверки SPF, DKIM и DMARC; заголовки могут быть подделаны.", "Нәтижелер жүктелген хат тақырыптарынан алынған. CyberGuard SPF, DKIM, DMARC тексерулерін қайталаған жоқ; тақырыптар жалған болуы мүмкін."},
	"reputation_notice":      {"An unknown hash or zero detections is not proof that a file is safe. Files are never uploaded; only hashes are looked up.", "Неизвестный хеш или ноль обнаружений не доказывают безопасность файла. Файлы не загружаются; проверяются только хеши.", "Белгісіз хеш немесе нөл анықтау файлдың қауіпсіздігін дәлелдемейді. Файлдар жүктелмейді; тек хештер тексеріледі."},
	"indicators":             {"Technical observations (not verdicts)", "Технические наблюдения (не вердикты)", "Техникалық бақылаулар (қорытынды емес)"},
	"iocs":                   {"Indicators (defanged)", "Индикаторы (обезвреженная запись)", "Индикаторлар (залалсыздандырылған)"},
	"omitted_resources":      {"%d embedded resources (images, style sheets, tracking pixels) or further entries are not listed here; they remain in the JSON export.", "%d встроенных ресурсов (изображения, стили, пиксели отслеживания) или прочих записей здесь не показаны; они есть в JSON-экспорте.", "%d ендірілген ресурс (суреттер, стильдер, бақылау пиксельдері) немесе басқа жазбалар мұнда көрсетілмеген; олар JSON экспортында бар."},
	"attachments":            {"Attachments and reputation", "Вложения и репутация", "Тіркемелер және бедел"},
	"malicious":              {"malicious", "вредоносных", "зиянды"},
	"suspicious_count":       {"suspicious", "подозрительных", "күдікті"},
	"harmless":               {"harmless", "безвредных", "зиянсыз"},
	"undetected":             {"undetected", "без обнаружения", "анықталмаған"},
	"last_analysis":          {"last provider analysis", "последний анализ провайдера", "провайдердің соңғы талдауы"},
	"limitations":            {"Limitations and missing evidence", "Ограничения и отсутствующие данные", "Шектеулер және жетіспейтін деректер"},
	"explanation":            {"Explanation", "Объяснение", "Түсіндірме"},
	"bytes":                  {"bytes", "байт", "байт"},
	"none":                   {"None", "Нет", "Жоқ"},
	"not_provided":           {"not provided", "не предоставлено", "берілмеген"},
	"footer":                 {"Generated by CyberGuard AI. Automated analysis supports, and does not replace, a human security decision.", "Создано CyberGuard AI. Автоматический анализ помогает принять решение, но не заменяет специалиста.", "CyberGuard AI жасаған. Автоматты талдау маманның шешімін алмастырмайды, тек көмектеседі."},

	"legitimate":   {"Legitimate (not a safety guarantee)", "Легитимное (не гарантия безопасности)", "Заңды (қауіпсіздік кепілдігі емес)"},
	"suspicious":   {"Suspicious", "Подозрительное", "Күдікті"},
	"phishing":     {"Phishing", "Фишинг", "Фишинг"},
	"inconclusive": {"Inconclusive", "Недостаточно данных", "Деректер жеткіліксіз"},
	"low":          {"Low", "Низкая", "Төмен"},
	"medium":       {"Medium", "Средняя", "Орташа"},
	"high":         {"High", "Высокая", "Жоғары"},
	"critical":     {"Critical", "Критическая", "Аса жоғары"},

	"status_completed":              {"completed", "выполнено", "орындалды"},
	"status_partial":                {"partly completed", "выполнено частично", "ішінара орындалды"},
	"status_not_requested":          {"not requested", "не запрошено", "сұралмаған"},
	"status_not_configured":         {"not configured", "не настроено", "бапталмаған"},
	"status_skipped_no_attachments": {"no attachments to check", "нет вложений для проверки", "тексеретін тіркеме жоқ"},
	"status_not_found":              {"hash unknown to the provider", "хеш неизвестен провайдеру", "хеш провайдерге белгісіз"},
	"status_authentication_failed":  {"credentials rejected", "ключ отклонён", "кілт қабылданбады"},
	"status_access_forbidden":       {"access denied", "доступ запрещён", "қолжетімділікке тыйым салынған"},
	"status_quota_exceeded":         {"quota exhausted", "квота исчерпана", "квота таусылды"},
	"status_deferred_local_limit":   {"not sent: local request allowance reached", "не отправлено: исчерпан локальный лимит запросов", "жіберілмеді: жергілікті сұраулар шегіне жетті"},
	"status_rate_limited":           {"request limit reached", "достигнут лимит запросов", "сұраулар шегіне жетті"},
	"status_unsupported_model":      {"model unavailable or unsupported", "модель недоступна или не поддерживается", "модель қолжетімсіз немесе қолдау жоқ"},
	"status_invalid_response":       {"response rejected by validation", "ответ отклонён проверкой", "жауап тексеруден өтпеді"},
	"status_timeout":                {"timed out", "время ожидания истекло", "күту уақыты аяқталды"},
	"status_network_error":          {"network error", "ошибка сети", "желі қатесі"},
	"status_provider_error":         {"provider error", "ошибка провайдера", "провайдер қатесі"},

	"untrusted_reported": {"reported by an untrusted header", "заявлено недоверенным заголовком", "сенімсіз тақырыпта мәлімделген"},
	"trusted_reported":   {"reported by a configured receiving server", "заявлено настроенным принимающим сервером", "бапталған қабылдаушы сервер мәлімдеген"},
	"unavailable":        {"not available", "недоступно", "қолжетімсіз"},
	"unable_to_verify":   {"not independently verified", "независимо не проверено", "тәуелсіз тексерілмеген"},
	"verified":           {"independently verified", "независимо проверено", "тәуелсіз тексерілген"},

	"AUTHENTICATION_NOT_INDEPENDENTLY_VERIFIED":      {"SPF, DKIM and DMARC were not independently verified.", "SPF, DKIM и DMARC независимо не проверялись.", "SPF, DKIM және DMARC тәуелсіз тексерілмеді."},
	"MISSING_EMAIL_HEADERS":                          {"Transport headers are missing; sender and routing cannot be assessed.", "Транспортные заголовки отсутствуют; отправителя и маршрут оценить нельзя.", "Тасымалдау тақырыптары жоқ; жіберуші мен маршрутты бағалау мүмкін емес."},
	"MISSING_SENDER":                                 {"The sender is missing.", "Отправитель отсутствует.", "Жіберуші көрсетілмеген."},
	"MSG_PARTIAL_EVIDENCE":                           {"Outlook MSG files may not contain the original headers.", "Файлы Outlook MSG могут не содержать исходных заголовков.", "Outlook MSG файлдарында бастапқы тақырыптар болмауы мүмкін."},
	"MSG_SENDER_NOT_SMTP_ADDRESS":                    {"The MSG file stores an internal Exchange address instead of an SMTP address.", "В MSG сохранён внутренний адрес Exchange вместо SMTP-адреса.", "MSG файлында SMTP мекенжайының орнына ішкі Exchange мекенжайы сақталған."},
	"MSG_TRANSPORT_HEADERS_UNREADABLE":               {"Transport headers in the MSG file could not be parsed.", "Транспортные заголовки в MSG не удалось разобрать.", "MSG файлындағы тасымалдау тақырыптары талданбады."},
	"EMBEDDED_MSG_NOT_ANALYZED":                      {"An embedded message was not analysed.", "Вложенное сообщение не анализировалось.", "Ендірілген хат талданбады."},
	"UNSUPPORTED_CHARSET":                            {"A part uses an unsupported character set.", "Часть письма использует неподдерживаемую кодировку.", "Хат бөлігі қолдау көрсетілмейтін кодтауды пайдаланады."},
	"UNSUPPORTED_MIME_PART":                          {"A part of an unsupported type was not analysed.", "Часть неподдерживаемого типа не анализировалась.", "Қолдау көрсетілмейтін түрдегі бөлік талданбады."},
	"MODEL_INPUT_TRUNCATED":                          {"Long content was shortened before assessment.", "Длинное содержимое сокращено перед оценкой.", "Ұзын мазмұн бағалау алдында қысқартылды."},
	"MODEL_IOCS_TRUNCATED":                           {"Only part of the indicators was sent for assessment.", "Для оценки передана часть индикаторов.", "Бағалауға индикаторлардың бір бөлігі жіберілді."},
	"MODEL_LINKS_TRUNCATED":                          {"Only part of the links was sent for assessment.", "Для оценки передана часть ссылок.", "Бағалауға сілтемелердің бір бөлігі жіберілді."},
	"HEADER_EVIDENCE_TRUNCATED":                      {"Only part of the repeated headers was kept.", "Сохранена часть повторяющихся заголовков.", "Қайталанатын тақырыптардың бір бөлігі сақталды."},
	"IOC_LIMIT_REACHED":                              {"The indicator limit was reached; further indicators were not recorded.", "Достигнут лимит индикаторов; остальные не записаны.", "Индикаторлар шегіне жетті; қалғандары жазылмады."},
	"REPUTATION_UPDATED_AFTER_ASSESSMENT":            {"Attachment reputation was updated after the verdict was produced; the verdict does not reflect it.", "Репутация вложений обновлена после получения вердикта; вердикт её не учитывает.", "Тіркеме беделі қорытындыдан кейін жаңартылды; қорытынды оны ескермейді."},
	"UPLOADED_HEADERS_CAN_BE_FORGED":                 {"Uploaded headers can be forged.", "Заголовки загруженного письма могут быть подделаны.", "Жүктелген хат тақырыптары жалған болуы мүмкін."},
	"NO_REPORTED_RESULT":                             {"No result was reported.", "Результат не заявлен.", "Нәтиже мәлімделмеген."},
	"DKIM_SIGNATURE_PRESENT_NOT_VERIFIED":            {"A DKIM signature is present but was not verified.", "Подпись DKIM присутствует, но не проверялась.", "DKIM қолтаңбасы бар, бірақ тексерілмеді."},
	"AI_CONSENT_REQUIRED":                            {"Consent to send evidence to OpenAI was not given.", "Согласие на передачу данных OpenAI не дано.", "Деректерді OpenAI-ға жіберуге келісім берілмеді."},
	"PROVIDER_NOT_CONFIGURED":                        {"OpenAI is not configured.", "OpenAI не настроен.", "OpenAI бапталмаған."},
	"PROVIDER_DISABLED":                              {"OpenAI is configured but disabled.", "OpenAI настроен, но отключён.", "OpenAI бапталған, бірақ өшірілген."},
	"PROVIDER_INVALID_CREDENTIALS":                   {"OpenAI rejected the API key.", "OpenAI отклонил API-ключ.", "OpenAI API кілтін қабылдамады."},
	"PROVIDER_ACCESS_DENIED":                         {"OpenAI denied access for this key.", "OpenAI отказал в доступе для этого ключа.", "OpenAI осы кілтке қолжетімділік бермеді."},
	"PROVIDER_CREDENTIAL_UNREADABLE":                 {"The saved key cannot be decrypted with the current server key.", "Сохранённый ключ не расшифровывается текущим ключом сервера.", "Сақталған кілт сервердің қазіргі кілтімен ашылмайды."},
	"PROVIDER_INSUFFICIENT_QUOTA":                    {"The OpenAI quota or balance is exhausted.", "Квота или баланс OpenAI исчерпаны.", "OpenAI квотасы немесе балансы таусылды."},
	"PROVIDER_RATE_LIMITED":                          {"OpenAI rate limit reached.", "Достигнут лимит запросов OpenAI.", "OpenAI сұраулар шегіне жетті."},
	"PROVIDER_UNSUPPORTED_MODEL":                     {"The selected model is unavailable or does not support this request.", "Выбранная модель недоступна или не поддерживает запрос.", "Таңдалған модель қолжетімсіз немесе сұрауды қолдамайды."},
	"PROVIDER_INVALID_OUTPUT":                        {"The model response failed validation and was discarded.", "Ответ модели не прошёл проверку и отброшен.", "Модель жауабы тексеруден өтпей, қабылданбады."},
	"PROVIDER_OUTPUT_TRUNCATED":                      {"The model response was cut off and discarded.", "Ответ модели оборван и отброшен.", "Модель жауабы үзіліп, қабылданбады."},
	"PROVIDER_REFUSED":                               {"The model declined to answer.", "Модель отказалась отвечать.", "Модель жауап беруден бас тартты."},
	"PROVIDER_UNSUPPORTED_CLAIM":                     {"The model stated something the evidence does not support; the response was discarded.", "Модель заявила то, что не подтверждается данными; ответ отброшен.", "Модель деректермен расталмайтын мәлімдеме жасады; жауап қабылданбады."},
	"PROVIDER_TIMEOUT":                               {"OpenAI did not answer in time.", "OpenAI не ответил вовремя.", "OpenAI уақытында жауап бермеді."},
	"PROVIDER_NETWORK_FAILURE":                       {"OpenAI could not be reached.", "Нет соединения с OpenAI.", "OpenAI-ға қосылу мүмкін болмады."},
	"PROVIDER_ERROR":                                 {"OpenAI returned a service error.", "OpenAI вернул ошибку сервиса.", "OpenAI қызмет қатесін қайтарды."},
	"PROVIDER_REQUEST_REJECTED":                      {"OpenAI rejected the request.", "OpenAI отклонил запрос.", "OpenAI сұрауды қабылдамады."},
	"PROVIDER_INPUT_TOO_LARGE":                       {"The evidence is too large for the model.", "Данные слишком велики для модели.", "Деректер модель үшін тым үлкен."},
	"PROVIDER_ENCRYPTION_UNAVAILABLE":                {"The server encryption key is missing or invalid.", "Ключ шифрования сервера отсутствует или неверен.", "Сервердің шифрлау кілті жоқ немесе жарамсыз."},
	"PROVIDER_CONFIGURATION_UNAVAILABLE":             {"Provider settings could not be read.", "Не удалось прочитать настройки провайдера.", "Провайдер баптаулары оқылмады."},
	"REPLY_TO_DOMAIN_DIFFERS":                        {"Reply-To uses a different domain than From", "Домен Reply-To отличается от домена From", "Reply-To домені From доменінен өзгеше"},
	"RETURN_PATH_DOMAIN_DIFFERS":                     {"Return-Path uses a different domain than From", "Домен Return-Path отличается от домена From", "Return-Path домені From доменінен өзгеше"},
	"PUNYCODE_SENDER_DOMAIN":                         {"Sender domain is an internationalised (punycode) name", "Домен отправителя записан в punycode", "Жіберуші домені punycode түрінде"},
	"DISPLAY_NAME_CONTAINS_OTHER_ADDRESS":            {"Display name shows a different email address", "В отображаемом имени указан другой адрес", "Көрсетілетін атауда басқа мекенжай бар"},
	"REPORTED_AUTHENTICATION_FAILURE":                {"A header reports an authentication failure", "Заголовок сообщает об ошибке аутентификации", "Тақырып аутентификация қатесін мәлімдейді"},
	"TEXT_ADDRESSED_TO_AUTOMATED_ANALYSIS":           {"Text addressed to an automated analyser", "Текст, адресованный автоматическому анализатору", "Автоматты талдағышқа арналған мәтін"},
	"LINK_TO_IP_ADDRESS":                             {"Link points to an IP address", "Ссылка ведёт на IP-адрес", "Сілтеме IP мекенжайына апарады"},
	"URL_WITH_EMBEDDED_CREDENTIALS":                  {"URL contains a user name part", "URL содержит часть с именем пользователя", "URL-де пайдаланушы аты бөлігі бар"},
	"PUNYCODE_LINK_HOST":                             {"Link host is an internationalised (punycode) name", "Хост ссылки записан в punycode", "Сілтеме хосты punycode түрінде"},
	"LINK_TEXT_SHOWS_DIFFERENT_HOST":                 {"Visible link text shows a different host than the destination", "Видимый текст ссылки показывает другой хост", "Сілтеменің көрінетін мәтіні басқа хостты көрсетеді"},
	"HTML_FORM_SUBMITS_TO_URL":                       {"HTML form submits data to a URL", "HTML-форма отправляет данные на URL", "HTML пішіні деректерді URL-ге жібереді"},
	"HTML_FORM_PRESENT":                              {"HTML form present", "Присутствует HTML-форма", "HTML пішіні бар"},
	"HTML_REFERENCES_SCRIPT":                         {"HTML references a script", "HTML ссылается на скрипт", "HTML скриптке сілтеме жасайды"},
	"ATTACHMENT_TYPE_DIFFERS_FROM_DECLARED":          {"Attachment content differs from its declared type", "Содержимое вложения отличается от заявленного типа", "Тіркеме мазмұны мәлімделген түрден өзгеше"},
	"EXECUTABLE_ATTACHMENT_TYPE":                     {"Attachment has an executable file type", "Вложение исполняемого типа", "Тіркеме орындалатын файл түрінде"},
	"EXECUTABLE_BEHIND_DOCUMENT_EXTENSION":           {"Executable file name imitates a document", "Имя исполняемого файла имитирует документ", "Орындалатын файл атауы құжатқа ұқсатылған"},
	"MACRO_CAPABLE_DOCUMENT":                         {"Document format can contain macros", "Формат документа может содержать макросы", "Құжат пішімінде макростар болуы мүмкін"},
	"ARCHIVE_CONTENT_NOT_INSPECTED":                  {"Archive content was not inspected", "Содержимое архива не проверялось", "Мұрағат мазмұны тексерілмеді"},
	"HTML_ATTACHMENT":                                {"HTML or SVG attachment", "Вложение HTML или SVG", "HTML немесе SVG тіркемесі"},
	"REPORTED_BY_CONFIGURED_RECEIVER_NOT_REVERIFIED": {"Reported by a configured receiving server; not re-verified.", "Заявлено настроенным сервером; повторно не проверялось.", "Бапталған сервер мәлімдеген; қайта тексерілмеген."},
}

// Label returns the localized label, or the key itself for unknown codes so
// that historical reports with retired codes remain readable.
func Label(lang, key string) string {
	index := 0
	if lang == "ru" {
		index = 1
	} else if lang == "kk" {
		index = 2
	}
	if values, ok := labels[key]; ok {
		return values[index]
	}
	if len(key) > 7 && key[:7] == "status_" {
		return key[7:]
	}
	return key
}

// Keys lists every label key; used by tests that check translation coverage.
func Keys() []string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	return keys
}
