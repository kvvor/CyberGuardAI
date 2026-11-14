import i18n from "./index";
const messages = {
  register: ["Create Account", "Создать аккаунт", "Тіркелгі жасау"],
  display_name: ["Display name", "Имя", "Аты-жөні"],
  backToLogin: ["Back to sign in", "Вернуться ко входу", "Кіру бетіне оралу"],
  nameRequirements: ["Enter a name without control characters, up to 200 UTF-8 bytes.", "Введите имя без управляющих символов, не более 200 байт UTF-8.", "Басқару таңбалары жоқ, 200 UTF-8 байттан аспайтын ат енгізіңіз."],
  registrationAccepted: ["Registration request accepted. Sign in with your credentials. If you already have an account, use your existing password.", "Запрос на регистрацию принят. Войдите со своими данными. Если аккаунт уже существует, используйте прежний пароль.", "Тіркелу сұрауы қабылданды. Өз деректеріңізбен кіріңіз. Тіркелгіңіз бұрыннан бар болса, қазіргі құпиясөзіңізді пайдаланыңыз."],
  REGISTRATION_DISABLED: ["Website registration is currently disabled. Contact your account operator.", "Регистрация на сайте отключена. Обратитесь к оператору.", "Сайтта тіркелу қазір өшірулі. Операторға хабарласыңыз."],
  INVALID_REGISTRATION_INPUT: ["Check your name, email and password. Use a stronger passphrase and matching confirmation.", "Проверьте имя, почту и пароль. Используйте надёжную парольную фразу и совпадающее подтверждение.", "Атыңызды, поштаңызды және құпиясөзіңізді тексеріңіз. Сенімді құпиясөз енгізіп, оны дәл растаңыз."],
  UNSUPPORTED_MEDIA_TYPE: ["The server could not accept this request format. Please retry.", "Сервер не принял формат запроса. Повторите попытку.", "Сервер сұрау пішімін қабылдамады. Қайталап көріңіз."]
};
for (const [index, lang] of ["en", "ru", "kk"].entries()) i18n.addResourceBundle(lang, "translation", Object.fromEntries(Object.entries(messages).map(([key, values]) => [key, values[index]])), true, true);
