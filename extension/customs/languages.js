// languages.js: text in languages other than English.
//
// The text rules in rules.js read English. Two checks here cover other languages:
//
//   1. Requests for card details or passwords in ten widely used languages: Spanish,
//      French, German, Portuguese, Italian, Russian, Chinese, Japanese, Hindi and Arabic.
//      A sentence counts when it has a request word and a secret word and no negation
//      word at all, so "never ask for passwords" in any of them is not read as a request.
//      Rules.js reports these as C-SECRETS, the same as in English.
//   2. Sentences that are not clearly English, whatever the language. The English rules
//      cannot read them, so rules.js holds the network for a person to look at (C-LANGUAGE).
//      english-words.js holds the common English words this check counts.
//
// Both run on text that normalizeForRules has already cleaned.

import { isEnglishWord } from "./english-words.js";

// Whole words: no letter, mark or digit right before or after. JavaScript's \b only
// knows ASCII letters, so it would split "contraseña" after the "ñ".
const EDGE_BEFORE = "(?<![\\p{L}\\p{M}\\p{N}])";
const EDGE_AFTER = "(?![\\p{L}\\p{M}\\p{N}])";
const words = (...parts) => new RegExp(`${EDGE_BEFORE}(?:${parts.join("|")})${EDGE_AFTER}`, "iu");
// Chinese and Japanese put no spaces between words, so their patterns match anywhere.
const anywhere = (...parts) => new RegExp(`(?:${parts.join("|")})`, "iu");

// Some request verbs also describe the visitor asking: "si el visitante pide ayuda con su
// contraseña" ("if the visitor asks for help with their password"). These count only when
// no subject, "if", "when" or article comes right before them.
const notAfter = (list) => `(?<!(?:${list}) )`;
// Infinitives after "wants to", "can" or "to" describe the visitor too: "si el cliente
// quiere pedir ayuda con su contraseña".
const ES_NOT_AFTER = notAfter("si|cuando|que|quien|quienes|visitante|visitantes|usuario|usuarios|cliente|clientes|alguien|persona|él|ella|ellos|ellas|le|les|se|lo|la|una|cada|quiere|quieren|puede|pueden|necesita|necesitan|desea|desean|suele|suelen|para|al|va a|van a");
const PT_NOT_AFTER = notAfter("se|quando|que|quem|visitante|visitantes|usu[aá]rio|usu[aá]rios|utilizador|cliente|clientes|algu[eé]m|pessoa|ele|ela|eles|elas|lhe|lhes|uma|cada|quer|querem|pode|podem|precisa|precisam|deseja|desejam|costuma|costumam|para|ao|vai|v[aã]o");
const FR_NOT_AFTER = notAfter("si|quand|qui|que|visiteur|visiteuse|visiteurs|utilisateur|utilisatrice|utilisateurs|client|cliente|clients|quelqu'un|personne|il|elle|ils|elles|on|la|une|chaque|ta|sa|ma|votre|leur|cette|ce|toute|nouvelle|aucune|à|de|pour|veut|veulent|peut|peuvent|souhaite|souhaitent|voudrait|aimerait");
const IT_NOT_AFTER = notAfter("se|quando|che|chi|visitatore|visitatrice|utente|utenti|cliente|clienti|qualcuno|persona|lui|lei|loro|gli|le|si|una|ogni|vuole|vogliono|pu[oò]|possono|desidera|desiderano|per|di|a");
const DE_NOT_AFTER = notAfter("ich|er|sie|es|man|wer|besucher|besucherin|nutzer|nutzerin|kunde|kundin|kunden|jemand|die|eine|jede|jeder|deine|ihre|seine|keine|diese|welche|der|einer|deiner|ihrer|seiner|unsere|unserer");
const ZH_NOT_AFTER = "(?<!(?:用户|用戶|访客|訪客|客户|客戶|顾客|顧客|他们|他們|她们|她們|他|她|对方|對方|有人|别人|別人|如果|若))";

/**
 * Request words, secret words and negation words for each language with full requests
 * checked. Words that are also nouns ("pregunta" is a question, "Frage" too) count
 * only in their request form. Verbs such as "obtain" are left out: "para obtener una
 * nueva contraseña" ("to get a new password") is ordinary help.
 */
export const SECRET_LANGUAGES = [
  {
    code: "es", name: "Spanish",
    asks: words(
      `${ES_NOT_AFTER}(?:p[ií]d[ae]n?|solicit[ae]n?|exig[ea]|exijan?|recopil[ae]n?|recog[ea]|recojan?|pregunten?|pregunta (?:al|a la|a los|a las|a su|a tu|por|si|cu[aá]l|qu[eé])|pedir(?:le|les)?|preguntar(?:le|les)?|solicitar(?:le|les)?|exigir(?:le|les)?|recopilar)`,
      "p[ií]d[ae]le(?:s)?", "preg[uú]nt[ae]le(?:s)?", "solicit[ae]le(?:s)?",
      "dame", "danos", "d[eé]me", "d[eé]nos", "dime", "d[ií]game", "d[ií]ganos",
      "env[ií]ame", "env[ií]anos", "env[ií]eme", "env[ií]enos", "m[aá]ndame", "m[aá]ndeme", "d[ií]ctame", "d[ií]cteme", "p[aá]same",
      "(?:introduzca|ingrese|escriba|teclee|env[ií]e|comparta|proporcione|facilite|dicte|indique|confirme) (?:su|sus)",
      "(?:introduce|ingresa|escribe|teclea|env[ií]a|comparte|proporciona|facilita|dicta|indica|confirma) (?:tu|tus)",
      "que (?:te |le |nos |me )?(?:dé|diga|dicte|env[ií]e|escriba|introduzca|ingrese|proporcione|comparta|facilite|lea|teclee)",
      "necesit(?:o|amos|as|a) (?:su|tu|sus|tus)", "ha(?:z|ga) que",
    ),
    secrets: words(
      "n[uú]meros? de (?:la |su |tu |sus |tus )?tarjetas?", "datos de (?:la |su |tu )?tarjeta",
      "c[oó]digos? (?:de seguridad|cvv|cvc|pin|de verificaci[oó]n|de confirmaci[oó]n|otp|de un solo uso|secreto|de acceso)",
      "cvv2?", "cvc", "contrase[ñn]as?", "claves? (?:de acceso|secretas?|bancarias?|personal(?:es)?|de la tarjeta)",
      "(?:su|tu|sus|tus) claves?", "pin", "otp", "fecha de (?:caducidad|vencimiento|expiraci[oó]n)",
      "credenciales", "usuario y contrase[ñn]a", "datos de acceso",
    ),
    negations: [words("no", "nunca", "jam[aá]s", "ni", "sin", "tampoco", "ning[uú]n", "ninguna", "ninguno", "prohibido", "evit[ae]")],
  },
  {
    code: "pt", name: "Portuguese",
    asks: words(
      `${PT_NOT_AFTER}(?:pe[cç]am? (?:ao|à|aos|às|a|o|os|as|para|que|seu|sua|seus|suas)|perguntem?|pergunta (?:ao|à|aos|às|por|se|qual)|solicitem?|exijam?|coletem?|recolham?|pedir(?:-lhes?)?|perguntar(?:-lhes?)?|solicitar(?:-lhes?)?|exigir|coletar|recolher)`,
      "pe[cç]a-lhes?", "pergunte-lhes?", "solicite-lhes?",
      "me dê", "nos dê", "dê-(?:me|nos)", "diga-(?:me|nos)", "(?:me|nos) diga", "envie-(?:me|nos)", "(?:me|nos) envie",
      "(?:me|nos) passe", "passe-(?:me|nos)", "(?:me|nos) informe", "informe-(?:me|nos)", "dite-(?:me|nos)", "(?:me|nos) dite",
      "(?:digite|insira|introduza|informe|forne[cç]a|envie|compartilhe|partilhe|confirme|dite|indique) (?:o seu|a sua|os seus|as suas|seu|sua|seus|suas|o|a)",
      "fa[cç]a (?:com )?que", "precis(?:o|amos) d[oa] (?:seu|sua)",
    ),
    secrets: words(
      "n[uú]meros? d[oe] (?:seu |sua )?cart[aã]o", "dados d[oe] (?:seu |sua )?cart[aã]o",
      "c[oó]digos? (?:de seguran[cç]a|cvv|cvc|pin|de verifica[cç][aã]o|de confirma[cç][aã]o|otp|de uso [uú]nico|de acesso)",
      "cvv2?", "cvc", "senhas?", "pin", "otp", "validade do cart[aã]o", "data de validade",
      "credenciais", "usu[aá]rio e senha", "dados de acesso", "token (?:do banco|banc[aá]rio)",
    ),
    negations: [words("n[aã]o", "nunca", "jamais", "nem", "sem", "nenhum", "nenhuma", "proibido", "evite")],
  },
  {
    code: "fr", name: "French",
    asks: words(
      `${FR_NOT_AFTER}(?:demande[sz]? (?:au|à|aux|le|la|les|l'|son|sa|ses|leur|leurs|votre|vos|ton|ta|tes|si|quel|quelle|quels|quelles|lui)|demandez|demander|exige[sz]?|exigez|exiger|sollicite[sz]?|sollicitez|solliciter|recueille[sz]?|recueillez|recueillir|collecte[sz]?|collectez|collecter|r[eé]clame[sz]?|r[eé]clamez|r[eé]clamer)`,
      "demande[sz]?-(?:lui|leur)", "demandons",
      "(?:donne|donnez|envoie|envoyez|dis|dites|communique|communiquez|transmets|transmettez|fournis|fournissez|dicte|dictez|lis|lisez|indique|indiquez|confirme|confirmez)[- ](?:moi|nous)",
      "(?:saisis|saisissez|tape|tapez|entrez|indiquez|communiquez|envoyez|fournissez|donnez|dictez|partagez|transmettez|confirmez) (?:votre|vos|ton|ta|tes|son|sa|ses|leur|leurs)",
      "fai(?:s|tes)[- ](?:lui|leur) (?:saisir|taper|donner|communiquer|dicter|lire|envoyer|indiquer|confirmer)",
      "pri[eè]re de (?:fournir|saisir|communiquer|donner|indiquer)",
    ),
    secrets: words(
      "num[eé]ros? de (?:la |sa |votre |ta |leur )?cartes?(?: bancaires?| de cr[eé]dit| de d[eé]bit)?",
      "donn[eé]es (?:de (?:la |sa |votre |ta |leur )?carte|bancaires)", "coordonn[eé]es bancaires",
      "codes? (?:de s[eé]curit[eé]|pin|secrets?|confidentiels?|de v[eé]rification|de confirmation|[aà] usage unique|otp|sms|d'acc[eè]s)",
      "cryptogrammes?(?: visuels?)?", "cvv2?", "cvc", "mots? de passe", "pin", "otp",
      "date d'expiration", "date de validit[eé]",
      "identifiants? (?:bancaires|de connexion|de banque en ligne)", "identifiants? et mots? de passe",
    ),
    negations: [words("ne", "pas", "jamais", "sans", "aucun", "aucune", "ni", "interdite?s?", "[eé]vite[rz]?"), /(?<![\p{L}\p{M}])n'/iu],
  },
  {
    code: "it", name: "Italian",
    asks: words(
      `${IT_NOT_AFTER}(?:chiedi|chieda|chiedete|chiedano|chiedere|richiedi|richieda|richiedete|richiedere|pretendi|pretenda|pretendere|esigi|esiga|esigere|raccogli|raccolga|raccogliere)`,
      "chiedigli", "chiedile", "chiedetegli", "chiedergli", "chiederle",
      "fa(?:tti|tevi) (?:dare|dire|dettare|inviare|mandare|comunicare|fornire|leggere)",
      "si faccia (?:dare|dire|dettare|inviare|mandare|comunicare|fornire)",
      "dammi", "dacci", "dimmi", "ditemi", "mandami", "inviami", "dettami", "comunicami", "forniscimi", "leggimi",
      "(?:mi|ci) (?:dia|dica|invii|mandi|detti|comunichi|fornisca)",
      "(?:inserisci|inserisca|digita|digiti|scrivi|scriva|invia|invii|comunica|comunichi|fornisci|fornisca|indica|indichi|conferma|confermi|detta|detti) (?:il tuo|la tua|i tuoi|le tue|il suo|la sua|i suoi|le sue|tuo|tua|suo|sua|il|la)",
    ),
    secrets: words(
      "numer[oi] (?:della |di |delle )(?:sua |tua |propria )?carta(?: di credito| di debito)?", "dati della (?:sua |tua )?carta",
      "codic[ei] (?:di sicurezza|pin|segret[oi]|di verifica|di conferma|otp|monouso|di accesso)",
      "cvv2?", "cvc", "password", "pin", "otp", "data di scadenza", "scadenza della carta",
      "credenziali", "nome utente e password", "dati di accesso",
    ),
    negations: [words("non", "mai", "senza", "n[eé]", "nessun[oa]?", "vietat[oaie]", "evita(?:re)?")],
  },
  {
    code: "de", name: "German",
    // Only the forms that give an order: "fragt" and "fragen" also describe the visitor
    // ("wenn der Besucher nach seinem Passwort fragt"), and "Frage" is also "question".
    asks: words(
      `${DE_NOT_AFTER}(?:frag|frage|erfrage|verlang|verlange|fordere|erbitte|sammle|notiere|erhebe)`,
      "(?:fragen|erfragen|verlangen|fordern|erbitten|sammeln|notieren|erheben) sie", "bitte (?:\\p{L}+ ){1,3}?um",
      "lass(?:t|en sie)? (?:dir|euch|sich|ihnen|uns|mir) (?:\\p{L}+ ){0,4}?(?:geben|nennen|sagen|schicken|senden|zeigen|diktieren|vorlesen|mitteilen|durchgeben)",
      "(?:gib|geben sie|nenne|nennen sie|sag|sage|sagen sie|schick|schicke|schicken sie|sende|senden sie|teile|teilen sie|diktiere|diktieren sie|lies|lesen sie) (?:mir|uns)",
      "(?:gib|geben sie|tippe|tippen sie|trage|tragen sie|nenne|nennen sie|sende|senden sie|schick|schicke|schicken sie|teile|teilen sie|best[aä]tige|best[aä]tigen sie) (?:deine|deinen|dein|deiner|ihre|ihren|ihr|ihrer|seine|seinen|sein|eure|euren)",
    ),
    // German joins words, so "Kreditkartennummer" holds "kartennummer".
    secrets: words(
      "\\p{L}*kartennummer\\p{L}*", "\\p{L}*kartendaten\\p{L}*", "\\p{L}*kartenpr[uü]f\\p{L}*", "pr[uü]fziffer\\p{L}*", "pr[uü]fnummer\\p{L}*",
      "\\p{L}*sicherheitscode\\p{L}*", "cvv2?", "cvc", "\\p{L}*passw[oö]rt\\p{L}*", "\\p{L}*kennw[oö]rt\\p{L}*",
      "pin(?:-?(?:nummer|code))?", "geheimzahl\\p{L}*", "tan", "\\p{L}*best[aä]tigungscode\\p{L}*", "einmal(?:code|passwort|kennwort)\\p{L}*",
      "\\p{L}*zugangsdaten", "\\p{L}*anmeldedaten", "login-?daten", "online-?banking-?(?:zugang|daten|passwort|pin|login|zugangsdaten)\\p{L}*",
      "(?:ablauf|g[uü]ltigkeits|verfalls)datum der (?:\\p{L}+ )?karte",
    ),
    negations: [words("nicht", "nie", "niemals", "kein", "keine", "keinen", "keinem", "keiner", "keines", "ohne", "nichts", "verboten", "keinesfalls", "vermeiden?")],
  },
  {
    code: "ru", name: "Russian",
    asks: words(
      "спроси(?:те)?", "спрашивай(?:те)?", "попроси(?:те)?", "запроси(?:те)?", "запрашивай(?:те)?",
      "потребуй(?:те)?", "требуй(?:те)?", "собери(?:те)?", "собирай(?:те)?", "выпроси(?:те)?",
      "пусть (?:\\p{L}+ ){0,3}?(?:введ[её]т|назов[её]т|сообщит|продиктует|отправит|скажет|напишет|пришл[её]т|укажет)",
      "(?:дай|дайте|скажи|скажите|сообщи|сообщите|назови|назовите|пришли|пришлите|отправь|отправьте|продиктуй|продиктуйте) (?:мне|нам)",
      "(?:введи|введите|укажи|укажите|назови|назовите|сообщи|сообщите|продиктуй|продиктуйте|пришли|пришлите|отправь|отправьте|напиши|напишите) (?:свой|свою|своё|свое|свои|ваш|вашу|ваше|ваши|твой|твою|твоё|твое|твои)",
    ),
    secrets: words(
      "номер\\p{L}* (?:\\p{L}+ ){0,2}?карт\\p{L}*", "данн\\p{L}* (?:\\p{L}+ )?карт\\p{L}*", "реквизит\\p{L}* (?:\\p{L}+ )?карт\\p{L}*",
      "cvv2?", "cvc", "cvv-код\\p{L}*", "код\\p{L}* безопасности", "парол\\p{L}*", "пин(?:-?код\\p{L}*)?", "pin(?:-?код\\p{L}*)?",
      "код\\p{L}* (?:из (?:смс|sms)|подтверждения)", "одноразов\\p{L}* (?:код|парол)\\p{L}*",
      "срок\\p{L}* действия (?:\\p{L}+ )?карт\\p{L}*", "логин\\p{L}* и парол\\p{L}*", "логин\\p{L}* от (?:\\p{L}+ )?банк\\p{L}*",
      "уч[её]тн\\p{L}* данн\\p{L}*", "данные для входа",
    ),
    negations: [words("не", "ни", "никогда", "нельзя", "без", "запрещено", "ничего", "избегай(?:те)?")],
  },
  {
    code: "zh", name: "Chinese",
    asks: anywhere(
      // "问" ("ask") alone, but not inside 询问, 提问 ("asks a question"), 访问 ("visit") or 问题 ("question").
      `${ZH_NOT_AFTER}(?:询问|詢問|(?<![询詢提疑访訪学學顾顧])(?:问|問)(?![题題候]))`, "索要", "索取", "收集",
      // "让/要求 X 提供" is X providing. "请告诉他们" ("please tell them") is the assistant
      // telling, so "请" counts only before "enter" or "fill in".
      "(?:让|讓|要求|叫)\\p{Script=Han}{0,4}?(?:提供|输入|輸入|告诉|告訴|发送|發送|填写|填寫|报出|報出|说出|說出|念出|给出|給出|发给|發給)",
      "(?:请|請)(?:您|你)?(?:输入|輸入|填写|填寫)",
      "告诉我", "告訴我", "发给我", "發給我", "报给我", "報給我",
    ),
    secrets: anywhere(
      "卡号", "卡號", "卡的号码", "卡的號碼", "卡片号码", "卡片號碼", "信用卡号码", "信用卡號碼", "银行卡号", "銀行卡號",
      "安全码", "安全碼", "验证码", "驗證碼", "cvv", "cvc", "密码", "密碼", "口令", "pin码", "pin碼", "动态码", "動態碼",
      "卡(?:片)?的?有效期", "网银的?(?:账号|密码|登录)", "網銀的?(?:帳號|密碼|登錄)", "登录信息", "登錄信息", "账号和密码", "帳號和密碼",
    ),
    negations: [anywhere("不", "别", "別", "勿", "禁止", "切勿", "绝不", "絕不", "从不", "從不", "无需", "無需", "没有", "沒有", "非")],
  },
  {
    code: "ja", name: "Japanese",
    // Request forms only: "ユーザーがパスワードについて聞いてきたら" is the visitor asking.
    asks: anywhere(
      "聞いてください", "聞いて下さい", "聞いてくれ", "聞いて$", "聞き出して", "聞き出せ", "聞け", "聞くこと",
      "尋ねてください", "尋ねること", "訊いてください", "求めてください", "求めること", "求めよ", "要求してください", "要求すること",
      "入力させ", "入力してもら", "入力してください", "教えてもら", "伝えてもら", "送ってもら", "送らせ",
      "提供してもら", "提供させ", "確認させ", "言わせ", "読み上げさせ", "収集して", "収集する",
    ),
    secrets: anywhere(
      "カード番号", "カードの番号", "クレジットカード番号", "セキュリティコード", "セキュリティーコード", "暗証番号", "パスワード",
      "認証コード", "確認コード", "ワンタイムパスワード", "cvv", "cvc", "カードの有効期限",
      "ネットバンキングの?(?:id|パスワード|ログイン)", "ログイン情報", "ログインid",
    ),
    negations: [anywhere("ない", "ません", "ないで", "禁止", "決して", "しないこと", "だめ", "ダメ", "いけない")],
  },
  {
    code: "hi", name: "Hindi",
    asks: words(
      "पूछें", "पूछो", "पूछिए", "पूछिये", "पूछना", "पूछ लें", "पूछ लो", "मांगें", "मांगो", "मांगिए", "मांगना", "मांग लें",
      "माँगें", "माँगो", "माँगिए", "माँगना", "माँग लें", "बताने को कहें", "बताने के लिए कहें", "दर्ज करवाएं", "दर्ज कराएं",
      "दर्ज करने को कहें", "डालने को कहें", "भेजने को कहें", "साझा करने को कहें", "शेयर करने को कहें", "इकट्ठा करें", "एकत्र करें",
    ),
    // "पिन कोड" is a postal code in India, so it does not count as a PIN.
    secrets: words(
      "कार्ड नंबर", "कार्ड संख्या", "कार्ड का नंबर", "कार्ड की संख्या", "कार्ड के नंबर", "कार्ड डिटेल्स", "कार्ड विवरण", "कार्ड की जानकारी",
      "सीवीवी", "cvv", "पिन(?! ?कोड)", "पासवर्ड", "ओटीपी", "otp", "सत्यापन कोड",
      "नेट ?बैंकिंग (?:लॉगिन|पासवर्ड|विवरण|आईडी)", "लॉगिन (?:विवरण|आईडी|डिटेल्स)", "यूपीआई पिन", "एटीएम पिन", "upi pin",
    ),
    negations: [words("नहीं", "न", "मत", "कभी", "बिना", "ना", "वर्जित", "मना")],
  },
  {
    code: "ar", name: "Arabic",
    // Arabic joins "and" (و), "so" (ف), "with" (ب) and "for" (ل) to the next word.
    // Orders only: "عندما يسأل الزائر" is the visitor asking.
    asks: words(
      "[وف]?(?:اطلب|اطلبي|اطلبوا|اسأل|اسألي|اسألوا|اجمع|اجمعي|اجمعوا)",
      "[وف]?(?:احصل|احصلي) على", "[وف]?(?:أعطني|اعطني|أعطنا|اعطنا|زودني|زوّدني|زودنا|زوّدنا|أخبرني|اخبرني|أخبرنا|اخبرنا)",
      "[وف]?(?:أرسل|ارسل) (?:لي|لنا)",
    ),
    secrets: words(
      "[وفبل]?(?:رقم|أرقام|ارقام) (?:ال)?بطاق\\p{L}*", "[وفبل]?بيانات (?:ال)?بطاق\\p{L}*", "[وفبل]?رمز (?:ال)?(?:أمان|امان|تحقق)\\p{L}*",
      "[وفبل]?كلم(?:ة|ات) (?:ال)?(?:مرور|سر)\\p{L}*", "[وفبل]?(?:ال)?(?:رقم|رمز) السري", "رمز (?:cvv|pin)", "cvv", "cvc", "otp",
      "رمز لمرة واحدة", "تاريخ انتهاء (?:صلاحية )?(?:ال)?بطاق\\p{L}*", "بيانات (?:تسجيل )?الدخول",
    ),
    negations: [words("[وف]?لا", "[وف]?لن", "[وف]?لم", "ليس", "أبدا", "أبداً", "ابدا", "دون", "بدون", "عدم", "ممنوع", "إياك", "اياك")],
  },
];

// Sentences end at these marks in the scripts above, or at a line break. A Latin full stop
// ends a sentence only before a space or the end, so web addresses and abbreviations stay whole.
const ABBREV_DOT = /\b(?:e\.g|i\.e|etc|vs|incl|approx|et\s+al|fig|vol|rev|est|ref)\.(?=\s|$)|\bno\.(?=\s+\d)/gi;
const SENTENCE_END = /[.!?;]+(?=\s|$)|[。！？；؟।\n]+/u;
const PARA_END = /[.!?;]+(?=\s|$)|[。！？；؟।]+|\n\s*\n+|\n(?=\s*(?:[-*•+]|\d+[.)]|#)\s)/u;

function maskAbbreviations(text) {
  const dots = [];
  const masked = text.replace(ABBREV_DOT, (m) => {
    dots.push(m);
    return `\u0000ABBR${dots.length - 1}\u0000`;
  });
  return { masked, unmask: (s) => s.replace(/\u0000ABBR(\d+)\u0000/g, (_, i) => dots[Number(i)]) };
}

function sentences(text) {
  const { masked, unmask } = maskAbbreviations(text);
  return masked.split(SENTENCE_END).map((s) => unmask(s).trim()).filter(Boolean);
}

// Soft-wrapped lines inside one paragraph (no blank line, no bullet) are joined so a
// line break mid-sentence does not hide a foreign request or split a short sentence.
function wrappedSentences(text) {
  const { masked, unmask } = maskAbbreviations(text);
  const joined = masked.replace(/([^\n.!?;:。！？；؟।])\n(?!\s*(?:[-*•+]|\d+[.)]|#)\s)/gu, "$1 ");
  return joined.split(PARA_END).map((s) => unmask(s).replace(/\s+/g, " ").trim()).filter(Boolean);
}

/**
 * Requests for card details or passwords in the ten languages above.
 *
 * :param normalized: Text from normalizeForRules.
 * :return: [{match, excerpt, language}] for each sentence with a request word, a secret
 *   word and no negation word.
 */
export function foreignSecretRequests(normalized) {
  const hits = [];
  const seen = new Set();
  for (const sentence of [...sentences(normalized), ...wrappedSentences(normalized)]) {
    for (const lang of SECRET_LANGUAGES) {
      const secret = sentence.match(lang.secrets);
      if (!secret || !lang.asks.test(sentence)) continue;
      if (lang.negations.some((re) => re.test(sentence))) continue;
      if (seen.has(sentence)) break;
      seen.add(sentence);
      hits.push({ match: secret[0], excerpt: sentence, language: lang.name });
      break;
    }
  }
  return hits;
}

// ---- Which language a sentence is in --------------------------------------------

// Common English function words. A sentence in English has several of them. "a" and
// "i" are left out: they are words in many languages (Spanish "a", Polish "i").
const ENGLISH = new Set(`the and of to in is it you that for on with as are be this your from at by or an not they we can
  will if do what all their has have any when which who our us them about only never always should must would could there these
  those then than into out up use its was were been how more other some such no so but may each also just me my he she his her
  him where why does did here after before because while very please anything something everything nothing`.split(/\s+/));
// The same without words that are also common in other languages (Spanish "no" and "me",
// German "in" and "so", Dutch "is", Polish "to"), for weighing English against them.
const STRONG_ENGLISH = new Set([...ENGLISH].filter((w) => !["no", "me", "he", "in", "on", "so", "do", "to", "is", "as", "an"].includes(w)));

// Common function words of other languages written in Latin letters. Words that are also
// English words ("a", "in", "is", "do", "die"...) are left out, except German "die",
// which is far more common in German than in English instructions.
const LATIN_LANGUAGES = {
  Spanish: "el la los las del al y que en por para con su sus es un una lo le les se como pero más este esta estos estas sin sobre cuando también usted ustedes tu tú muy hay ser está están cada todo todos todas nuestro nuestra siempre nunca qué cómo dónde porque ni ya aquí de",
  Portuguese: "os um uma não para com por sua seu seus suas da dos das na nos nas em é mas ou você vocês ao aos pelo pela pelos pelas muito também sempre nunca cada este esta isso isto essa esse está estão são ser ter tem foi como quando onde porque já aqui lhe de se pode deve",
  French: "le la les des du et est un une que qui pour dans sur avec pas ne il elle ils elles vous nous votre vos notre nos sa ses au aux ce cette ces mais ou où très leur leurs être sont été à y en se lui quand comme aussi tout tous toutes chaque jamais toujours ici de l qu j n c peut doit si",
  Italian: "il lo gli la le un una uno è che non con del della dei delle degli nel nella nei nelle al alla ai alle sono suo sua suoi sue ma anche ti si ci questo questa questi queste molto sempre mai ogni tutto tutti tutte vostro vostra nostro nostra essere hanno ha di da tra fra quando dove perché già qui se l c dell all nell sull dall puoi può devi deve ho hai abbiamo sei siamo",
  German: "der die das und ist nicht ein eine einen einem einer dem den des zu mit für auf sie ihr ihre ihren ihnen sich auch wie wenn oder aber bitte nach von bei dass daß werden wird kein keine sein seine seiner seinen ich wir uns unser unsere nur noch schon immer jeder jede jedes alle sind haben kann können soll sollen muss müssen im vom zum zur um dir dich mir mich du es nie niemals hier wo warum weil",
  Dutch: "het een en van niet dat die voor met zijn op te je uw hij zij ze maar ook als bij naar om er wat wordt worden kan moet deze dit onze ons geen nooit altijd alle de mijn jouw hun hier waar waarom omdat",
  Polish: "nie się że jest jak po co tak za od przez jego jej ich czy lub oraz dla ta te tylko już bardzo może są być aby który która które jeśli gdy proszę wszystkie zawsze nigdy na nas je potem teraz też także jeszcze twój twoja twoje pan pani bez przy przed pod albo",
  Turkish: "ve bir bu için ile değil çok ne ama gibi daha sonra olarak mı mi şu lütfen ya veya kadar sizin bizim onun bunu şey da de ki hiç asla ziyaretçi ziyaretçiye ziyaretçiden müşteri müşteriden müşteriye kullanıcı sor sorun sorunun iste isteyin verin şifre şifresi şifresini şifrenizi güvenlik kredi kart kartı kartını numara numarasını kod kodu kodunu pin atm hesap hesabı onay gönder",
  Indonesian: "dan yang di ke dari untuk dengan tidak ini itu adalah akan pada juga atau saya anda kami mereka kita sudah bisa harus tolong mohon jika kalau karena oleh sebagai ada telah jangan minta tanya tanyakan sebelum memesan pesan nomor kartu kredit pengunjung tamu kirim kirimkan berikan bagikan masukkan kata sandi kode keamanan pin atm rekening rahasia verifikasi tagihan",
  Swahili: "na ya wa kwa ni za katika hii kama lakini sana hapa hiyo wako yako wewe sisi tafadhali pia au kwamba",
  Tagalog: "ang ng sa mga ay hindi ko mo niya siya para ito iyan kayo tayo namin natin po ba lang din rin kung pag huwag",
  Vietnamese: "và của là không có được cho một những các này với người bạn trong khi đã sẽ đó để thì nếu hãy vui lòng",
  Romanian: "și în cu pe nu un este să din pentru sau dar mai ce acest această vă al ale lui ei sunt fi niciodată",
  Czech: "se na je že jako pro nebo jsou být který která které jeho její jejich prosím také není nikdy",
  Slovak: "sa na je že ako pre alebo sú byť ktorý ktorá ktoré jeho jej ich prosím aj nie nikdy",
  Swedish: "och att det som en på är av med den har inte om ett jag du vi ni kan ska eller från vid vår er din ditt sin sitt aldrig alltid be fråga gäst gästen besökare besökaren kund kunden kort kortet kortnummer kortnumret kreditkort lösenord säkerhetskod nummer snälla",
  Danish: "og det som en på er af med til den har ikke om et jeg du vi kan skal eller fra ved vores deres din dit sin sit hvis når aldrig altid bed spørg gæst gæsten besøgende kunde kunden kort kortet kortnummer kreditkort adgangskode sikkerhedskode nummer venligst",
  Norwegian: "og det som en på er av med til den har ikke om et jeg du vi kan skal eller fra ved vår deres din ditt sin sitt hvis når aldrig altid spør be gjest gjesten besøgende kunde kunden kort kortet kortnummer kredittkort passord sikkerhetskode nummer vennligst",
  Finnish: "ja ei se että oli mutta kun niin jos kuin tai myös ole olla sinun teidän meidän hänen heidän tämä tuo nämä joka mikä kaikki vain nyt koskaan aina",
  Hungarian: "az és hogy nem egy meg csak mint el ez azt ezt vagy kell már még sem nagyon minden kérem kérjük ön önt soha mindig",
  Croatian: "je da se na za od su ne sa kao ali ili što koji koja koje vas vaš vaša molimo može mora nije biti nikada uvijek",
  Albanian: "dhe në të një për nga që është nuk ju ose por edhe si kurrë",
  Catalan: "els les que amb una és dels seu seva però més aquest aquesta també mai sempre",
  Afrikaans: "die en van het nie wat op te vir met sy hy ons julle jou maar ook kan sal moet nooit altyd",
  Estonian: "ja ei et oli aga kui siis kas või ka teie meie tema nende kõik ainult mitte kunagi alati",
  Hausa: "da ba na ya ta ga cikin wannan kuma amma don shi ita su ku mu ne ce kada",
  Zulu: "futhi ukuthi kodwa uma noma ngoba wena thina bona ngicela cela isivakashi ikhasimende amakhasimende inombolo ikhadi yekhadi lasebhange ebhange iphasiwedi ikhodi iphinikhodi ye le ne",
  Somali: "iyo waan waa in uu ay ku ka la ma ahay tahay yahay si aad uga waxaa waxa weydii martida lambarka kaarka bangiga sirta furaha lacagta fadlan",
  Latvian: "un ir uz par ar kas ka lai bet vai jā nē es tu viņš viņa mēs jūs viņi šis tas tā kā arī pie līdz pēc savu mūsu jūsu lūdzu nav būs bija var ja kad tikai vēl jau ļoti visi kur",
  Lithuanian: "ir kad bet su į iš ne tai kaip jo jos jūs mes aš tu šis ta tas ar prašome prašau apie nuo už kas kur labai dar jau yra buvo bus savo mūsų jūsų jei kai tik visi",
  // Hindi and Urdu as many people type them, in Latin letters ("card ka number poochho").
  "Hindi written in Latin letters": "hai hain ka ki ke ko se mein aur ya nahi nahin kya kyun kaise kab kahan yeh ye woh wo unka unki unke apna apni apne uska uski uske mera meri mere tera teri tum aap hum kar karo karein karna kijiye dijiye batao bataiye poocho poochho puchho puchiye lijiye ho hota hoti tha thi raha rahi wala wali bhi sirf abhi jab tab agar toh liye liya gaya gayi chahiye sakte sakta sakti",
};
const LATIN_WORDS = Object.entries(LATIN_LANGUAGES).map(([name, list]) => [name, new Set(list.split(/\s+/))]);

// Scripts other than Latin, with the language a reader would name. Scripts written
// without spaces between words count each character as half a word.
const SCRIPTS = [
  ["Hiragana", "Japanese", true], ["Katakana", "Japanese", true], ["Han", "Chinese", true], ["Hangul", "Korean", true],
  ["Thai", "Thai", true], ["Lao", "Lao", true], ["Khmer", "Khmer", true], ["Myanmar", "Burmese", true], ["Tibetan", "Tibetan", true],
  ["Cyrillic", "Cyrillic script (such as Russian)", false], ["Greek", "Greek", false],
  ["Arabic", "Arabic script (such as Arabic, Persian or Urdu)", false], ["Hebrew", "Hebrew", false],
  ["Devanagari", "Devanagari script (such as Hindi)", false], ["Bengali", "Bengali", false], ["Tamil", "Tamil", false],
  ["Telugu", "Telugu", false], ["Kannada", "Kannada", false], ["Malayalam", "Malayalam", false], ["Gujarati", "Gujarati", false],
  ["Gurmukhi", "Punjabi", false], ["Oriya", "Odia", false], ["Sinhala", "Sinhala", false], ["Georgian", "Georgian", false],
  ["Armenian", "Armenian", false], ["Ethiopic", "Ethiopic script (such as Amharic)", false], ["Thaana", "Dhivehi", false],
].map(([script, name, dense]) => ({ name, dense, re: new RegExp(`\\p{Script=${script}}`, "gu") }));

// A Latin word: a Latin letter, then letters and accents. Accents alone (Hindi vowel
// signs are accents too) do not make a word.
const LATIN_WORD = /\p{Script=Latin}[\p{Script=Latin}\p{M}]*/gu;

// The name used for a sentence that is not English, in no language the lists know.
export const UNRECOGNISED = "a language Agent Customs doesn't recognise";

// Addresses, URIs, regexes, JSON snippets, file names and code identifiers are not
// words of any language.
const NOT_WORDS = new RegExp([
  /[a-z][a-z0-9+.-]*:\/\/\S+/.source,
  /\b[\w.+-]+@[\w-]+\.[\w.-]+/.source,
  /\b[\w-]+\.(?:com|org|net|io|dev|app|ai|ae|de|fr|nl|uk|eu|ru|jp|cn|br|au|ca|me|co|edu|gov|info|xyz|cloud|agency|now|ad|ml|json|yaml|yml|toml|html|htm|xml|svg|png|jpg|jpeg|webp|js|mjs|ts|tsx|jsx|py|rb|go|rs|java|cpp|css|md|txt|csv|pdf|zip|sh|sql)\b/.source,
  /\{[^{}\n"]{0,300}"[^"\n]{1,60}"\s*:[^}\n]{0,300}\}/.source,
  /\[(?:[^\]\s\\]|\\.)+\]/.source,
  /<\/?[a-zA-Z0-9_-]+[^>\n]{0,120}>|\{\{[^}\n]{1,120}\}\}/.source,
  /`[a-z0-9_.:\/-]+`/.source,
  /\b\w*_\w*\b|\b0x[0-9a-f]+\b/.source,
  /\b(?:e\.g|i\.e|etc|vs|incl|approx|et\s+al)\.?(?=\s|,|;|:|\)|$)/.source,
].join("|"), "gi");

// Whitespace chunks containing digits, code operators/delimiters, dotted identifiers,
// camelCase, or locale tags like "pt-PT" are technical tokens rather than prose words.
const CODE_CHUNK = /\d|[\\/_:=+*^~@#$%&<>{}[\]]|\p{Ll}\p{Lu}|\p{L}\.\p{L}|^[a-z]{1,3}-[A-Z]{2,}$/u;
const OUTER_PUNCT = /^[,.;:!?()'"“”‘’«»—–]+|[,.;:!?()'"“”‘’«»—–]+$/g;

// A list of short items, such as "Menu: tapas, paella de marisco, churros con chocolate":
// dish and product names are often foreign words, so lists are not judged as sentences.
function looksLikeList(sentence) {
  const items = sentence.split(/[,:;|\/]|\s(?:and|or|&)\s/i).map((s) => s.trim()).filter(Boolean);
  const separators = (sentence.match(/[,:;|\/]/g) || []).length;
  return separators >= 2 && items.every((item) => item.split(/\s+/).length <= 4);
}

/**
 * The language a sentence is written in, when it is not clearly English.
 *
 * In this order:
 * - most of it is in another script (three words or more): that script's language;
 * - its Latin words include at least three common words of a listed language, a fifth of
 *   all its words, and more than twice as many as English ones: that language, so foreign
 *   names inside English sentences ("Café de la Paix") do not count;
 * - six or more words (or accented unknown words) that are not a list, with no common
 *   English word ("the", "and", "with" ...), fewer than half of them English words, and
 *   a sign of another language (accented letters, or a common word of a listed language):
 *   that language, or one the lists don't know. Technical tokens, regexes, URIs and
 *   acronyms don't count either way.
 *
 * :param sentence: One sentence of cleaned text.
 * :return: The language's name, or null for English or too little text to tell.
 */
export function otherLanguageOf(sentence) {
  // "I'm", "don't", "we're": the ending is part of an English word, not a word of its own.
  const text = sentence.replace(NOT_WORDS, " ").replace(/'(?:m|s|t|re|ve|ll|d)\b/gi, "");
  const prose = text.split(/\s+/).map((c) => c.replace(OUTER_PUNCT, "")).filter((c) => c && !CODE_CHUNK.test(c)).join(" ");
  const tokens = [...prose.matchAll(LATIN_WORD)].map((m) => m[0]);
  const latin = tokens.map((w) => w.toLowerCase());
  let best = null;
  for (const script of SCRIPTS) {
    const letters = (sentence.match(script.re) || []).length;
    if (!letters) continue;
    const units = script.dense ? letters / 2 : letters / 5;
    if (!best || units > best.units) best = { name: script.name, units };
  }
  // Japanese mixes kana with Chinese characters: any kana makes it Japanese.
  if (best && best.name === "Chinese" && /[\p{Script=Hiragana}\p{Script=Katakana}]/u.test(sentence)) best.name = "Japanese";
  if (best && best.units >= 3) return best.name;
  const english = latin.filter((w) => STRONG_ENGLISH.has(w)).length;
  const candidateWords = [...new Set(tokens.filter((w) => !/^\p{Lu}{2,}$/u.test(w)).map((w) => w.toLowerCase()))];
  let top = null;
  for (const [name, set] of LATIN_WORDS) {
    const count = candidateWords.filter((w) => set.has(w)).length;
    if (!top || count > top.count) top = { name, count };
  }
  const hasAccents = /[^\x00-\x7f]/.test(latin.join(""));
  // Lists of short ASCII codes (e.g. locale tags "Locale (e.g. en, de, fr)") are not prose.
  const twoCharCount = tokens.filter((w) => w.length <= 2).length;
  if (!hasAccents && english === 0 && (text.match(/[,|\/]/g) || []).length >= 2 && twoCharCount >= 3 && tokens.length - twoCharCount <= 2) {
    return null;
  }
  if (!hasAccents && english === 0 && looksLikeList(text) && tokens.length >= 2 && tokens.every((w) => w.length <= 3)) {
    return null;
  }
  // For 3-word Latin phrases with non-ASCII letters, hold only when clearly non-English prose
  // (>= 2 words from a known language list, or an explicit foreign request/secret term), leaving
  // short menu dishes ("Crème brûlée maison.") and brief greetings ("Grüße aus München!") clear.
  if (latin.length === 3) {
    if (english === 0 && !looksLikeList(text) && hasAccents) {
      const judged3 = tokens.filter((word, i) => !(i > 0 && /^\p{Lu}/u.test(word)) && !/^\p{Lu}{2,}$/u.test(word))
        .map((w) => w.toLowerCase());
      const known3 = judged3.filter((w) => ENGLISH.has(w) || isEnglishWord(w)).length;
      if (judged3.length >= 2 && known3 === 0 && top.count >= 2) return top.name;
    }
    return null;
  }
  if (latin.length < 4) return null;
  const minCount = latin.length < 12 ? 2 : 3;
  const minRatio = latin.length < 12 ? 0.3 : 0.2;
  if (top.count >= minCount && top.count >= minRatio * Math.max(candidateWords.length, 1) && top.count > 2 * english) return top.name;
  // Not clearly English, whatever the language.
  if (english > 0 || looksLikeList(text)) return null;
  const judged = tokens.filter((word, i) => !(i > 0 && /^\p{Lu}/u.test(word)) && !/^\p{Lu}{2,}$/u.test(word) && !/\p{Ll}\p{Lu}/u.test(word))
    .map((word) => word.toLowerCase());
  if (judged.length < 4) return null;
  const known = judged.filter((word) => ENGLISH.has(word) || isEnglishWord(word)).length;
  if (known >= 0.5 * judged.length) return null;
  const realKnown = judged.filter((word) => word.length > 1 && (ENGLISH.has(word) || isEnglishWord(word))).length;
  const distinctJudged = new Set(judged).size;
  const englishSuffixes = judged.filter((word) => /^[a-z]{4,}(?:ing|ed|tion|ment|ness|able|ible|ive|ize|ise)$/i.test(word)).length;
  const foreignSign = hasAccents || top.count >= 2 || (realKnown === 0 && distinctJudged >= 6 && englishSuffixes < 2);
  if (!foreignSign) return null;
  if (judged.length < 6 && realKnown > 0) return null;
  if (top.count < 2 && (distinctJudged < 6 || englishSuffixes >= 2) && !(hasAccents && known === 0 && realKnown === 0)) return null;
  return top.count >= 2 ? top.name : UNRECOGNISED;
}

/**
 * Sentences written in another language than English.
 *
 * :param normalized: Text from normalizeForRules.
 * :return: [{match, excerpt, language}], one per sentence, with the language's name as
 *   the match.
 */
export function otherLanguageSentences(normalized) {
  const hits = [];
  const seen = new Set();
  for (const sentence of [...sentences(normalized), ...wrappedSentences(normalized)]) {
    if (seen.has(sentence)) continue;
    const language = otherLanguageOf(sentence);
    if (language) {
      seen.add(sentence);
      hits.push({ match: language, excerpt: sentence, language });
    }
  }
  return hits;
}
