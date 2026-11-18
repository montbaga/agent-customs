// english-words.js: common English words, for telling English text from other languages.
//
// languages.js counts how many words of a sentence are English. Words are listed in their
// base form, and isEnglishWord also accepts the usual endings ("visitors", "booked",
// "warmly", "shopping"). The list includes the words agentic sites use most: shops, food,
// travel and the web.

const WORDS = `
a about above after again against ago all almost already also always am an and any are as at away back be because been
before being below between both but by can could did do does doing down during each either else even ever every few for
from further had has have having he her here hers herself him himself his how i if in into is it its itself just last
least less like many may maybe me might mine more most much must my myself neither never next no nor not now of off often
on once only or other our ours ourselves out over own perhaps please same shall she should since so some still such than
that the their theirs them themselves then there these they this those though through thus to too under until up upon us
very was we well were what whatever when whenever where wherever whether which while who whoever whole whom whose why will
with within without would yet you your yours yourself yourselves yes ok okay hello hi bye thanks thank sorry

accept act add admit advise afford agree aim allow answer appear apply arrange arrive ask attach attend avoid bake bear
beat become begin believe belong bend bet bite blow boil book borrow bother break bring browse build burn buy calculate
call cancel care carry catch cause change charge chat check choose clean clear click climb close collect combine come
compare complain complete confirm connect consider contact contain continue control convert cook copy correct cost count
cover create cross cut dance deal decide decline deliver depend describe deserve design destroy develop die dig discover
discuss display divide do download drag draw dream dress drink drive drop earn eat edit email enable encourage end enjoy
enter escape estimate examine exchange exist expect explain explore express extend fail fall feed feel fetch fight fill
find finish fit fix flow fly fold follow forget forgive form freeze fry gather get give go greet grill grow guarantee
guess guide handle hang happen hate have hear heat help hide hire hit hold hope host hurry identify ignore imagine improve
include increase inform inspect install intend introduce invite involve join judge jump keep kick kill knock know land last
laugh lay lead learn leave lend let lie lift like limit link list listen live load lock look lose love make manage mark
match matter mean measure meet melt mention mind miss mix move need note notice obtain occur offer open operate order
organise organize own pack paint park pass pay perform pick place plan play point post pour practise practice pray prefer
prepare present press prevent print process produce promise protect prove provide publish pull purchase push put quote
raise reach read realise realize receive recognise recognize recommend record reduce refer refund refuse register relax
release rely remain remember remind remove rent repair repeat replace reply report represent request require rescue
reserve reset respond rest restore return reveal review ride ring rise roast run rush save say scan search see seem select
sell send serve set settle shake shape share shine shop shout show shut sign sing sink sit skip sleep slide smell smile
solve sort sound speak spell spend spread stand start stay steal step stick stop store study submit succeed suffer suggest
suit supply support suppose surprise survive swim switch take talk taste teach tell tend test text thank think throw tick
tie touch tour track trade train translate travel treat trust try turn type understand unlock update upgrade upload urge
use validate value verify view visit vote wait wake walk want warn wash waste watch wear welcome win wish wonder work worry
wrap write

ability access account action activity actor address admin adult advantage advice afternoon age agency agent agreement
air airport alarm album amount anger animal answer apartment app appeal apple application appointment area argument arm
army arrival art article artist aspect assistant attack attempt attention audience author autumn average baby background
bag bakery balance ball band bank bar base basket bath bathroom battery beach bean bear beauty bed bedroom beef beer
beginning behaviour behavior benefit bike bill bird birth birthday biscuit bit blog blood board boat body bonus book
booking boot border bottle bottom bowl box boy brain branch brand bread breakfast brick bridge brother budget bug building
bus business butter button cafe cake calendar call camera camp campaign capital car card care career carpet case cash
castle cat category cause ceiling cell centre center century chain chair challenge champion chance change channel chapter
character charge chart chat cheese chef chicken child chocolate choice church cinema circle citizen city claim class
client climate clock clothes cloud club coach coast coat code coffee coin collection college colour color column comment
community company competition complaint computer concert condition conference connection contact content context contract
control conversation cookie copy corner cost cottage counter country county couple course court cousin cover cream credit
crime crowd cup currency curtain customer cycle dad damage danger data date daughter day deal death debt decision degree
delivery demand department deposit design desk dessert detail device diet difference dinner direction director discount
discussion dish disk distance doctor document dog dollar door double download dream dress drink driver drop duty ear earth
east economy edge education effect effort egg election element email employee end energy engine engineer entrance entry
environment equipment error event evening evidence exam example exchange exercise exit experience expert eye face fact
factory family fan farm father fault favour favor fear feature fee feedback feeling festival field figure file film filter
finger fire fish flat flight floor flour flower fly focus food foot football force forest form format forum frame freedom
friend front fruit fuel fun function future gallery game garage garden gas gate gift girl glass goal gold golf government
grade grain grass ground group growth guest guide guitar gym habit hair half hall hand head health heart heat height
help hero highway hill history hobby hole holiday home honey hope horse hospital host hotel hour house household human
husband ice idea image impact income industry information ingredient input insurance interest internet interview invoice
island issue item jacket job joke journey judge juice key keyboard kid kind king kitchen knife knowledge label lake land
language laptop law lawyer layer leader leaf lesson letter level library licence license life light limit line link lip
list loaf location lock login loss lot love lunch machine magazine mail manager map market marriage match material matter
meal meaning meat media medicine meeting member memory menu message metal method middle milk mind minute mirror mistake
mobile mode model moment money month mood morning mother motor mountain mouse mouth movie mum museum music name nation
nature neck network news newspaper night noise north nose note notice number nurse object ocean offer office officer oil
operation opinion option orange order organisation organization outcome output owner package page pain painting pair
pancake panel paper parent park part partner party passenger password past pasta path patient pattern payment peace pen
pencil people pepper percent period person pet phone photo phrase piano picture pie piece pilot pizza place plan plane
planet plant plastic plate platform player pocket poem point police policy pool pop population position post pot potato
pound power practice prayer preference presence president pressure price pride priest print priority prison privacy
prize problem process product profile profit program programme progress project promise property proposal protection pub
purpose quality quantity queen question queue race radio rain range rate reader reality reason receipt recipe record
region relation relationship release religion rent repair report request research reservation resource respect response
rest restaurant result review reward rice right ring risk river road rock role roof room rule safety salad salary sale
salt sample sandwich satisfaction sauce scale scene schedule school science score screen sea search season seat second
secret section security selection sense series service session setting shape share sheet shelf shirt shoe shop shopping
shot shoulder side sign signal silver singer sister site situation size skill skin sky sleep slice snack snow society sock
software soil soldier solution son song sort soul sound soup source south space speaker speech speed spirit sport spot
spring square staff stage stair standard star start state statement station status step stock stomach stone storage store
storm story strategy street strength stress structure student studio study style subject success sugar suggestion suit
summary summer sun supermarket supply support surface surprise survey sweet symbol system table tablet tag talent target
task taste tax tea teacher team technology teeth telephone television temperature tennis term test text theatre theater
theme theory thing thought ticket time tip title toast today toilet tomorrow tone tonight tool tooth top topic total tour
tourist town toy track trade traffic train training transport trip trouble truck truth turn type uncle union unit
university update user vacation valley value van variety vegetable vehicle version video view village visit visitor voice
volume wall war warning water wave way weakness weather web website wedding week weekend weight west wheel while wife
wind window wine wing winner winter woman wood word worker world writer year yesterday youth zone

able actual afraid alive alone amazing angry annual another available average awful bad basic beautiful best better big
bitter black blank blind blue bold bored boring bottom brave brief bright brilliant broad broken brown busy calm capable
careful central cheap chief chosen civil classic clean clear clever close cold comfortable common complete complex
confident considerable constant cool correct crazy creative critical crucial curious current cute daily dangerous dark
dead dear deep delicious dense different difficult digital direct dirty double dry due dull eager early easy eastern
economic effective electric electronic empty entire equal essential even evil exact excellent excited exciting expensive
expert extra extreme fair false familiar famous fancy fantastic far fast fat favourite favorite federal female few final
financial fine firm fit flat flexible foreign formal former free frequent fresh friendly front full funny general gentle
genuine giant glad global golden good gorgeous grand great green grey gray guilty half handy happy hard healthy heavy
helpful hidden high historic holy honest hot huge human hungry ideal ill illegal important impossible independent
individual initial inner innocent instant interesting internal international key kind large late latest lazy leading
legal light likely little live local lonely long loose loud lovely low lucky magic main major male manual many massive
medical medium mental middle mild military minor missing mobile modern modest moral narrow national native natural near
nearby neat necessary negative nervous new nice noble normal northern notable numerous obvious official old online only
open opposite optional ordinary organic original other outdoor outer overall own painful pale particular past perfect
personal physical plain pleasant plenty polite political poor popular positive possible powerful practical precious
premium present pretty previous primary prime prior private professional proper proud public pure quick quiet rapid rare
raw ready real recent red regional regular relevant remote responsible rich right rough round royal rude sad safe same
scared seasonal secret secure senior sensitive separate serious several severe sexy shallow sharp short shy sick significant
silent silly similar simple single slight slow small smart smooth social soft solid sorry southern spare special specific
spicy square stable standard steady sticky stiff straight strange strict strong stupid successful sudden sufficient
suitable super sure surprised sweet tall tasty technical temporary terrible thick thin tight tiny tired top total tough
traditional true typical ugly unable unique unknown unusual upper upset urgent useful usual valid valuable various vast
vegan vegetarian visible vital warm weak wealthy weekly weird welcome west western wet white whole wide wild willing
wise wonderful wooden working worried worse worst wrong young

one two three four five six seven eight nine ten eleven twelve twenty thirty forty fifty hundred thousand million first
second third fourth fifth once twice

ai api app assistant bot browser cart chatbot checkout cookie customs dashboard database developer domain email faq guard
html http https inbox inspect inspection json login logout manifest online prompt runtime script server signup sitemap
spec subscription token url username webpage website www github google wifi
bagel baguette barista bistro brownie burger cappuccino catering cheesecake cinnamon croissant cupcake donut doughnut
espresso fries gluten grocery latte muffin pastry pharmacy sourdough vanilla waffle tapas
puzzle maze loop quiz riddle trivia
pm etc eg ie vs mr mrs ms dr st nd rd th kg km cm mm ml min mins hr hrs sec secs
`;

/** The common English words, in base form. */
export const ENGLISH_WORDS = new Set(WORDS.split(/\s+/).filter(Boolean));

/**
 * Whether a lower-case word is a common English word, allowing for the usual endings.
 *
 * :param word: One word in lower case.
 * :return: True when the word or its base form is in the list.
 */
export function isEnglishWord(word) {
  if (ENGLISH_WORDS.has(word)) return true;
  const forms = [
    word.replace(/'s$/, ""), word.replace(/s$/, ""), word.replace(/es$/, ""), word.replace(/ies$/, "y"),
    word.replace(/ied$/, "y"), word.replace(/ed$/, ""), word.replace(/d$/, ""), word.replace(/ing$/, ""),
    word.replace(/ing$/, "e"), word.replace(/ly$/, ""), word.replace(/ily$/, "y"), word.replace(/er$/, ""),
    word.replace(/ers$/, ""), word.replace(/est$/, ""), word.replace(/ness$/, ""), word.replace(/ment$/, ""),
    word.replace(/ful$/, ""), word.replace(/less$/, ""), word.replace(/al$/, ""),
    // shopping, stopped, bigger: a doubled last consonant before the ending.
    word.replace(/([bdgklmnprt])\1(?:ing|ed|er|est)$/, "$1"),
  ];
  return forms.some((form) => form !== word && form.length > 1 && ENGLISH_WORDS.has(form));
}
