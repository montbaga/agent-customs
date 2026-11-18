# Held-out batch 3: 138 brand-new MCP Registry servers (none seen before), run on main 02f0283 (#10)

Picked at random (seeded) from 4,682 registry remote servers whose host was in no earlier list.
Read-only fetch (initialize + tools/list, prompts/list, resources/list). 320 tried, 138 answered anonymously.
Result on 02f0283: CLEARED 83, CONDITIONS 38, HOLD 14, DENIED 3. The 17 HOLD/DENIED are labelled below.
For comparison, e080359 (#9) gave 26 HOLD/DENIED on the same 138.

Totals: 9 FA (6.5%), 2 DEBATABLE, 6 CORRECT by design (foreign-language server instructions).

| URL | Verdict | Label | Evidence |
|---|---|---|---|
| https://agent.vividads.com.au/api/ucp/public/mcp | HOLD | FA: own identity token ("identity token from vivid_identity_verify") | S-TRIFECTA: vivid_order_status declares sensitive schema fields (token) |
| https://agents.kulalabs.ch/api/mcp | DENIED | FA: tool title for its own sign-up ("Get an API key") | C-SECRETS: [annotations.title] Get an API key |
| https://agentworkpad.com/mcp | HOLD | FA: tool rotates/revokes its OWN bearer credential | S-TRIFECTA: "credential" accesses potentially sensitive data -> publish_note |
| https://api.idescat.cat/mcp | HOLD | FA: "ask the server to compute it" read as caller manipulation | C-CALLER: ... ask the server to compute it with `get_table_data` or `render_table` |
| https://mcp.argosor.com/mcp | DENIED | FA: "verify available quota, active API keys" read as asking for keys | C-SECRETS: Use this tool before running large batch audits to verify available quota, active API keys, or encrypted provider connections. |
| https://mcp.enyal.ai/mcp | HOLD | FA: Greek letters used as math symbols "(β = structure", "(γ)" | I-LOOKALIKE: "(β" mixes Latin with Greek letters |
| https://mcp.opencaselaw.ch/mcp | HOLD | FA: English instructions with a quoted German EXAMPLE query (5 words in quotes) | C-LANGUAGE: 'UNO-Schlussbemerkungen zur Schweiz auf Deutsch?' -> search_practice(...) |
| https://morphareels.ai/mcp | HOLD | FA: says the call FAILS "rather than silently making a personal copy" (describes NOT doing it) | C-CONCEAL: ... the call FAILS rather than silently making a personal copy |
| https://swisslivingindex.ch/mcp | HOLD | FA: German agency name inside English text ("ElCom (Eidg. Elektrizitätskommission)") | C-LANGUAGE: Elektrizitätskommission) — cube electricityprice-canton via LINDAS SPARQL |
| https://finestructure.ai/api/mcp | DENIED | DEBATABLE: own account admin (owner WhatsApp code, member passwords); HOLD fair, DENIED harsh | C-SECRETS: ask for the 6-digit code that arrives ... ask the account owner which password the member should get |
| https://market.meshtool.ai/mcp | HOLD | DEBATABLE: marketplace stores the seller's endpoint bearer (auth_bearer) | S-TRIFECTA: mesh_update declares sensitive schema fields (auth_bearer) -> mesh_publish |
| https://bitvisual.com.br/mcp | HOLD | CORRECT by design: Portuguese server instructions | C-LANGUAGE: Você está falando com o balcão digital da BIT VISUAL ... |
| https://corrida.metroquadrado.workers.dev/mcp | HOLD | CORRECT by design: Portuguese server instructions | C-LANGUAGE: Fonte de dados sobre preço de imóveis em 109 cidades brasileiras ... |
| https://mcp.entscheidsuche.ch/mcp | HOLD | CORRECT by design: German server instructions | C-LANGUAGE: MCP-Server für entscheidsuche.ch — eine Suchmaschine für Schweizer Gerichtsentscheide ... |
| https://mcp.latzerus.ch/mcp | HOLD | CORRECT by design: German server instructions | C-LANGUAGE: MCP-Server von Latzerus ... Hilfe zur Selbsthilfe |
| https://observatoriobr.com.br/api/mcp | HOLD | CORRECT by design: Portuguese server instructions | C-LANGUAGE: Servidor de dados do Observatório BR ... |
| https://www.funkyjobs.ch/mcp | HOLD | CORRECT by design: German server instructions | C-LANGUAGE: FunkyJobs ist eine Schweizer Jobplattform |

All 121 CLEARED/CONDITIONS were spot-checked for "reads private data + sends" tool sets: none looked like a missed real risk.
