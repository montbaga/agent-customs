# Held-out batch 4: 192 brand-new MCP Registry servers + 44 brand-new A2A cards, run on main cae4a77 (#11)

Hosts in no earlier list (reg-urls, curated, fresh-urls, all-hosts, third-urls, earlier A2A lists). Seeded random pick (seed 777001)
from 4,361 untested registry remote servers; 400 tried read-only, 192 answered anonymously. A2A cards found on the same hosts.
Result on cae4a77: CLEARED 136, CONDITIONS 53, HOLD 33, DENIED 11, INVALID 3 (fair: 0 tools / no endpoint).
For comparison on the same 236: 02f0283 (#10) 41 HOLD/DENIED, e080359 (#9) 58.

Totals: 26 FA (11.0%), 5 DEBATABLE, 13 CORRECT by design (foreign-language server instructions).

| URL | Verdict | Label | Evidence |
|---|---|---|---|
| https://3lgrouptechnology.com/mcp | HOLD | FA: describes giving the human a one-tap Allow/Deny approval link | C-CONSENT: returns a one-tap Allow/Deny approval_url for the human |
| https://agentanthill.com/mcp | DENIED | FA: game tool title "get the pass code" | C-SECRETS: [title] Take the leaf (get the pass code) |
| https://api.keenable.ai/mcp-public?keenable_title=mcp-registry | HOLD | FA: UI option "disable cards" | C-CONSENT: disable cards |
| https://injectionscan.openkrill.app/mcp | HOLD | FA: a prompt-injection SCANNER describing what it detects | C-OVERRIDE: Finds instructions aimed at the model (ignore previous instructions, ...) |
| https://leadgen-mcp.adrianhomelab.com/mcp?src=mcp-registry | DENIED | FA: "every watch owned by your API key" | C-SECRETS: drain the changeset for every watch owned by your API key |
| https://nerdnoir.ai/api/mcp | DENIED | FA: resource URI template builder://<key> | C-EXFIL: The `builder://<key>` resource holds the full coaching |
| https://tendeck.ai/mcp | DENIED | FA: own signup code + "call this BEFORE telling the user you don't know" | C-SECRETS / C-CONCEAL |
| https://trydock.ai/api/mcp | DENIED | FA: own workspace admin docs; own confirm_token | C-SECRETS: Ask the human owner to revoke ANOTHER agent's active API key |
| https://verticalmarketplace.ai/api/mcp | DENIED | FA: own OAuth / Authorization: Bearer docs (agent inbox HOLD alone would be debatable) | C-SECRETS: Works with your Vermarco connector sign-in (OAuth) or your agent API key ... |
| https://www.arthr.com.au/api/mcp | DENIED | FA: loan calculator field "creditCardLimits" (a limit, not a card number) | C-SECRETS: parameter "creditCardLimits" |
| https://www.arthr.com.au/.well-known/agent-card.json | DENIED | FA: same "creditCardLimits" field | C-SECRETS |
| https://www.oriiion.ai/mcp | DENIED | FA: own API/upload docs and owner link | C-EXFIL / C-SECRETS: Clients that hold the raw API key may also POST ... |
| https://www.affix-io.com/.well-known/agent-card.json | HOLD | FA: PROTECTIVE text "does not override your instructions" | C-OVERRIDE |
| https://authenticated-llm-agent-cryptography.getvda.ai/.well-known/agent-card.json | HOLD | FA: standard JWS in `proof.jws` (same cause as duami `signatures[].protected`) | C-ENCODED [rawDoc.proof.jws] |
| https://authenticated-mcp-agent-bcrypt.getvda.ai/.well-known/agent-card.json | HOLD | FA: JWS proof | C-ENCODED |
| https://elasticsearch-redis-stack-generator.getvda.ai/.well-known/agent-card.json | HOLD | FA: JWS proof | C-ENCODED |
| https://google-auth-oauthlib-langchain-la-c1a755.getvda.ai/.well-known/agent-card.json | HOLD | FA: JWS proof | C-ENCODED |
| https://llm-orchestration-agent-langchain.getvda.ai/.well-known/agent-card.json | HOLD | FA: JWS proof | C-ENCODED |
| https://postgres-kafka-stack-generator.getvda.ai/.well-known/agent-card.json | HOLD | FA: JWS proof | C-ENCODED |
| https://postgres-prometheus-stack-generator.getvda.ai/.well-known/agent-card.json | HOLD | FA: JWS proof | C-ENCODED |
| https://structured-output-agent-c2ddcc.getvda.ai/.well-known/agent-card.json | HOLD | FA: JWS proof | C-ENCODED |
| https://alishahiinsurance.com/mcp | HOLD | FA: application token from the reply email (own handle) | S-TRIFECTA: get_application (token) |
| https://angelscohq.com/aether/mcp | HOLD | FA: own peer_token paired with peer_id | S-TRIFECTA: aether_find (peer_token) |
| https://codigo07.vercel.app/mcp | HOLD | FA: "token_consulta returned when the request was created" | S-TRIFECTA: pagar_solicitud (token) |
| https://mcp.himalayas.app/mcp | HOLD | FA: two-step delete confirm_token (was CONDITIONS on #10) | S-TRIFECTA: delete_company_job (confirm_token) |
| https://mcp.robomart.ai/mcp | HOLD | FA: read-only balance of the org's own service wallet | S-TRIFECTA: wallet_balance |
| https://palmyr.ai/mcp | DENIED | DEBATABLE: extracts OTP codes from an agent inbox; HOLD fair, DENIED harsh | C-SECRETS: Custom extraction regex overriding the default OTP formats |
| https://mcp.facesign.ai/mcp | DENIED | DEBATABLE: asks the user for its OWN API key in chat (HOLD fair); JSON pointer with /anyOf/2/ is FA | C-SECRETS / C-ENCODED |
| https://mcp.greenlandai.ai/mcp | HOLD | DEBATABLE: agent wallet-to-wallet transfers | S-TRIFECTA: wallet_transfer |
| https://mcp.aave.com | HOLD | DEBATABLE: DeFi wallet balances + submit signed orders | S-TRIFECTA |
| https://mcp.sandbox.ableandagent.com/ | HOLD | DEBATABLE: agent chat messages + register_agent | S-TRIFECTA: list_messages |
| https://ai.ihaola.com.cn/api/mcp/haola-pe | HOLD | CORRECT by design: Chinese instructions | C-LANGUAGE |
| https://algomakers.com/mcp | HOLD | CORRECT by design: Portuguese instructions | C-LANGUAGE |
| https://galetosdobrasilaldeota.com.br/mcp | HOLD | CORRECT by design: Portuguese | C-LANGUAGE |
| https://garimpopublico.com.br/mcp | HOLD | CORRECT by design: Portuguese | C-LANGUAGE |
| https://mana.bzh/mcp | HOLD | CORRECT by design: French | C-LANGUAGE |
| https://mcp.den.archi/mcp | HOLD | CORRECT by design: Korean | C-LANGUAGE |
| https://mcp.normhyra.ai/ | HOLD | CORRECT by design: Swedish | C-LANGUAGE |
| https://namerimidom.bg/mcp/public | HOLD | CORRECT by design: Bulgarian | C-LANGUAGE |
| https://ncha.app/mcp | HOLD | CORRECT by design: Korean | C-LANGUAGE |
| https://servicekuhn.ch/wp-json/kuhn-sr/v1/mcp | HOLD | CORRECT by design: German | C-LANGUAGE |
| https://www.mueblito.ar/api/mcp | HOLD | CORRECT by design: Spanish | C-LANGUAGE |
| https://xiximm.cloud/mcp | HOLD | CORRECT by design: Chinese | C-LANGUAGE |
| https://53on.com/.well-known/agent-card.json | HOLD | CORRECT by design: Spanish skill example | C-LANGUAGE |
