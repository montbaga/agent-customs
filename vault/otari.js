// otari.js: otari.ai sends the Otari window here once the visitor approves a key, or cancels.
// The reply goes to the key vault that opened this window, and only to one on this same
// address. Its code is of no use without the secret the vault kept, so nothing is stored here.

import { OTARI } from "./vault-core.js";

const params = new URLSearchParams(location.search);
history.replaceState(null, "", location.pathname);
const reply = { type: OTARI.reply };
for (const name of ["code", "state", "iss", "error"]) {
  if (params.has(name)) reply[name] = params.get(name);
}

const note = document.getElementById("note");
if (window.opener && !window.opener.closed) {
  window.opener.postMessage(reply, location.origin);
  window.close();
  note.textContent = "Done. You can close this window.";
} else {
  note.textContent = "Agent Customs isn't waiting for this sign-in any more. Close this window and press Connect with Otari again.";
}
