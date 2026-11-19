// Back from the officer's "Save and start", which reloads the page: keep the page hidden
// until view.js has reopened the Officer tab and scrolled to it, so it never shows another
// section first. A timer reveals it anyway if that does not happen. A plain script (not a
// module), so it runs before the page draws.
try {
  var savedAt = Number(sessionStorage.getItem("agent-customs-after-save") || 0);
  if (savedAt && Date.now() - savedAt < 60000) {
    document.documentElement.classList.add("returning");
    setTimeout(function () { document.documentElement.classList.remove("returning"); }, 2000);
  }
} catch (e) { /* storage blocked: show the page as usual */ }
