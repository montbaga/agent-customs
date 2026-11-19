// trusted-types.js: one cleaner for every piece of HTML this page writes.
//
// The page's policy (index.html) asks the browser for Trusted Types: HTML may reach the page
// only through a policy. This file is the default policy, so every innerHTML-style write, in
// this site's code and in the runtime's, passes through clean() first. It removes what could
// run code or load something: script, frame and object elements, <base>, <meta>, <link>, event
// handler attributes, srcdoc, and javascript: or data: addresses. Scripts may load only from
// this site. A browser without Trusted Types ignores all of this, and the page works as before.
// HTML with an event handler makes the browser log a blocked inline handler while clean() reads
// it; the page's script-src rule blocks it, so it never runs.
// A plain script (not a module) loaded first, so the policy exists before anything writes HTML.
(function () {
  "use strict";
  var tt = window.trustedTypes;
  if (!tt || !tt.createPolicy) return;

  // Only clean() uses this one, to read HTML into a detached template.
  var reader = tt.createPolicy("agent-customs-html", { createHTML: function (html) { return html; } });
  var DROP = { SCRIPT: 1, IFRAME: 1, FRAME: 1, FRAMESET: 1, OBJECT: 1, EMBED: 1, BASE: 1, META: 1, LINK: 1, ANIMATE: 1, SET: 1 };
  var URL_ATTRS = { href: 1, src: 1, action: 1, formaction: 1, "xlink:href": 1, poster: 1, data: 1, background: 1 };
  var SAFE_DATA = /^data:image\/(png|jpe?g|gif|webp|avif);/;

  function unsafeUrl(value) {
    var url = String(value).replace(/[\u0000- ]+/g, "").toLowerCase();
    if (/^(javascript|vbscript):/.test(url)) return true;
    return url.indexOf("data:") === 0 && !SAFE_DATA.test(url);
  }

  function clean(root) {
    var walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT);
    var drop = [];
    for (var el = walker.nextNode(); el; el = walker.nextNode()) {
      if (DROP[el.tagName.toUpperCase()]) { drop.push(el); continue; }
      if (el.tagName.toUpperCase() === "TEMPLATE") clean(el.content);
      for (var i = el.attributes.length - 1; i >= 0; i -= 1) {
        var name = el.attributes[i].name.toLowerCase();
        if (name.indexOf("on") === 0 || name === "srcdoc" || (URL_ATTRS[name] && unsafeUrl(el.attributes[i].value))) {
          el.removeAttribute(el.attributes[i].name);
        }
      }
    }
    for (var j = 0; j < drop.length; j += 1) drop[j].remove();
  }

  tt.createPolicy("default", {
    createHTML: function (html) {
      var template = document.createElement("template");
      template.innerHTML = reader.createHTML(String(html));
      clean(template.content);
      return template.innerHTML;
    },
    createScriptURL: function (url) {
      var parsed = new URL(url, document.baseURI);
      if (parsed.origin === location.origin || parsed.protocol === "blob:") return parsed.href;
      throw new TypeError("Agent Customs: scripts load only from this site, not " + parsed.origin);
    },
  });
})();
