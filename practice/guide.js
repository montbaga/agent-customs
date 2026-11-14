// The page script of Main Street Guide. Load it with:
//   <script type="module" src="guide.js"></script>
//
// App.page reads the shop list from the page, for the assistant's website_list_shops tool.
// The "Ask in the chat" buttons put a question in the assistant's message box and leave
// sending it to the visitor, because a message goes to the visitor's AI provider.

/**
 * The page object that site-actions.js wraps.
 */
export class App {
  static page = {
    /**
     * Read the shops on this page.
     *
     * :return: The street and its shops, each with its name, what it sells and the link to
     *   its own page.
     */
    getState() {
      const shops = [];
      for (const card of document.querySelectorAll("[data-shop]")) {
        shops.push({
          name: card.dataset.shop,
          sells: card.querySelector("[data-sells]")?.textContent.trim() || "",
          page: card.querySelector("a[data-page]")?.href || "",
        });
      }
      return { street: "Main Street", shops };
    },
  };

  /**
   * Put a question in the chat's message box, bring the chat into view and focus the box.
   *
   * :param question: The text to put in the box.
   * :return: True when the chat was there to take it.
   */
  static ask(question) {
    const input = document.querySelector("#ns-input");
    if (!input) {
      const status = document.querySelector("#assistant-status");
      if (status) status.textContent = "The assistant is still loading. Try again in a moment.";
      return false;
    }
    input.value = question;
    input.dispatchEvent(new Event("input", { bubbles: true }));
    document.querySelector("#assistant")?.scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
    input.focus({ preventScroll: true });
    return true;
  }

  /**
   * Wire the page's own controls: the "Ask in the chat" buttons and the copy buttons.
   */
  static wire() {
    for (const button of document.querySelectorAll("[data-ask]")) {
      button.addEventListener("click", () => App.ask(button.dataset.ask));
    }
    for (const button of document.querySelectorAll("[data-copy]")) {
      button.addEventListener("click", async () => {
        const source = document.getElementById(button.dataset.copy);
        try {
          await navigator.clipboard.writeText(source.textContent);
          button.textContent = "Copied";
        } catch {
          button.textContent = "Select and copy";
        }
        setTimeout(() => { button.textContent = "Copy"; }, 1600);
      });
    }
  }
}

if (typeof document !== "undefined") {
  App.wire();
}
