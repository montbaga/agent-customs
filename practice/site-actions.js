// Registers this website's operations with the agent runtime.
// agent-manifest.json loads this module through "actions.module". Only the names in
// "actions.agentTools" become model tools, called website_<name>.
//
// Main Street Guide has one operation: reading the shop list on the page.
import { App } from "./guide.js";

/**
 * Describes the site's operations as actions the agents can call.
 */
class SiteActions {
  /**
   * Register every site action with the runtime.
   *
   * :param actions: The runtime registry facade with a register(definition) method.
   */
  static registerActions(actions) {
    actions.register(SiteActions.listShopsAction());
  }

  /**
   * Describe the read action that returns the shops on this page.
   *
   * :return: The action definition.
   */
  static listShopsAction() {
    return {
      name: "list_shops",
      description: "Read the shops listed on this Main Street page: each shop's name, what it sells and the link to its own page.",
      effect: "read",
      inputSchema: {
        type: "object",
        properties: {},
        additionalProperties: false,
      },
      execute: SiteActions.listShops,
    };
  }

  /**
   * Return a fresh copy of the shop list.
   *
   * :return: The page state as plain JSON data.
   */
  static listShops() {
    return App.page.getState();
  }
}

// The runtime calls the module's registerActions export.
export const registerActions = SiteActions.registerActions;
