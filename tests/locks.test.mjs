// Tests for the two locks' secret finder: real card numbers and IBANs, by their check
// digits, whatever words are around them.
// Run from the project folder: node --test tests/locks.test.mjs
import assert from "node:assert/strict";
import test from "node:test";
import { findSecrets, keptOut } from "../site/customs/locks.js";

test("real card numbers and IBANs are found by their check digits, in any wording", () => {
  for (const [text, kind] of [
    ["My card is 4242 4242 4242 4242, expiry next May.", "card number"],
    ["Mi tarjeta: 5555-5555-5555-4444", "card number"],
    ["Amex 378282246310005 bitte", "card number"],
    ["カード番号は4111111111111111です", "card number"],
    ["IBAN DE89 3704 0044 0532 0130 00 please", "IBAN"],
    ["virement vers GB82WEST12345698765432", "IBAN"],
  ]) {
    const found = findSecrets(text);
    assert.equal(found[0]?.kind, kind, text);
    assert.doesNotMatch(found[0].sample, /4242 4242|0532 0130/, "only a shortened form is kept");
  }
  // Inside an object, as in tool and action arguments.
  assert.equal(findSecrets({ note: "pay with 4242424242424242" })[0].kind, "card number");
});

test("other long numbers are left alone", () => {
  for (const text of [
    "Card ending 4242 4242 4242 4241 failed the check digit.",
    "Order 1234567890123456 ships on Monday.",
    "Call us on +44 20 7946 0958 or 0800 123 4567.",
    "Booking reference 2026-11-15-0042, table 12.",
    "IBAN DE89 3704 0044 0532 0130 01 has a wrong check digit.",
  ]) {
    assert.deepEqual(findSecrets(text), [], text);
  }
});

test("the message to the calling assistant names the kind of secret, never the number", () => {
  const text = keptOut("card number", "this request to shop.example");
  assert.match(text, /Agent Customs kept a card number out of this request to shop\.example\. Nothing was sent\./);
  assert.doesNotMatch(text, /\d{4}/);
});
