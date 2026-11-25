// tour.js: the "Watch the 2-minute tour" buttons open a dialog with the narrated video.
// The Vimeo player is created only when someone opens the dialog, and removed when it closes,
// so a visitor who doesn't watch loads nothing from Vimeo, and closing it stops the sound.
// dnt=1 asks Vimeo not to track the viewer or set cookies.

const VIDEO = "https://player.vimeo.com/video/1249916930?h=aadbd4f80e&dnt=1&autoplay=1&title=0&byline=0&portrait=0";

const dialog = document.getElementById("tour");
const frame = dialog?.querySelector(".tour-frame");
let opener = null;

function openTour(event) {
  if (!dialog || !frame || dialog.open) return;
  opener = event.currentTarget;
  frame.querySelector(".tour-player")?.remove();
  const player = document.createElement("iframe");
  player.className = "tour-player";
  player.title = "Agent Customs in 2 minutes (video)";
  player.setAttribute("allow", "autoplay; fullscreen; picture-in-picture; encrypted-media");
  player.setAttribute("allowfullscreen", "");
  player.referrerPolicy = "strict-origin-when-cross-origin";
  player.src = VIDEO;
  frame.append(player);
  dialog.showModal();
}

if (dialog) {
  for (const button of document.querySelectorAll("[data-tour]")) button.addEventListener("click", openTour);
  dialog.querySelector("[data-tour-close]")?.addEventListener("click", () => dialog.close());
  // A click on the dimmed page around the dialog closes it, as Escape does.
  dialog.addEventListener("click", (event) => { if (event.target === dialog) dialog.close(); });
  dialog.addEventListener("close", () => {
    dialog.querySelector(".tour-player")?.remove();
    opener?.focus();
    opener = null;
  });
}
