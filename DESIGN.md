# Agent Customs: design notes

The page should feel like a border post at night: dark ink, passport paper and rubber stamps. The inspection desk in the middle is a working tool, so it uses ordinary controls. The sections around it explain the product.

## Materials

- Ink at night: the dark background, with one live effect in the hero (flowing ink and a scan line that passes now and then).
- Passport paper: the light band, printed with a faint guilloche, the fine line pattern that passports and banknotes use against forgery.
- Rubber stamps: every verdict is an inked stamp.
- Glass: only where something moves behind it, on the menu bar and the replay window.

## Palette

Three colors in a 60-30-10 split. Forest is the default, chosen by the owner: `--c1` deep forest `#0c1d18` (60%), `--c2` warm paper `#ece4d3` (30%), and `--c3` lime `#c8f03c` (10%, for the main action, the scan light and one italic word per heading). On the light band, accent text uses `--c3-ink` `#3d6b0a`, a darker lime that keeps a 5:1 contrast. The verdict colors (cleared, held, denied) appear only on verdicts. Three more palettes (terracotta, navy and espresso) can be picked in the footer.

## Type

Geist for text and headings, Geist Mono for code, URLs and fingerprints, and Instrument Serif italic for one accent word per heading: two families in three files. Headings use weight 500 and tracking of -0.035em at most. Sizes: h1 72/38, h2 48/30, h3 28/24, lead 20/18, body 16, small 14, labels 13. Labels use sentence case; the stamps are the only place with capitals.

## Sections

Each section fills one screen, on a 12-column grid with equal edges.

| # | Section | Content |
|---|---|---|
| 1 | Hero | Heading, lead, the inspect form, and the replay window on the right |
| 2 | The sentence you can't see | Shady Pizza's hidden sentence lights up word by word |
| 3 | The inspection desk | One window with four tabs: Report, Approvals, Compare, Officer |
| 4 | Five checks, one stamp | The light band, a diagram with pulses, and three principles |
| 5 | A guard for your agentic site | Text on the left, the code on the right |
| 6 | Close and footer | The brand line, one fact, the main action, links |

## Copy

- The main heading says what the product does: "Safety checks for AI agents from other websites." The line "Border control for the agentic web" appears once, at the end.
- The first screen includes concrete numbers: five checks, and the replay shows 8 findings.
- Headings name things, and buttons say what they do. The main action is "Inspect a network" in the menu bar, the hero and the close.
- The page copy has no questions, exclamation marks, all-caps labels or filler.

## Motion

| Motion | Purpose | How |
|---|---|---|
| Hero entrance, once | Introduces the page | Heading words rise from masks (700 ms, 30 ms apart, at most 240 ms in total); the lead and form fade up 12 px (520 ms, 60 ms apart); the window settles from 0.98 (900 ms) |
| Hero background | Sets the scene | WebGL shader with a pause button; still under reduced motion |
| Replay, on load and on click | Shows a real inspection | The rows resolve in about 0.9 s, the stamp lands at 0.95 s, and the reason wipes in by 1.5 s |
| The hidden sentence | Shows the attack itself | Lights up word by word as you scroll through its section, and is finished by the time the section's top is a fifth of the way down the screen |
| Diagram pulses | Shows one network going through five checks | A pulse runs from the input to the core, the five lanes and the verdict; a 3.2 s cycle with a 0.24 s ripple; runs only on screen, has a pause button, and stays still on phones and under reduced motion |
| Tabs | Shows which tab is open | The highlight slides with clip-path (260 ms) |
| Stamp on a new report | Marks the verdict | 320 ms ease-out, no bounce |
| Hover and press | Feedback on every control | Buttons rise 1 px and press down to scale 0.98; arrows move 3 px; underlines draw in; fine pointers only |

Nothing else moves on scroll. The curves are `cubic-bezier(0.23, 1, 0.32, 1)` for interface motion and `cubic-bezier(0.77, 0, 0.175, 1)` for movement across the screen.

## The practice site

Main Street Guide (`practice/`) uses the same system with the navy palette (`#0a1430`, `#eef0f2` and coral `#ff6f59`), so it reads as a different site by the same hand. It has three screens: the street, with each shop's stamp; what the site added, as a folder tree and a two-line diff; and the assistant. It keeps the hero entrance, the glass bar and the stamps, and drops the shader, the scroll moment and the diagram, which belong to Agent Customs.
