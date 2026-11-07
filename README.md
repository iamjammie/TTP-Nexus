# TTP NEXUS

**Connecting Tactics. Decoding Threats. Enabling Defence.**

A single-file, offline-first cybersecurity knowledge & learning portal that unifies MITRE ATT&CK, D3FEND, CAPEC, CWE/CVE, the Cyber Kill Chain, and pentest methodologies (PTES, OWASP WSTG, OWASP Top 10, NIST) into one interconnected TTP learning and operational-analysis platform.

> **Open [`index.html`](index.html) directly in any modern browser.** No server, no build step, no dependencies, no account. Works fully air-gapped.

---

## Highlights

- **One standalone HTML file** — HTML/CSS/JS only, no external scripts, stylesheets, fonts or CDNs. Runs from `file://`.
- **Unified explorers** — ATT&CK (Enterprise / ICS / Mobile), D3FEND, CAPEC, CWE/CVE, Kill Chain, each with rich detail views.
- **9-tab technique detail** — Overview · Adversary Methodology · Execution (lab) · Tools · Detection Engineering · Mitigation & Hardening · Relationships · Labs · References.
- **Cross-framework correlation** with confidence tags — **Official / Validated / Curated / Inferred** on every relationship.
- **Attack-Defence Mapping Studio** with an SVG force graph and coverage read-out.
- **Navigator-style matrix** (scoring, notes, ATT&CK Navigator layer JSON import/export, CSV).
- **Knowledge graph** (multi-hop, zoom/pan, SVG/JSON export).
- **Integrity & Coverage dashboard** — broken-reference / orphan / duplicate checks, detection-gap list, coverage %.
- **Learning Paths** (6 courses) + **Study Mode** (spaced-repetition flashcards, generated quizzes), progress saved locally.
- **Scenario Builder** and an **Export Center** (JSON / CSV / Markdown / HTML / print-PDF / **STIX 2.1**).
- **Command palette** (Ctrl/⌘ K), breadcrumbs, dark/light theme.

## Offline vs Online mode

A mode toggle in the top bar controls whether the portal reaches live sources:

- **Offline (default):** uses the embedded, curated dataset. Zero network calls.
- **Online:** after a **real connectivity probe** confirms a connection (it never trusts `navigator.onLine` as the positive signal), the portal fetches the **full official ATT&CK catalog** (STIX 2.1) from MITRE and switches technique Overviews and References to official content. Fetched data is cached in IndexedDB.

If the browser/network blocks the fetch (CORS, proxy, offline), the portal reports the real error and falls back to **file import** of an official STIX JSON, or the embedded dataset. See [Dataset & provenance](#dataset--provenance).

## Dataset & provenance

Framework versions referenced (verified 2026-11-07): **ATT&CK v20.1**, **D3FEND 1.0**, **CAPEC 3.9**, **CWE 5.0**, **OWASP Top 10:2025**.

**Honesty notes (also stated in-app):**

- The *embedded* content is a **curated subset**, not a complete framework. Descriptions are **paraphrased summaries, not official framework text**.
- Detection profiles are **curated educational guidance, not validated detections** — validate before production use.
- Cross-framework mappings carry a **source + confidence**; unknown mappings are **omitted, never invented**. No technique IDs, CVEs or rules are fabricated.
- To work with the **complete official catalog**, use **Online mode** (live fetch) or **Settings → Dataset Update Center → Import dataset file** with an official `enterprise-attack.json` (or mobile/ICS) from [attack-stix-data](https://github.com/mitre-attack/attack-stix-data).

MITRE ATT&CK®, D3FEND™, CAPEC™ and CWE™ are trademarks of The MITRE Corporation. OWASP® is a trademark of the OWASP Foundation. This project is **not affiliated with or endorsed by** MITRE or OWASP. See [`NOTICE`](NOTICE).

## Repository layout

```
index.html              # the built, standalone app — open this
build/
  build_data.py         # authors the embedded knowledge base -> data/kb_data.json
  app_template.html     # the app shell/UI/logic with a /*__KB_DATA__*/ placeholder
  assemble.py           # injects data/kb_data.json into the template -> index.html
  harness.js            # headless smoke test (engine + views)
  harness2.js           # headless regression test (views, detection, courses, STIX, parser)
data/
  kb_data.json          # generated embedded dataset (do not edit by hand)
```

## Build / develop

Requires Python 3 and (for tests) Node.js. No packages needed.

```bash
python3 build/build_data.py     # regenerate data/kb_data.json from build_data.py
python3 build/assemble.py       # inject data -> index.html
node   build/harness2.js        # run the regression tests
```

The app auto-builds its indices, reverse-maps, search and coverage from the data at runtime, so **adding records only means editing `build/build_data.py`** (same field shapes) and rerunning the two commands above — no app-code changes.

## Hosting (optional)

Because it is a single static file, it can be served by any static host or GitHub Pages (`index.html` at the repo root). It needs no backend.

## License

Code: [MIT](LICENSE). Framework data and trademarks remain the property of their respective owners — see [`NOTICE`](NOTICE).
