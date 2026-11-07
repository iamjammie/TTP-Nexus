#!/usr/bin/env python3
"""
Assemble the standalone TTP NEXUS app.

Injects data/kb_data.json into build/app_template.html and writes the
single, self-contained index.html at the repo root.

Usage:
    python3 build/build_data.py     # regenerate data/kb_data.json
    python3 build/assemble.py       # produce index.html
"""
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLACEHOLDER = "/*__KB_DATA__*/"


def main() -> None:
    data = (ROOT / "data" / "kb_data.json").read_text(encoding="utf-8")
    tmpl = (ROOT / "build" / "app_template.html").read_text(encoding="utf-8")
    if PLACEHOLDER not in tmpl:
        raise SystemExit("placeholder %s missing from template" % PLACEHOLDER)
    out = tmpl.replace(PLACEHOLDER, data)
    (ROOT / "index.html").write_text(out, encoding="utf-8")
    print("Wrote %s (%.1f KB)" % (ROOT / "index.html", len(out.encode()) / 1024))


if __name__ == "__main__":
    main()
