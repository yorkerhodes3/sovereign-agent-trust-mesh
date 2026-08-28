"""Validate the explainer site: well-formed markup and resolving references.

Mirrors .github/workflows/pages.yml so a developer runs the identical checks CI
runs. Kept as a real file rather than inlined into the workflow because an
inlined script cannot be run locally, and a check you cannot run locally is a
check you discover you have broken only after pushing.

Usage:  python tools/check-site.py
"""

import re
import sys
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urldefrag

ROOT = Path(__file__).resolve().parent.parent / "site"

VOID = {
    "area", "base", "br", "col", "embed", "hr", "img", "input",
    "link", "meta", "param", "source", "track", "wbr",
}


class Balance(HTMLParser):
    """Checks that every non-void element is closed, and closed in order."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.errors = []

    def handle_starttag(self, tag, attrs):
        if tag not in VOID:
            self.stack.append((tag, self.getpos()[0]))

    def handle_endtag(self, tag):
        if tag in VOID:
            return
        if not self.stack:
            self.errors.append(f"line {self.getpos()[0]}: stray </{tag}>")
            return
        open_tag, line = self.stack.pop()
        if open_tag != tag:
            self.errors.append(
                f"line {self.getpos()[0]}: </{tag}> closes <{open_tag}> opened on line {line}"
            )


def check_markup():
    failures = []

    # SVG is XML, so it must parse strictly. A malformed diagram simply fails to
    # render, with no console error in an <img> context.
    for svg in sorted(ROOT.rglob("*.svg")):
        try:
            ET.parse(svg)
        except ET.ParseError as exc:
            failures.append(f"{svg.relative_to(ROOT)}: {exc}")

    for page in sorted(ROOT.rglob("*.html")):
        parser = Balance()
        parser.feed(page.read_text(encoding="utf-8"))
        rel = page.relative_to(ROOT)
        failures.extend(f"{rel}: {e}" for e in parser.errors)
        failures.extend(
            f"{rel}: <{tag}> opened on line {line} is never closed"
            for tag, line in parser.stack
        )

    return failures


def check_references():
    failures = []

    for page in sorted(ROOT.rglob("*.html")):
        html = page.read_text(encoding="utf-8")
        rel = page.relative_to(ROOT)

        for ref in re.findall(r'(?:href|src)="([^"]+)"', html):
            if ref.startswith(("http://", "https://", "mailto:", "data:", "#")):
                continue
            target, _ = urldefrag(ref)
            if not target:
                continue
            # A leading slash is root-relative to the site, not the filesystem.
            base = ROOT if target.startswith("/") else page.parent
            resolved = (base / target.lstrip("/")).resolve()
            if not resolved.exists():
                failures.append(f"{rel}: {ref}")

        # An in-page anchor with no matching id silently does nothing, which is
        # the kind of bug nobody reports and everybody notices.
        ids = set(re.findall(r'id="([^"]+)"', html))
        for anchor in re.findall(r'href="#([^"]+)"', html):
            if anchor not in ids:
                failures.append(f"{rel}: #{anchor} has no matching id")

    return failures


def main():
    if not ROOT.is_dir():
        print(f"no site directory at {ROOT}", file=sys.stderr)
        return 1

    markup = check_markup()
    refs = check_references()

    if markup:
        print("MALFORMED MARKUP")
        for f in markup:
            print(f"  {f}")
    if refs:
        print("BROKEN REFERENCES")
        for f in refs:
            print(f"  {f}")

    if markup or refs:
        return 1

    pages = len(list(ROOT.rglob("*.html")))
    svgs = len(list(ROOT.rglob("*.svg")))
    print(f"OK — {pages} pages, {svgs} diagrams: markup well-formed, all references resolve")
    return 0


if __name__ == "__main__":
    sys.exit(main())
