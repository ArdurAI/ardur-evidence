#!/usr/bin/env python3
"""Fail when rendered documentation links back to GitHub for hosted docs."""

from __future__ import annotations

import argparse
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlparse


REPO_ROOT = Path(__file__).resolve().parents[2]
REPO_HOST = "github.com"
REPO_PATH = "/ArdurAI/ardur-evidence"

ROOT_DOCS = {
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "MEDIA.md",
    "README.md",
    "RESEARCH.md",
    "ROADMAP.md",
    "SECURITY.md",
    "STATUS.md"
}

DOC_EXTENSIONS = {".cast", ".json", ".md", ".yaml", ".yml"}
DOC_PREFIXES = (".github/", "deploy/", "docs/", "examples/", "go/spec/", "media/")
EXPECTED_SOURCE_ROUTES = {
    "MEDIA.md": "/source/media-notes/"
}


class Anchor:
    def __init__(self, href: str, text: str, path: Path) -> None:
        self.href = href
        self.text = " ".join(text.split())
        self.path = path


class AnchorParser(HTMLParser):
    def __init__(self, path: Path) -> None:
        super().__init__(convert_charrefs=True)
        self.path = path
        self.anchors: list[Anchor] = []
        self._href_stack: list[str | None] = []
        self._text_stack: list[list[str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            return
        href = None
        for name, value in attrs:
            if name == "href":
                href = value
                break
        self._href_stack.append(href)
        self._text_stack.append([])

    def handle_data(self, data: str) -> None:
        if self._text_stack:
            self._text_stack[-1].append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag != "a" or not self._href_stack:
            return
        href = self._href_stack.pop()
        text = "".join(self._text_stack.pop())
        if href:
            self.anchors.append(Anchor(href, text, self.path))


def repo_target_from_url(href: str) -> str | None:
    parsed = urlparse(href)
    if parsed.netloc != REPO_HOST:
        return None
    path = unquote(parsed.path)
    for mode in ("blob", "tree"):
        prefix = f"{REPO_PATH}/{mode}/"
        if not path.startswith(prefix):
            continue
        parts = path[len(prefix):].split("/", 1)
        if len(parts) != 2:
            return None
        return parts[1].rstrip("/")
    return None


def route_for(target: str) -> Path:
    return Path(*[
        part.lower().lstrip(".") if part.startswith(".") else part.lower()
        for part in Path(target).parts
    ])


def is_documentation_target(target: str, rendered_root: Path) -> bool:
    if target in ROOT_DOCS:
        return True
    suffix = Path(target).suffix.lower()
    if not suffix:
        return (rendered_root / "source" / route_for(target) / "index.html").exists()
    if target.startswith(DOC_PREFIXES):
        return suffix in DOC_EXTENSIONS
    return Path(target).suffix.lower() in DOC_EXTENSIONS


def is_allowed_provenance_link(anchor: Anchor) -> bool:
    return anchor.text.startswith("Source:")


def display_path(path: Path) -> str:
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def rendered_href_path(href: str) -> str:
    path = urlparse(href).path.rstrip("/")
    return f"{path}/"


def validate(rendered_root: Path) -> list[str]:
    failures: list[str] = []
    for html_path in sorted(rendered_root.rglob("*.html")):
        parser = AnchorParser(html_path)
        parser.feed(html_path.read_text(encoding="utf-8"))
        for anchor in parser.anchors:
            if anchor.text in EXPECTED_SOURCE_ROUTES and not is_allowed_provenance_link(anchor):
                expected = EXPECTED_SOURCE_ROUTES[anchor.text]
                if not rendered_href_path(anchor.href).endswith(expected):
                    failures.append(
                        f"{display_path(html_path)} links {anchor.text!r} to "
                        f"{anchor.href!r}; expected rendered source route ending {expected!r}"
                    )
            target = repo_target_from_url(anchor.href)
            if not target or not is_documentation_target(target, rendered_root):
                continue
            if is_allowed_provenance_link(anchor):
                continue
            failures.append(
                f"{display_path(html_path)} links to GitHub documentation target "
                f"{target!r} with text {anchor.text!r}"
            )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "rendered_root",
        nargs="?",
        default="site/public",
        help="rendered Hugo output directory"
    )
    args = parser.parse_args()
    rendered_root = (REPO_ROOT / args.rendered_root).resolve()
    if not rendered_root.exists():
        print(f"rendered docs link validation failed: missing {rendered_root}", file=sys.stderr)
        return 1

    failures = validate(rendered_root)
    if failures:
        for failure in failures:
            print(f"rendered docs link validation failed: {failure}", file=sys.stderr)
        return 1
    print("validated rendered documentation links")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
