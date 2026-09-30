#!/usr/bin/env python3
"""Validate the generated llms.txt structure and its rendered-site links."""

from __future__ import annotations

import argparse
import re
import stat
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse


REPO_ROOT = Path(__file__).resolve().parents[2]
LLMS_FILENAME = "llms.txt"
MAX_OUTPUT_BYTES = 5 * 1024 * 1024
EXPECTED_TITLE = "# Ardur"
EXPECTED_SECTIONS = (
    "Curated Documentation",
    "Source-Backed Repository Documentation",
    "Optional",
)
SITE_SCHEME = "https"
SITE_HOST = "ardurai.github.io"
SITE_PATH_PREFIX = "/ardur-evidence/"
FORBIDDEN_MARKERS = (
    "blob/dev",
    "tree/dev",
    "__ARDUR_SOURCE_REF__",
    "__ardur_internal__",
    "file://",
)
LINK_RE = re.compile(r"^- \[([^\]\r\n]+)\]\((https://[^)\s]+)\)(?:: ([^\r\n]+))?$")


def display_path(path: Path) -> str:
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def rendered_target(rendered_root: Path, url: str) -> tuple[Path | None, str | None]:
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        return None, f"link is not a valid URL: {url!r} ({exc})"
    if parsed.scheme != SITE_SCHEME or hostname != SITE_HOST:
        return (
            None,
            f"link must use the canonical {SITE_SCHEME}://{SITE_HOST} origin: {url!r}",
        )
    if parsed.username is not None or parsed.password is not None or port is not None:
        return None, f"link must not contain URL credentials or a port: {url!r}"
    if parsed.query or parsed.fragment:
        return None, f"link must not contain a query or fragment: {url!r}"
    if not parsed.path.startswith(SITE_PATH_PREFIX):
        return None, f"link must stay below {SITE_PATH_PREFIX!r}: {url!r}"

    relative_url = unquote(parsed.path[len(SITE_PATH_PREFIX) :])
    if (
        not relative_url
        or "\\" in relative_url
        or any(
            ord(character) < 32 or ord(character) == 127 for character in relative_url
        )
    ):
        return None, f"link has an unsafe or empty site path: {url!r}"
    relative = Path(relative_url)
    if relative.is_absolute() or ".." in relative.parts:
        return None, f"link has an unsafe or empty site path: {url!r}"

    if relative_url.endswith("/"):
        target = rendered_root / relative / "index.html"
    elif relative.suffix == ".html":
        target = rendered_root / relative
    else:
        return None, f"link must target a rendered page route: {url!r}"

    try:
        target.resolve().relative_to(rendered_root.resolve())
    except ValueError:
        return None, f"link resolves outside the rendered site: {url!r}"
    return target, None


def validate(rendered_root: Path) -> list[str]:
    failures: list[str] = []
    llms_path = rendered_root / LLMS_FILENAME
    try:
        metadata = llms_path.lstat()
    except FileNotFoundError:
        return [f"missing {display_path(llms_path)}"]
    except OSError as exc:
        return [f"cannot inspect {display_path(llms_path)}: {exc}"]

    if not stat.S_ISREG(metadata.st_mode):
        return [
            f"{display_path(llms_path)} must be a regular file, not a symlink or device"
        ]
    if metadata.st_size > MAX_OUTPUT_BYTES:
        return [
            f"{display_path(llms_path)} exceeds the {MAX_OUTPUT_BYTES}-byte safety limit"
        ]

    try:
        raw = llms_path.read_bytes()
    except OSError as exc:
        return [f"cannot read {display_path(llms_path)}: {exc}"]
    if len(raw) > MAX_OUTPUT_BYTES:
        failures.append(
            f"{display_path(llms_path)} exceeds the {MAX_OUTPUT_BYTES}-byte safety limit"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        return [f"{display_path(llms_path)} is not UTF-8: {exc}"]

    if not text.endswith("\n"):
        failures.append(f"{display_path(llms_path)} must end with a newline")
    if "\r" in text:
        failures.append(f"{display_path(llms_path)} must use LF line endings")
    if any(ord(character) < 32 and character != "\n" for character in text):
        failures.append(f"{display_path(llms_path)} contains control characters")

    for marker in FORBIDDEN_MARKERS:
        if marker.lower() in text.lower():
            failures.append(
                f"{display_path(llms_path)} contains forbidden marker {marker!r}"
            )

    lines = text.splitlines()
    if not lines or lines[0] != EXPECTED_TITLE:
        failures.append(f"first line must be exactly {EXPECTED_TITLE!r}")
    first_nonempty_after_title = next((line for line in lines[1:] if line.strip()), "")
    if not first_nonempty_after_title.startswith("> "):
        failures.append(
            "the first non-empty line after the title must be a blockquote summary"
        )

    current_section: str | None = None
    section_order: list[str] = []
    section_counts = {section: 0 for section in EXPECTED_SECTIONS}
    seen_urls: set[str] = set()

    for line_number, line in enumerate(lines, start=1):
        if line.startswith("## "):
            current_section = line[3:]
            section_order.append(current_section)
            if current_section not in section_counts:
                failures.append(
                    f"line {line_number}: unexpected section {current_section!r}"
                )
            continue
        if not line.startswith("- "):
            if current_section is not None and line.strip():
                failures.append(
                    f"line {line_number}: unexpected content inside "
                    f"section {current_section!r}"
                )
            continue
        if current_section not in section_counts:
            failures.append(
                f"line {line_number}: link entry appears outside an expected section"
            )
            continue

        match = LINK_RE.fullmatch(line)
        if not match:
            failures.append(f"line {line_number}: malformed link entry")
            continue
        title, url, _description = match.groups()
        if not title.strip():
            failures.append(f"line {line_number}: link title is empty")
        if url in seen_urls:
            failures.append(f"line {line_number}: duplicate URL {url!r}")
        else:
            seen_urls.add(url)

        target, error = rendered_target(rendered_root, url)
        if error:
            failures.append(f"line {line_number}: {error}")
        elif target is not None and not target.is_file():
            failures.append(
                f"line {line_number}: link target is not rendered: {display_path(target)}"
            )
        section_counts[current_section] += 1

    if section_order != list(EXPECTED_SECTIONS):
        failures.append(
            "sections must appear exactly once in this order: "
            + ", ".join(EXPECTED_SECTIONS)
        )
    for section, count in section_counts.items():
        if count == 0:
            failures.append(f"section {section!r} must contain at least one link")

    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "rendered_root",
        nargs="?",
        default="site/public",
        help="rendered Hugo output directory",
    )
    args = parser.parse_args()
    rendered_root = (REPO_ROOT / args.rendered_root).resolve()
    if not rendered_root.is_dir():
        print(
            f"llms.txt validation failed: missing rendered site {rendered_root}",
            file=sys.stderr,
        )
        return 1

    failures = validate(rendered_root)
    if failures:
        for failure in failures:
            print(f"llms.txt validation failed: {failure}", file=sys.stderr)
        return 1
    print("validated generated llms.txt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
