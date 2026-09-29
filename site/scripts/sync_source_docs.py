#!/usr/bin/env python3
"""Generate source-backed Hugo pages from the public repo Markdown corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath


REPO_ROOT = Path(__file__).resolve().parents[2]
SITE_ROOT = REPO_ROOT / "site"
CONTENT_SOURCE_ROOT = SITE_ROOT / "content" / "source"
STATIC_ARTIFACT_ROOT = SITE_ROOT / "static" / "repo"
CAPABILITIES_OUTPUT = SITE_ROOT / "data" / "capabilities.json"
SOURCE_ROUTES_OUTPUT = SITE_ROOT / "data" / "source_routes.json"
REPO_URL = "https://github.com/ArdurAI/ardur-evidence"
SOURCE_REF_PLACEHOLDER = "__ARDUR_SOURCE_REF__"
INTERNAL_URL_PREFIX = "/__ardur_internal__/"

PUBLIC_MARKDOWN_EXCLUDED_PREFIXES = (
    ".context/",
    ".worktrees/",
    "_internal/",
    "logs/",
    "site/content/",
    "site/public/",
    "site/resources/",
    "python/tests/test-results/",
    "worktrees/",
)

PUBLIC_MARKDOWN_EXCLUDED_DIR_NAMES = {
    ".git",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "vendor",
    "worktrees",
}

PUBLIC_MARKDOWN_INCLUDED_HIDDEN_DIRS: set[str] = set()

PUBLIC_ARTIFACT_GLOBS = [
    ".github/ISSUE_TEMPLATE/*.yml",
    ".github/workflows/*.yml",
    "docs/**/*.json",
    "docs/**/*.jsonl",
    "docs/specs/fixtures/*.pem",
    "python/vibap/_specs/*.json",
    "go/spec/**/*.json",
    "go/pkg/kernelcapture/testdata/agent-recognition-benchmark-*.json",
    "examples/**/*.json",
    "examples/_shared/*.py",
    "deploy/**/*.yaml",
    "deploy/**/*.yml",
    "deploy/helm/ardur/Chart.yaml",
    "deploy/helm/ardur/values.yaml",
    "media/selected-assets.json",
    "media/casts/*.cast"
]

LINK_RE = re.compile(r"(?<!!)\[([^\]]+)\]\(([^)\s]+)\)")
IMAGE_LINK_RE = re.compile(r"(\[!\[[^\]]*\]\([^)]+\)\])\(([^)\s]+)\)")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def json_front_matter(fields: dict[str, object]) -> str:
    lines = ["---"]
    for key, value in fields.items():
        lines.append(f"{key}: {json.dumps(value, ensure_ascii=False)}")
    lines.append("---")
    return "\n".join(lines)


def is_public_markdown_path(path: Path) -> bool:
    posix = path.as_posix()
    if any(posix.startswith(prefix) for prefix in PUBLIC_MARKDOWN_EXCLUDED_PREFIXES):
        return False
    for part in path.parts:
        if part in PUBLIC_MARKDOWN_EXCLUDED_DIR_NAMES:
            return False
        if part.startswith(".") and part not in PUBLIC_MARKDOWN_INCLUDED_HIDDEN_DIRS:
            return False
    return True


def discover_markdown() -> list[Path]:
    paths: set[Path] = set()
    for path in REPO_ROOT.rglob("*.md"):
        if path.is_file():
            relative = path.relative_to(REPO_ROOT)
            if is_public_markdown_path(relative):
                paths.add(relative)
    return sorted(paths, key=lambda p: p.as_posix())


def discover_artifacts() -> list[Path]:
    paths: set[Path] = set()
    for pattern in PUBLIC_ARTIFACT_GLOBS:
        for path in REPO_ROOT.glob(pattern):
            if path.is_file():
                paths.add(path.relative_to(REPO_ROOT))
    return sorted(paths, key=lambda p: p.as_posix())


def extract_title(text: str, source: Path) -> str:
    for line in text.splitlines():
        if line.startswith("# "):
            return line[2:].strip().strip("`")
    stem = source.stem if source.name.lower() != "readme.md" else source.parent.name
    if stem in {"", "."}:
        stem = "README"
    return stem.replace("-", " ").replace("_", " ").title()


def strip_first_h1(text: str) -> str:
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.startswith("# "):
            return "\n".join(lines[:i] + lines[i + 1 :]).lstrip()
    return text


def extract_description(text: str) -> str:
    in_fence = False
    in_html_comment = False
    for raw in strip_first_h1(text).splitlines():
        line = raw.strip()
        if line.startswith("```"):
            in_fence = not in_fence
            continue
        if in_html_comment:
            if "-->" in line:
                in_html_comment = False
            continue
        if line.startswith("<!--"):
            if "-->" not in line:
                in_html_comment = True
            continue
        if in_fence or not line:
            continue
        if line.startswith(("#", "-", "|", ">", "```")):
            continue
        return re.sub(r"\s+", " ", line)[:180]
    return "Source-backed public repo document."


def classify(source: Path, text: str) -> dict[str, list[str]]:
    lowered = source.as_posix().lower()
    surfaces = ["docs"] if len(source.parts) == 1 else [source.parts[0]]
    claim_types = ["documentation"]
    frameworks = ["framework-agnostic"]
    evidence_levels = ["code-and-doc"]
    maturity = ["public-now"]

    if lowered.startswith("docs/specs/"):
        surfaces = ["docs", "specs"]
        claim_types = ["protocol-spec"]
        evidence_levels = ["spec"]
    elif lowered.startswith("docs/decisions/"):
        surfaces = ["docs"]
        claim_types = ["decision-record"]
    elif lowered.startswith("docs/articles/"):
        surfaces = ["docs"]
        claim_types = ["article"]
    elif lowered.startswith("docs/comparisons/"):
        surfaces = ["docs"]
        claim_types = ["comparison"]
    elif lowered.startswith("docs/audit/"):
        surfaces = ["docs"]
        claim_types = ["audit"]
    elif "known-limitations" in lowered:
        surfaces = ["docs"]
        claim_types = ["limitation"]
        evidence_levels = ["limitation-backed"]
    elif "security" in lowered:
        surfaces = ["docs"]
        claim_types = ["security-model"]
    elif lowered == "media.md":
        surfaces = ["media", "docs"]
        claim_types = ["proof-media"]
        frameworks = ["framework-live", "foundation"]
        evidence_levels = ["archival-media"]
        maturity = ["in-progress"]
    elif lowered.startswith("deploy/"):
        surfaces = ["deploy"]
        claim_types = ["deployment"]
        frameworks = ["kubernetes", "spire"]
        evidence_levels = ["doc-and-manifest"]
        maturity = ["in-progress"]
    elif lowered.startswith("examples/"):
        surfaces = ["examples"]
        claim_types = ["integration"]
        if "langchain" in lowered:
            frameworks = ["langchain"]
        elif "langgraph" in lowered:
            frameworks = ["langgraph"]
        elif "autogen" in lowered:
            frameworks = ["autogen"]
        elif "google-adk" in lowered:
            frameworks = ["google-adk"]
        elif "openai-agents-sdk" in lowered:
            frameworks = ["openai-agents-sdk"]
        elif "claude-code-hook" in lowered:
            frameworks = ["claude-code"]
        if "placeholder" in text.lower() or "stub" in text.lower():
            maturity = ["in-progress"]
    elif lowered.startswith("python/"):
        surfaces = ["python"]
        claim_types = ["runtime-boundary"]
    elif lowered.startswith("go/"):
        surfaces = ["go"]
        claim_types = ["runtime-boundary"]
    elif lowered == "status.md":
        claim_types = ["status"]
        surfaces = ["docs"]
        maturity = ["public-now", "in-progress"]
    elif lowered == "roadmap.md":
        claim_types = ["roadmap"]
        surfaces = ["docs"]
        maturity = ["in-progress"]
    elif lowered == "readme.md":
        claim_types = ["orientation", "runtime-boundary"]
        surfaces = ["docs"]

    return {
        "maturity": sorted(set(maturity)),
        "claim_types": sorted(set(claim_types)),
        "surfaces": sorted(set(surfaces)),
        "frameworks": sorted(set(frameworks)),
        "evidence_levels": sorted(set(evidence_levels))
    }


def repo_source_url(source: Path, fragment: str = "") -> str:
    mode = "tree" if (REPO_ROOT / source).is_dir() else "blob"
    return f"{REPO_URL}/{mode}/{SOURCE_REF_PLACEHOLDER}/{source.as_posix().rstrip('/')}{fragment}"


def site_route_for(source: Path) -> Path:
    return Path(*[
        part.lower().lstrip(".") if part.startswith(".") else part.lower()
        for part in source.parts
    ])


def content_path_for(source: Path) -> Path:
    return Path(*[
        part.lstrip(".") if part.startswith(".") else part
        for part in source.parts
    ])


def source_route_for(source: Path, documentation_directories: set[Path]) -> Path:
    route = site_route_for(source.with_suffix(""))
    directory_routes = {site_route_for(directory) for directory in documentation_directories}
    if route in directory_routes:
        suffix = "notes" if source.name.lower() == "media.md" else "file"
        route = route.parent / f"{route.name}-{suffix}"
    return route


def source_page_path(source: Path, documentation_directories: set[Path]) -> str:
    return f"source/{source_route_for(source, documentation_directories).as_posix()}/"


def directory_page_path(directory: Path) -> str:
    return f"source/{site_route_for(directory).as_posix().rstrip('/')}/"


def internal_url(path: str, fragment: str = "") -> str:
    return f"{INTERNAL_URL_PREFIX}{path.lstrip('/')}{fragment}"


def normalize_relative_target(source: Path, target: str) -> tuple[Path | None, str]:
    if "#" in target:
        target_path, fragment = target.split("#", 1)
        fragment = f"#{fragment}"
    else:
        target_path, fragment = target, ""
    if not target_path:
        return None, fragment
    normalized = PurePosixPath(source.parent.as_posix()) / PurePosixPath(target_path)
    parts: list[str] = []
    for part in normalized.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return Path(*parts), fragment


def documentation_url(
    repo_target: Path,
    fragment: str,
    markdown_pages: dict[Path, str],
    artifact_paths: set[Path],
    directory_pages: dict[Path, str]
) -> str | None:
    candidates: list[Path] = []
    if repo_target.suffix.lower() == ".md":
        candidates.append(repo_target)
    else:
        candidates.append(repo_target / "README.md")
        candidates.append(repo_target.with_suffix(".md"))

    for candidate in candidates:
        if candidate in markdown_pages:
            return internal_url(markdown_pages[candidate], fragment)

    if repo_target in directory_pages:
        return internal_url(directory_pages[repo_target], fragment)

    if repo_target in artifact_paths:
        return internal_url(f"repo/{repo_target.as_posix()}", fragment)

    return None


def github_url_to_documentation_url(
    target: str,
    markdown_pages: dict[Path, str],
    artifact_paths: set[Path],
    directory_pages: dict[Path, str]
) -> str | None:
    for mode in ("blob", "tree"):
        prefix = f"{REPO_URL}/{mode}/dev/"
        if not target.startswith(prefix):
            continue
        remainder = target[len(prefix):]
        if "#" in remainder:
            path_part, fragment = remainder.split("#", 1)
            fragment = f"#{fragment}"
        else:
            path_part, fragment = remainder, ""
        return documentation_url(Path(path_part), fragment, markdown_pages, artifact_paths, directory_pages)
    return None


def rewrite_links(
    text: str,
    source: Path,
    markdown_pages: dict[Path, str],
    artifact_paths: set[Path],
    directory_pages: dict[Path, str]
) -> str:
    lines: list[str] = []
    in_fence = False
    for raw in text.splitlines():
        if raw.strip().startswith("```"):
            in_fence = not in_fence
            lines.append(raw)
            continue
        if in_fence:
            lines.append(raw)
            continue

        def rewrite_target(label: str, target: str) -> str:
            internal = github_url_to_documentation_url(target, markdown_pages, artifact_paths, directory_pages)
            if internal:
                return f"{label}({internal})"
            if target.startswith(f"{REPO_URL}/blob/dev/"):
                return f"{label}({target.replace(f'{REPO_URL}/blob/dev/', f'{REPO_URL}/blob/{SOURCE_REF_PLACEHOLDER}/', 1)})"
            if target.startswith(f"{REPO_URL}/tree/dev/"):
                return f"{label}({target.replace(f'{REPO_URL}/tree/dev/', f'{REPO_URL}/tree/{SOURCE_REF_PLACEHOLDER}/', 1)})"
            if target.startswith(("http://", "https://", "mailto:", "#")):
                return f"{label}({target})"
            if target.startswith("/") and not target.startswith("//"):
                repo_target, fragment = normalize_relative_target(Path("README.md"), target.lstrip("/"))
            else:
                repo_target, fragment = normalize_relative_target(source, target)
            if repo_target is None:
                return f"{label}({target})"
            internal = documentation_url(repo_target, fragment, markdown_pages, artifact_paths, directory_pages)
            if internal:
                return f"{label}({internal})"
            return f"{label}({repo_source_url(repo_target, fragment)})"

        raw = IMAGE_LINK_RE.sub(lambda match: rewrite_target(match.group(1), match.group(2)), raw)
        lines.append(LINK_RE.sub(lambda match: rewrite_target(f"[{match.group(1)}]", match.group(2)), raw))
    return "\n".join(lines)


def output_path_for(source: Path, documentation_directories: set[Path]) -> Path:
    default_route = site_route_for(source.with_suffix(""))
    actual_route = source_route_for(source, documentation_directories)
    if actual_route != default_route:
        return CONTENT_SOURCE_ROOT / actual_route.with_suffix(".md")
    return (CONTENT_SOURCE_ROOT / content_path_for(source)).with_suffix(".md")


def render_source_page(
    source: Path,
    markdown_pages: dict[Path, str],
    artifact_paths: set[Path],
    directory_pages: dict[Path, str]
) -> str:
    original = (REPO_ROOT / source).read_text(encoding="utf-8")
    fields = {
        "title": extract_title(original, source),
        "description": extract_description(original),
        "source_path": source.as_posix(),
        "source_sha256": sha256_text(original),
        "weight": 100,
        **classify(source, original)
    }
    source_callout = (
        '{{< proof-status state="public" label="Source-backed mirror" '
        f'source="{source.as_posix()}" >}}}}\n'
        "This page is generated from the public repository source file. "
        "Edit the source file, then run `python3 site/scripts/sync_source_docs.py` "
        "to refresh the Hugo mirror.\n"
        "{{< /proof-status >}}"
    )
    body = rewrite_links(strip_first_h1(original), source, markdown_pages, artifact_paths, directory_pages)
    return (
        f"{json_front_matter(fields)}\n\n"
        "<!-- Generated by site/scripts/sync_source_docs.py; do not edit by hand. -->\n\n"
        f"{source_callout}\n\n"
        f"{body.rstrip()}\n"
    )


def render_source_index(sources: list[Path], artifacts: list[Path]) -> str:
    fields = {
        "title": "Documentation",
        "description": "Hosted mirrors of the public documentation corpus.",
        "weight": 70,
        "maturity": ["public-now", "in-progress"],
        "claim_types": ["documentation"],
        "surfaces": ["docs", "python", "go", "examples", "deploy", "media", "github"],
        "frameworks": ["framework-agnostic"],
        "evidence_levels": ["code-and-doc", "spec", "archival-media", "doc-and-manifest", "limitation-backed"]
    }
    return (
        f"{json_front_matter(fields)}\n\n"
        "<!-- Generated by site/scripts/sync_source_docs.py; do not edit by hand. -->\n\n"
        f"The pages in this section are generated from {len(sources)} public Markdown files in the repo. "
        f"The site also mirrors {len(artifacts)} documentation artifacts such as schemas, mission examples, helper source files, casts, and deployment manifests. "
        "Generated site content, local review context, and dependency/vendor directories are excluded from publication. "
        "The CI check fails when generated documentation drifts from its source hash.\n"
    )


def render_directory_index(
    directory: Path,
    sources: list[Path],
    artifacts: list[Path],
    markdown_pages: dict[Path, str],
    directory_pages: dict[Path, str]
) -> str:
    title = directory.as_posix()
    route = site_route_for(directory)
    direct_sources = [source for source in sources if source.parent == directory]
    direct_artifacts = [artifact for artifact in artifacts if artifact.parent == directory]
    child_directories = [
        child
        for child in directory_pages
        if child != directory and child.parent == directory
    ]
    fields = {
        "title": title,
        "description": f"Hosted documentation and artifacts under {title}.",
        "weight": 80,
        "maturity": ["public-now", "in-progress"],
        "claim_types": ["documentation"],
        "surfaces": [route.parts[0]],
        "frameworks": ["framework-agnostic"],
        "evidence_levels": ["code-and-doc"]
    }
    return (
        f"{json_front_matter(fields)}\n\n"
        "<!-- Generated by site/scripts/sync_source_docs.py; do not edit by hand. -->\n\n"
        f"This section lists hosted documentation and mirrored artifacts generated from `{title}/`.\n"
        f"{render_directory_listing('Hosted Docs', direct_sources, markdown_pages)}"
        f"{render_artifact_listing(direct_artifacts)}"
        f"{render_child_directory_listing(child_directories, directory_pages)}"
    )


def render_directory_listing(title: str, sources: list[Path], markdown_pages: dict[Path, str]) -> str:
    if not sources:
        return ""
    lines = [f"\n## {title}\n"]
    for source in sorted(sources, key=lambda p: p.as_posix()):
        lines.append(f"- [`{source.name}`]({internal_url(markdown_pages[source])})")
    return "\n".join(lines) + "\n"


def render_artifact_listing(artifacts: list[Path]) -> str:
    if not artifacts:
        return ""
    lines = ["\n## Hosted Artifacts\n"]
    for artifact in sorted(artifacts, key=lambda p: p.as_posix()):
        lines.append(f"- [`{artifact.name}`]({internal_url(f'repo/{artifact.as_posix()}')})")
    return "\n".join(lines) + "\n"


def render_child_directory_listing(child_directories: list[Path], directory_pages: dict[Path, str]) -> str:
    if not child_directories:
        return ""
    lines = ["\n## Child Sections\n"]
    for child in sorted(child_directories, key=lambda p: p.as_posix()):
        lines.append(f"- [`{child.name}/`]({internal_url(directory_pages[child])})")
    return "\n".join(lines) + "\n"


def render_capabilities_data() -> str:
    source = Path("media/selected-assets.json")
    original = (REPO_ROOT / source).read_text(encoding="utf-8")
    payload = json.loads(original)
    for index, asset in enumerate(payload.get("included_now", [])):
        for field in ("id", "title", "kind", "proof_scope", "path"):
            if not asset.get(field):
                raise SystemExit(f"capability asset #{index} is missing {field}")
        media_path = REPO_ROOT / asset["path"]
        if not media_path.exists():
            raise SystemExit(f"capability asset path does not exist: {asset['path']}")
    output = {
        "source_path": source.as_posix(),
        "source_sha256": sha256_text(original),
        "asset_class": payload["asset_class"],
        "asset_class_note": payload["asset_class_note"],
        "included_now": payload.get("included_now", [])
    }
    if payload.get("next_candidates"):
        output["next_candidates"] = payload["next_candidates"]
    return json.dumps(output, indent=2, sort_keys=True) + "\n"


def render_source_routes(
    markdown_pages: dict[Path, str],
    artifacts: list[Path],
    directory_pages: dict[Path, str]
) -> str:
    output = {
        "markdown": {
            source.as_posix(): route
            for source, route in sorted(markdown_pages.items(), key=lambda item: item[0].as_posix())
        },
        "directories": {
            directory.as_posix(): route
            for directory, route in sorted(directory_pages.items(), key=lambda item: item[0].as_posix())
        },
        "artifacts": {
            artifact.as_posix(): f"repo/{artifact.as_posix()}"
            for artifact in sorted(artifacts, key=lambda path: path.as_posix())
        }
    }
    return json.dumps(output, indent=2, sort_keys=True) + "\n"


def write_or_check(path: Path, expected: str, check: bool, failures: list[str]) -> None:
    if check:
        try:
            current = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            failures.append(f"missing generated file: {path.relative_to(REPO_ROOT)}")
            return
        if current != expected:
            failures.append(f"stale generated file: {path.relative_to(REPO_ROOT)}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(expected, encoding="utf-8")


def copy_or_check(path: Path, source: Path, check: bool, failures: list[str]) -> None:
    expected = source.read_bytes()
    if check:
        try:
            current = path.read_bytes()
        except FileNotFoundError:
            failures.append(f"missing mirrored artifact: {path.relative_to(REPO_ROOT)}")
            return
        if current != expected:
            failures.append(f"stale mirrored artifact: {path.relative_to(REPO_ROOT)}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(expected)


def remove_stale(expected_paths: set[Path], check: bool, failures: list[str]) -> None:
    if not CONTENT_SOURCE_ROOT.exists():
        return
    existing = {p for p in CONTENT_SOURCE_ROOT.rglob("*.md") if p.is_file()}
    stale = sorted(existing - expected_paths)
    if check and stale:
        failures.extend(f"stale generated file should be removed: {p.relative_to(REPO_ROOT)}" for p in stale)
        return
    for path in stale:
        path.unlink()
    for directory in sorted(CONTENT_SOURCE_ROOT.rglob("*"), reverse=True):
        if directory.is_dir() and not any(directory.iterdir()):
            directory.rmdir()


def remove_stale_artifacts(expected_paths: set[Path], check: bool, failures: list[str]) -> None:
    if not STATIC_ARTIFACT_ROOT.exists():
        return
    existing = {p for p in STATIC_ARTIFACT_ROOT.rglob("*") if p.is_file()}
    stale = sorted(existing - expected_paths)
    if check and stale:
        failures.extend(f"stale mirrored artifact should be removed: {p.relative_to(REPO_ROOT)}" for p in stale)
        return
    for path in stale:
        path.unlink()
    for directory in sorted(STATIC_ARTIFACT_ROOT.rglob("*"), reverse=True):
        if directory.is_dir() and not any(directory.iterdir()):
            directory.rmdir()


def sync(check: bool) -> int:
    sources = discover_markdown()
    artifacts = discover_artifacts()
    artifact_paths = set(artifacts)
    documentation_directories = {
        parent
        for source in sources
        for parent in source.parents
        if parent != Path(".")
    }
    documentation_directories.update(
        parent
        for artifact in artifacts
        for parent in artifact.parents
        if parent != Path(".")
    )
    markdown_pages = {source: source_page_path(source, documentation_directories) for source in sources}
    directory_pages = {directory: directory_page_path(directory) for directory in documentation_directories}
    failures: list[str] = []
    expected_paths: set[Path] = {CONTENT_SOURCE_ROOT / "_index.md"}
    expected_paths.update(
        CONTENT_SOURCE_ROOT / content_path_for(directory) / "_index.md"
        for directory in documentation_directories
    )
    expected_paths.update(output_path_for(source, documentation_directories) for source in sources)
    expected_artifacts: set[Path] = {STATIC_ARTIFACT_ROOT / artifact for artifact in artifacts}

    if not check:
        remove_stale(expected_paths, check, failures)
        remove_stale_artifacts(expected_artifacts, check, failures)

    write_or_check(CONTENT_SOURCE_ROOT / "_index.md", render_source_index(sources, artifacts), check, failures)
    write_or_check(SOURCE_ROUTES_OUTPUT, render_source_routes(markdown_pages, artifacts, directory_pages), check, failures)
    for directory in sorted(documentation_directories, key=lambda p: p.as_posix()):
        output = CONTENT_SOURCE_ROOT / content_path_for(directory) / "_index.md"
        write_or_check(
            output,
            render_directory_index(directory, sources, artifacts, markdown_pages, directory_pages),
            check,
            failures
        )

    for source in sources:
        output = output_path_for(source, documentation_directories)
        write_or_check(
            output,
            render_source_page(source, markdown_pages, artifact_paths, directory_pages),
            check,
            failures
        )

    for artifact in artifacts:
        output = STATIC_ARTIFACT_ROOT / artifact
        copy_or_check(output, REPO_ROOT / artifact, check, failures)

    write_or_check(CAPABILITIES_OUTPUT, render_capabilities_data(), check, failures)
    if check:
        remove_stale(expected_paths, check, failures)
        remove_stale_artifacts(expected_artifacts, check, failures)

    if failures:
        for failure in failures:
            print(f"source sync failed: {failure}", file=sys.stderr)
        print("Run: python3 site/scripts/sync_source_docs.py", file=sys.stderr)
        return 1

    if check:
        print(f"verified {len(sources)} source-backed Hugo pages")
        print(f"verified {len(artifacts)} mirrored documentation artifacts")
    else:
        print(f"generated {len(sources)} source-backed Hugo pages")
        print(f"mirrored {len(artifacts)} documentation artifacts")
        print(f"generated {CAPABILITIES_OUTPUT.relative_to(REPO_ROOT)}")
        print(f"generated {SOURCE_ROUTES_OUTPUT.relative_to(REPO_ROOT)}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if generated files are stale")
    args = parser.parse_args()
    return sync(check=args.check)


if __name__ == "__main__":
    raise SystemExit(main())
