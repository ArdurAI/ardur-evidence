#!/usr/bin/env python3
"""Validate Ardur's built Python distributions before publication."""

from __future__ import annotations

import argparse
import configparser
import email.policy
import re
import stat
import tarfile
import zipfile
from datetime import date
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import BinaryIO

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 release runner
    import tomli as tomllib


REPO_ROOT = Path(__file__).resolve().parents[1]
PYTHON_ROOT = REPO_ROOT / "python"
SOURCE_PLUGIN = REPO_ROOT / "plugins" / "claude-code"
CHANGELOG = REPO_ROOT / "CHANGELOG.md"
CHANGELOG_RELEASE_HEADING = re.compile(
    r"^## \[(?P<version>[^]]+)\] — (?P<release_date>\S+)$", re.MULTILINE
)
EXPECTED_URLS = {
    "Homepage": "https://github.com/ArdurAI/ardur-evidence",
    "Documentation": "https://github.com/ArdurAI/ardur-evidence/tree/main/docs",
    "Repository": "https://github.com/ArdurAI/ardur-evidence",
    "Issues": "https://github.com/ArdurAI/ardur-evidence/issues",
    "Discussions": "https://github.com/ArdurAI/ardur-evidence/discussions",
}
EXPECTED_SUMMARY = "Runtime governance and signed evidence for AI agent tool calls"
EXPECTED_OS_CLASSIFIER = "Operating System :: POSIX"
PLUGIN_ASSETS = (
    PurePosixPath(".claude-plugin/plugin.json"),
    PurePosixPath("hooks/hooks.json"),
    PurePosixPath("hooks/post_tool_use"),
    PurePosixPath("hooks/post_tool_use_failure"),
    PurePosixPath("hooks/pre_tool_use"),
    PurePosixPath("hooks/subagent_start"),
    PurePosixPath("hooks/subagent_stop"),
)
REQUIRED_RUNTIME_FILES = (
    PurePosixPath("vibap/drp.py"),
    PurePosixPath("vibap/drp_conformance.py"),
    PurePosixPath("vibap/drp_fixture.py"),
    PurePosixPath("vibap/launch_gate.py"),
    PurePosixPath("vibap/linux_benchmark.py"),
    PurePosixPath("vibap/offline_verification.py"),
    PurePosixPath("vibap/offline_verification_fixture.py"),
    PurePosixPath("vibap/policy_conformance.py"),
    PurePosixPath("vibap/runtime_evidence.py"),
    PurePosixPath("vibap/transparency.py"),
)
VENDORED_RFC8785_FILES = (
    PurePosixPath("vibap/_vendor/rfc8785/LICENSE"),
    PurePosixPath("vibap/_vendor/rfc8785/UPSTREAM.md"),
    PurePosixPath("vibap/_vendor/rfc8785/__init__.py"),
    PurePosixPath("vibap/_vendor/rfc8785/_impl.py"),
)


class DistributionValidationError(ValueError):
    """A release artifact violates the publication contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DistributionValidationError(message)


def validate_changelog_text(changelog: str, expected_version: str) -> None:
    unreleased_matches = list(
        re.finditer(r"^## \[Unreleased\]$", changelog, re.MULTILINE)
    )
    require(
        len(unreleased_matches) == 1,
        "changelog must contain exactly one Unreleased heading",
    )
    matches = [
        match
        for match in CHANGELOG_RELEASE_HEADING.finditer(changelog)
        if match.group("version") == expected_version
    ]
    require(
        len(matches) == 1,
        f"changelog must contain exactly one release heading for {expected_version}",
    )
    release_date = matches[0].group("release_date")
    try:
        parsed_date = date.fromisoformat(release_date)
    except ValueError as exc:
        raise DistributionValidationError(
            f"changelog release date is not valid ISO YYYY-MM-DD: {release_date}"
        ) from exc
    require(
        parsed_date.isoformat() == release_date,
        f"changelog release date is not canonical ISO YYYY-MM-DD: {release_date}",
    )
    require(
        unreleased_matches[0].start() < matches[0].start(),
        "changelog Unreleased heading must precede the current release heading",
    )


def one(paths: list[Path], description: str) -> Path:
    require(len(paths) == 1, f"expected one {description}, found {len(paths)}")
    return paths[0]


def safe_archive_path(raw_name: str) -> PurePosixPath:
    path = PurePosixPath(raw_name)
    require(bool(raw_name), "archive contains an empty path")
    require(not path.is_absolute(), f"archive path is absolute: {raw_name}")
    require(".." not in path.parts, f"archive path traverses upward: {raw_name}")
    require("\\" not in raw_name, f"archive path contains a backslash: {raw_name}")
    return path


def project() -> dict[str, object]:
    with (PYTHON_ROOT / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)["project"]


def plugin_files() -> dict[PurePosixPath, Path]:
    files: dict[PurePosixPath, Path] = {}
    for relative_path in PLUGIN_ASSETS:
        path = SOURCE_PLUGIN / relative_path
        require(not path.is_symlink(), f"canonical plugin asset is a symlink: {path}")
        require(path.is_file(), f"canonical plugin asset is missing: {path}")
        files[PurePosixPath("vibap/_plugins/claude-code") / relative_path] = path
    return files


def embedded_schema_files() -> dict[PurePosixPath, Path]:
    source_root = PYTHON_ROOT / "vibap" / "_specs"
    files: dict[PurePosixPath, Path] = {}
    for path in sorted(source_root.glob("*.schema.json")):
        require(not path.is_symlink(), f"embedded schema is a symlink: {path}")
        require(path.is_file(), f"embedded schema is not a regular file: {path}")
        files[PurePosixPath("vibap/_specs") / path.name] = path
    require(bool(files), "no embedded schemas found in the Python source tree")
    return files


def file_mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def read_required(handle: BinaryIO | None, description: str) -> bytes:
    require(handle is not None, f"could not read {description}")
    return handle.read()


def validate_metadata(metadata_bytes: bytes, expected_version: str) -> None:
    metadata = BytesParser(policy=email.policy.default).parsebytes(metadata_bytes)
    require(metadata["Name"] == "ardur", "wheel Name must be ardur")
    require(
        metadata["Version"] == expected_version, "wheel version differs from source"
    )
    require(
        metadata["Summary"] == EXPECTED_SUMMARY, "wheel summary differs from source"
    )
    require(metadata["Requires-Python"] == ">=3.10", "Requires-Python must be >=3.10")
    require(metadata["License-Expression"] == "MIT", "license expression must be MIT")
    classifiers = metadata.get_all("Classifier", [])
    require(
        EXPECTED_OS_CLASSIFIER in classifiers,
        "wheel must declare the POSIX operating-system classifier",
    )
    require(
        "Operating System :: OS Independent" not in classifiers,
        "wheel must not claim OS-independent runtime support",
    )
    require(
        "rfc8785<0.2,>=0.1.4" in metadata.get_all("Requires-Dist", []),
        "wheel must declare the RFC 8785 runtime dependency",
    )
    require(
        metadata["Description-Content-Type"] == "text/markdown",
        "README must be Markdown",
    )
    urls: dict[str, str] = {}
    for value in metadata.get_all("Project-URL", []):
        label, separator, url = value.partition(", ")
        require(bool(separator), f"invalid Project-URL metadata: {value}")
        urls[label] = url
    require(
        urls == EXPECTED_URLS, "wheel project URLs differ from canonical ArdurAI URLs"
    )


def validate_wheel(wheel_path: Path, expected_version: str) -> None:
    expected_name = f"ardur-{expected_version}-py3-none-any.whl"
    require(
        wheel_path.name == expected_name,
        f"unexpected wheel filename: {wheel_path.name}",
    )
    with zipfile.ZipFile(wheel_path) as archive:
        infos = archive.infolist()
        names: dict[PurePosixPath, zipfile.ZipInfo] = {}
        for info in infos:
            path = safe_archive_path(info.filename)
            require(path not in names, f"wheel contains a duplicate path: {path}")
            archived_mode = info.external_attr >> 16
            require(
                not stat.S_ISLNK(archived_mode), f"wheel contains a symlink: {path}"
            )
            require(
                not info.is_dir() or info.file_size == 0,
                f"non-empty wheel directory: {path}",
            )
            names[path] = info
        metadata_path = one(
            [
                Path(str(path))
                for path in names
                if str(path).endswith(".dist-info/METADATA")
            ],
            "wheel METADATA",
        )
        dist_info = PurePosixPath(metadata_path.as_posix()).parent
        validate_metadata(archive.read(metadata_path.as_posix()), expected_version)
        wheel_metadata = archive.read((dist_info / "WHEEL").as_posix()).decode("utf-8")
        require(
            "Tag: py3-none-any" in wheel_metadata, "wheel must be platform independent"
        )
        entry_points = configparser.ConfigParser(interpolation=None)
        entry_points.read_string(
            archive.read((dist_info / "entry_points.txt").as_posix()).decode("utf-8")
        )
        require(
            dict(entry_points["console_scripts"])
            == {
                "ardur": "vibap.cli:main",
                "ardur-drp-fixtures": "vibap.drp_conformance:main",
                "ardur-policy-conformance": "vibap.policy_conformance:main",
                "ardur-proxy": "vibap.cli:main",
                "ardur-verify": "vibap.cli:verify_main",
            },
            "console entry points differ from the release contract",
        )
        license_path = dist_info / "licenses" / "LICENSE"
        require(license_path in names, "wheel does not contain the MIT license file")
        require(
            archive.read(license_path.as_posix())
            == (REPO_ROOT / "LICENSE").read_bytes(),
            "wheel license differs from root LICENSE",
        )
        expected_schemas = embedded_schema_files()
        schema_root = PurePosixPath("vibap/_specs")
        actual_schemas = {
            path
            for path, info in names.items()
            if path.parent == schema_root
            and path.name.endswith(".schema.json")
            and not info.is_dir()
        }
        require(
            actual_schemas == set(expected_schemas),
            "wheel embedded schema set differs from the source tree",
        )
        for packaged_path, source_path in expected_schemas.items():
            require(
                archive.read(packaged_path.as_posix()) == source_path.read_bytes(),
                f"wheel embedded schema differs from source: {packaged_path}",
            )
        for runtime_file in REQUIRED_RUNTIME_FILES:
            require(
                runtime_file in names, f"wheel is missing runtime file: {runtime_file}"
            )
        for vendored_file in VENDORED_RFC8785_FILES:
            require(
                vendored_file in names,
                f"wheel is missing vendored RFC 8785 file: {vendored_file}",
            )
            require(
                archive.read(vendored_file.as_posix())
                == (PYTHON_ROOT / vendored_file).read_bytes(),
                f"wheel vendored RFC 8785 file differs from source: {vendored_file}",
            )
        expected_plugin_files = plugin_files()
        plugin_root = PurePosixPath("vibap/_plugins/claude-code")
        actual_plugin_files = {
            path
            for path, info in names.items()
            if path.is_relative_to(plugin_root) and not info.is_dir()
        }
        require(
            actual_plugin_files == set(expected_plugin_files),
            "wheel plugin asset set differs from the release manifest",
        )
        for packaged_path, source_path in expected_plugin_files.items():
            require(
                packaged_path in names,
                f"wheel is missing plugin asset: {packaged_path}",
            )
            info = names[packaged_path]
            require(
                archive.read(packaged_path.as_posix()) == source_path.read_bytes(),
                f"wheel plugin asset differs from source: {packaged_path}",
            )
            archived_mode = (info.external_attr >> 16) & 0o777
            expected_mode = file_mode(source_path)
            require(
                archived_mode == expected_mode,
                f"wheel plugin asset has unexpected mode: {packaged_path}",
            )


def validate_sdist(sdist_path: Path, expected_version: str) -> None:
    expected_name = f"ardur-{expected_version}.tar.gz"
    require(
        sdist_path.name == expected_name,
        f"unexpected sdist filename: {sdist_path.name}",
    )
    root = PurePosixPath(f"ardur-{expected_version}")
    with tarfile.open(sdist_path, mode="r:gz") as archive:
        members = archive.getmembers()
        names: dict[PurePosixPath, tarfile.TarInfo] = {}
        for member in members:
            path = safe_archive_path(member.name)
            require(path not in names, f"sdist contains a duplicate path: {path}")
            require(
                not member.issym() and not member.islnk(),
                f"sdist contains a link: {path}",
            )
            require(not member.isdev(), f"sdist contains a device: {path}")
            require(
                path.parts and path.parts[0] == str(root),
                f"sdist path has wrong root: {path}",
            )
            names[path] = member
        for relative_path in ("pyproject.toml", "README.md", "LICENSE"):
            path = root / relative_path
            require(
                path in names and names[path].isfile(),
                f"sdist is missing {relative_path}",
            )
        for runtime_file in REQUIRED_RUNTIME_FILES:
            path = root / runtime_file
            require(
                path in names and names[path].isfile(),
                f"sdist is missing runtime file: {runtime_file}",
            )
        expected_schemas = embedded_schema_files()
        schema_root = root / "vibap/_specs"
        actual_schemas = {
            path.relative_to(root)
            for path, member in names.items()
            if path.parent == schema_root
            and path.name.endswith(".schema.json")
            and member.isfile()
        }
        require(
            actual_schemas == set(expected_schemas),
            "sdist embedded schema set differs from the source tree",
        )
        for packaged_path, source_path in expected_schemas.items():
            path = root / packaged_path
            require(
                read_required(archive.extractfile(names[path]), str(path))
                == source_path.read_bytes(),
                f"sdist embedded schema differs from source: {path}",
            )
        for vendored_file in VENDORED_RFC8785_FILES:
            path = root / vendored_file
            require(
                path in names and names[path].isfile(),
                f"sdist is missing vendored RFC 8785 file: {vendored_file}",
            )
            require(
                read_required(archive.extractfile(names[path]), str(path))
                == (PYTHON_ROOT / vendored_file).read_bytes(),
                f"sdist vendored RFC 8785 file differs from source: {vendored_file}",
            )
        require(
            read_required(archive.extractfile(names[root / "LICENSE"]), "sdist LICENSE")
            == (REPO_ROOT / "LICENSE").read_bytes(),
            "sdist license differs from root LICENSE",
        )
        expected_plugin_files = plugin_files()
        plugin_root = root / "vibap/_plugins/claude-code"
        actual_plugin_files = {
            path.relative_to(root)
            for path, member in names.items()
            if path.is_relative_to(plugin_root) and member.isfile()
        }
        require(
            actual_plugin_files == set(expected_plugin_files),
            "sdist plugin asset set differs from the release manifest",
        )
        for packaged_path, source_path in expected_plugin_files.items():
            path = root / packaged_path
            require(
                path in names and names[path].isfile(),
                f"sdist is missing plugin asset: {path}",
            )
            require(
                read_required(archive.extractfile(names[path]), str(path))
                == source_path.read_bytes(),
                f"sdist plugin asset differs from source: {path}",
            )
            require(
                stat.S_IMODE(names[path].mode) == file_mode(source_path),
                f"sdist plugin mode differs from source: {path}",
            )


def validate(dist_dir: Path, expected_tag: str | None = None) -> tuple[Path, Path, str]:
    config = project()
    expected_version = str(config["version"])
    require(config["name"] == "ardur", "source project name must be ardur")
    require(
        config["description"] == EXPECTED_SUMMARY,
        "source summary differs from release contract",
    )
    require(config["requires-python"] == ">=3.10", "source Python floor must be >=3.10")
    require(config["license"] == "MIT", "source license expression must be MIT")
    classifiers = config["classifiers"]
    require(
        EXPECTED_OS_CLASSIFIER in classifiers,
        "source must declare the POSIX operating-system classifier",
    )
    require(
        "Operating System :: OS Independent" not in classifiers,
        "source must not claim OS-independent runtime support",
    )
    require(
        config["urls"] == EXPECTED_URLS,
        "source project URLs differ from canonical URLs",
    )
    require(
        "rfc8785>=0.1.4,<0.2" in config["dependencies"],
        "source project must declare the RFC 8785 runtime dependency",
    )
    validate_changelog_text(CHANGELOG.read_text(encoding="utf-8"), expected_version)
    if expected_tag is not None:
        require(
            expected_tag == f"v{expected_version}",
            f"tag {expected_tag!r} must equal v{expected_version}",
        )
    require(dist_dir.is_dir(), f"distribution directory does not exist: {dist_dir}")
    wheel = one(sorted(dist_dir.glob("*.whl")), "wheel")
    sdist = one(sorted(dist_dir.glob("*.tar.gz")), "source distribution")
    require(wheel.is_file() and not wheel.is_symlink(), "wheel must be a regular file")
    require(sdist.is_file() and not sdist.is_symlink(), "sdist must be a regular file")
    dist_entries = set(dist_dir.iterdir())
    require(
        dist_entries == {wheel, sdist},
        "distribution directory must contain only the validated wheel and sdist",
    )
    validate_wheel(wheel, expected_version)
    validate_sdist(sdist, expected_version)
    return wheel, sdist, expected_version


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist-dir", type=Path, required=True)
    parser.add_argument("--expected-tag")
    args = parser.parse_args()
    try:
        wheel, sdist, version = validate(args.dist_dir.resolve(), args.expected_tag)
    except (DistributionValidationError, KeyError, configparser.Error, OSError) as exc:
        print(f"error: {exc}")
        return 1
    print(f"validated ardur {version}: {wheel.name}, {sdist.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
