from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


REPO_ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_PATH = REPO_ROOT / "site" / "scripts" / "validate_llms_output.py"


def load_validator():
    spec = importlib.util.spec_from_file_location(
        "validate_llms_output", VALIDATOR_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


validator = load_validator()


class LlmsOutputValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = TemporaryDirectory()
        self.rendered_root = Path(self.temporary_directory.name)
        for route in ("get-started", "source/readme", "work-in-progress"):
            target = self.rendered_root / route / "index.html"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                "<!doctype html><title>fixture</title>\n", encoding="utf-8"
            )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def valid_text(self) -> str:
        return """# Ardur

> Runtime governance and evidence for configured AI-agent tool paths.

This file is generated from the public evidence site.

## Curated Documentation

- [Get Started](https://ardurai.github.io/ardur-evidence/get-started/): Run the current proof.

## Source-Backed Repository Documentation

- [Ardur](https://ardurai.github.io/ardur-evidence/source/readme/): Source-backed project overview.

## Optional

- [Work in Progress](https://ardurai.github.io/ardur-evidence/work-in-progress/): Active work and boundaries.
"""

    def write_output(self, text: str | None = None) -> None:
        (self.rendered_root / "llms.txt").write_text(
            self.valid_text() if text is None else text,
            encoding="utf-8",
        )

    def test_accepts_canonical_generated_index(self) -> None:
        self.write_output()
        self.assertEqual(validator.validate(self.rendered_root), [])

    def test_rejects_missing_output(self) -> None:
        failures = validator.validate(self.rendered_root)
        self.assertTrue(any("missing" in failure for failure in failures), failures)

    def test_rejects_wrong_section_order(self) -> None:
        text = self.valid_text().replace(
            "## Curated Documentation", "## Unexpected Documentation", 1
        )
        self.write_output(text)
        failures = validator.validate(self.rendered_root)
        self.assertTrue(
            any("unexpected section" in failure for failure in failures), failures
        )
        self.assertTrue(
            any("sections must appear" in failure for failure in failures), failures
        )

    def test_rejects_duplicate_urls_across_sections(self) -> None:
        text = self.valid_text().replace(
            "https://ardurai.github.io/ardur-evidence/work-in-progress/",
            "https://ardurai.github.io/ardur-evidence/get-started/",
        )
        self.write_output(text)
        failures = validator.validate(self.rendered_root)
        self.assertTrue(
            any("duplicate URL" in failure for failure in failures), failures
        )

    def test_rejects_noncanonical_origin(self) -> None:
        text = self.valid_text().replace(
            "https://ardurai.github.io/ardur-evidence/get-started/",
            "https://example.invalid/ardur/get-started/",
        )
        self.write_output(text)
        failures = validator.validate(self.rendered_root)
        self.assertTrue(any("canonical" in failure for failure in failures), failures)

    def test_rejects_invalid_port_without_crashing(self) -> None:
        text = self.valid_text().replace(
            "https://ardurai.github.io/ardur-evidence/get-started/",
            "https://ardurai.github.io:notaport/ardur-evidence/get-started/",
        )
        self.write_output(text)
        failures = validator.validate(self.rendered_root)
        self.assertTrue(any("valid URL" in failure for failure in failures), failures)

    def test_rejects_explicit_zero_port(self) -> None:
        text = self.valid_text().replace(
            "https://ardurai.github.io/ardur-evidence/get-started/",
            "https://ardurai.github.io:0/ardur-evidence/get-started/",
        )
        self.write_output(text)
        failures = validator.validate(self.rendered_root)
        self.assertTrue(any("port" in failure for failure in failures), failures)

    def test_rejects_empty_userinfo(self) -> None:
        text = self.valid_text().replace(
            "https://ardurai.github.io/ardur-evidence/get-started/",
            "https://@ardurai.github.io/ardur-evidence/get-started/",
        )
        self.write_output(text)
        failures = validator.validate(self.rendered_root)
        self.assertTrue(any("credentials" in failure for failure in failures), failures)

    def test_rejects_encoded_path_traversal(self) -> None:
        text = self.valid_text().replace(
            "https://ardurai.github.io/ardur-evidence/get-started/",
            "https://ardurai.github.io/ardur-evidence/%2e%2e/get-started/",
        )
        self.write_output(text)
        failures = validator.validate(self.rendered_root)
        self.assertTrue(any("unsafe" in failure for failure in failures), failures)

    def test_rejects_encoded_control_character_in_path(self) -> None:
        text = self.valid_text().replace(
            "https://ardurai.github.io/ardur-evidence/get-started/",
            "https://ardurai.github.io/ardur-evidence/get%00started/",
        )
        self.write_output(text)
        failures = validator.validate(self.rendered_root)
        self.assertTrue(any("unsafe" in failure for failure in failures), failures)

    def test_rejects_unrendered_target(self) -> None:
        text = self.valid_text().replace("/get-started/", "/missing-page/", 1)
        self.write_output(text)
        failures = validator.validate(self.rendered_root)
        self.assertTrue(
            any("not rendered" in failure for failure in failures), failures
        )

    def test_rejects_llms_symlink(self) -> None:
        outside_directory = TemporaryDirectory()
        self.addCleanup(outside_directory.cleanup)
        outside = Path(outside_directory.name) / "outside.txt"
        outside.write_text(self.valid_text(), encoding="utf-8")
        (self.rendered_root / "llms.txt").symlink_to(outside)

        failures = validator.validate(self.rendered_root)
        self.assertTrue(
            any("regular file" in failure for failure in failures), failures
        )

    def test_rejects_oversized_output_before_reading_it(self) -> None:
        with (self.rendered_root / "llms.txt").open("wb") as output:
            output.truncate(validator.MAX_OUTPUT_BYTES + 1)

        failures = validator.validate(self.rendered_root)
        self.assertTrue(
            any("safety limit" in failure for failure in failures), failures
        )

    def test_rejects_rendered_target_symlink_escape(self) -> None:
        outside_directory = TemporaryDirectory()
        self.addCleanup(outside_directory.cleanup)
        outside = Path(outside_directory.name) / "outside.html"
        outside.write_text("outside\n", encoding="utf-8")
        target = self.rendered_root / "get-started" / "index.html"
        target.unlink()
        target.symlink_to(outside)
        self.write_output()

        failures = validator.validate(self.rendered_root)
        self.assertTrue(any("outside" in failure for failure in failures), failures)

    def test_rejects_provenance_placeholder(self) -> None:
        text = self.valid_text().replace(
            "Run the current proof.", "__ARDUR_SOURCE_REF__"
        )
        self.write_output(text)
        failures = validator.validate(self.rendered_root)
        self.assertTrue(
            any("forbidden marker" in failure for failure in failures), failures
        )

    def test_rejects_multiline_link_injection(self) -> None:
        text = self.valid_text().replace("[Get Started]", "[Get\n- [Injected]", 1)
        self.write_output(text)
        failures = validator.validate(self.rendered_root)
        self.assertTrue(
            any("malformed link entry" in failure for failure in failures), failures
        )

    def test_rejects_unstructured_section_content(self) -> None:
        text = self.valid_text().replace(
            "## Optional\n\n", "## Optional\n\nunexpected injected text\n", 1
        )
        self.write_output(text)
        failures = validator.validate(self.rendered_root)
        self.assertTrue(
            any("unexpected content" in failure for failure in failures), failures
        )

    def test_rejects_tab_control_characters(self) -> None:
        self.write_output(self.valid_text().replace("current proof", "current\tproof"))
        failures = validator.validate(self.rendered_root)
        self.assertTrue(
            any("control characters" in failure for failure in failures), failures
        )


if __name__ == "__main__":
    unittest.main()
