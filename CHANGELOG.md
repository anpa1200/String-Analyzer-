# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2025-02-20

### Added

- **Package layout**: Installable Python package `string_analyzer` with `pyproject.toml`.
- **CLI**: Full argument parsing (`string-analyzer file [options]`) with `--output`, `--min-length`, `--max-bytes`, `--unfiltered`, `--filtered`, `--ai-prompt`, `--quiet`, `--verbose`.
- **Programmatic API**: `analyze_file(path)` returns a dict with `entropy`, `strings`, `patterns`, and `obfuscated` flag; `detect_patterns(strings)` returns a fresh dict (no global state).
- **Safety**: Optional `max_bytes` limit when reading large files.
- **Type hints**: Full type annotations across the codebase.
- **Tests**: Pytest suite for entropy, extraction, pattern detection, and output generation.
- **CI**: GitHub Actions for lint (Ruff) and test (Python 3.8, 3.10, 3.12).
- **Documentation**: README aligned with GPL-3.0 license badge; CHANGELOG and .gitignore.

### Fixed

- **Duplicate logic**: Removed duplicated block that extended Windows API and suspicious keywords twice (lines 224–261 in original), fixing double-extension and overwritten keyword lists.
- **Global state**: `detect_patterns()` no longer mutates a module-level dict; each call returns a new result dict, making the module safe for library and repeated use.
- **License**: README badge and wording now match the project license (GPL-3.0).

### Changed

- **Pattern data**: Centralized in `string_analyzer/patterns.py` (single source of truth).
- **Backward compatibility**: `string_analyser.py` remains a launcher; with no arguments it runs interactive mode; with arguments it delegates to the new CLI.

## [1.x] - Original single-script version

- String extraction, entropy, pattern detection, AI prompt and filtered output.
- Interactive prompts only; no CLI flags.
