"""
Command-line interface for String Analyzer.
"""

import argparse
import logging
import sys
from pathlib import Path

from string_analyzer import __version__
from string_analyzer.analyzer import (
    analyze_file,
    compute_file_entropy,
    detect_patterns,
    extract_strings,
    generate_ai_prompt,
    generate_normal_output,
    is_likely_obfuscated,
)

logger = logging.getLogger("string_analyzer")


def _positive_int(value: str) -> int:
    v = int(value)
    if v <= 0:
        raise argparse.ArgumentTypeError(f"{value} is not a positive integer")
    return v


def parse_args(args: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract and analyze printable strings from binary files. "
        "Ideal for malware analysis and forensics.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "file",
        type=Path,
        help="Path to the binary file to analyze",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        metavar="PATH",
        help="Output file path (default: <basename>_strings.txt)",
    )
    parser.add_argument(
        "--min-length",
        type=_positive_int,
        default=4,
        metavar="N",
        help="Minimum string length to extract",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=None,
        metavar="N",
        help="Stop reading file after N bytes (safety for huge files)",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--unfiltered",
        action="store_true",
        help="Output all extracted strings (no categorization)",
    )
    mode.add_argument(
        "--filtered",
        action="store_true",
        help="Output categorized strings only (default when not --unfiltered)",
    )
    mode.add_argument(
        "--ai-prompt",
        action="store_true",
        help="Generate AI analysis prompt from categorized strings",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress non-error output",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose logging",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parsed = parser.parse_args(args)
    # Default mode: filtered (unless --unfiltered or --ai-prompt)
    if not parsed.unfiltered and not parsed.ai_prompt:
        parsed.filtered = True
    return parsed


def main(args: list[str] | None = None) -> int:
    ns = parse_args(args)
    logging.basicConfig(
        level=logging.DEBUG if ns.verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
    )

    path = ns.file
    if not path.exists():
        logger.error("File not found: %s", path)
        return 1
    if not path.is_file():
        logger.error("Not a file: %s", path)
        return 1

    try:
        file_entropy = compute_file_entropy(path)
        strings = extract_strings(
            path,
            min_length=ns.min_length,
            max_bytes=ns.max_bytes,
        )
    except PermissionError as e:
        logger.error("Permission denied: %s", e)
        return 1
    except OSError as e:
        logger.error("I/O error: %s", e)
        return 1

    out_path = ns.output
    if out_path is None:
        out_path = path.with_name(f"{path.stem}_strings.txt")

    if ns.unfiltered:
        with open(out_path, "w", encoding="utf-8") as f:
            for s in sorted(strings):
                f.write(s + "\n")
        if not ns.quiet:
            print(f"Extracted {len(strings)} strings -> {out_path}")
        return 0

    found = detect_patterns(strings)
    obfuscated = is_likely_obfuscated(found, file_entropy)

    if ns.ai_prompt:
        text = generate_ai_prompt(found, file_entropy, obfuscated)
    else:
        text = generate_normal_output(found, file_entropy, obfuscated)

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(text)
    if not ns.quiet:
        mode = "AI prompt" if ns.ai_prompt else "Filtered results"
        print(f"{mode} saved -> {out_path}")
    return 0


def run() -> None:
    sys.exit(main())


if __name__ == "__main__":
    run()
