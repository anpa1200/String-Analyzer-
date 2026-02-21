"""
Command-line interface for String Analyzer.
Single entry point: CLI with optional interactive mode.
"""

import argparse
import logging
import sys
from pathlib import Path

from string_analyzer import __version__
from string_analyzer.analyzer import (
    compute_file_entropy,
    detect_patterns,
    extract_strings,
    generate_ai_prompt,
    generate_normal_output,
    is_likely_obfuscated,
)
from string_analyzer.patterns import ENTROPY_THRESHOLD, MIN_USEFUL_COUNT

logger = logging.getLogger("string_analyzer")

# Max bytes to read by default in interactive mode (safety)
INTERACTIVE_MAX_BYTES = 50_000_000


def _positive_int(value: str) -> int:
    v = int(value)
    if v <= 0:
        raise argparse.ArgumentTypeError(f"{value} is not a positive integer")
    return v


def parse_args(args: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract and analyze printable strings from binary files. "
        "Ideal for malware analysis and forensics. Run with no arguments for interactive mode.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "file",
        type=Path,
        nargs="?",
        default=None,
        help="Path to the binary file to analyze (omit for interactive mode)",
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
        "--encoding",
        choices=["ascii", "utf16", "both"],
        default="both",
        help="String encoding to extract: ascii, utf16, or both (default: both, most sensitive)",
    )
    parser.add_argument(
        "--sensitive",
        action="store_true",
        help="Use lower thresholds for obfuscation detection; more suspicious keywords",
    )
    parser.add_argument(
        "--no-embedded",
        action="store_true",
        help="Do not extract URLs/IPs/emails from inside long strings",
    )
    parser.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="Run in interactive mode (prompt for file and options)",
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


def _run_interactive() -> int:
    """Interactive mode: prompt for file path and output type."""
    print("String Analyzer — interactive mode")
    print("----------------------------------")
    try:
        raw = input("Path to file: ").strip()
        if not raw:
            print("No path given. Exiting.")
            return 0
        path = Path(raw).expanduser().resolve()
        if not path.exists():
            print(f"Error: File not found: {path}")
            return 1
        if not path.is_file():
            print(f"Error: Not a file: {path}")
            return 1
    except (KeyboardInterrupt, EOFError):
        print("\nAborted.")
        return 130

    try:
        file_size = path.stat().st_size
        if file_size > INTERACTIVE_MAX_BYTES:
            print(f"Warning: file is {file_size / (1 << 20):.1f} MB; only first {INTERACTIVE_MAX_BYTES / (1 << 20):.0f} MB will be read.")
    except OSError:
        pass
    try:
        file_entropy = compute_file_entropy(path, max_bytes=INTERACTIVE_MAX_BYTES)
        strings = extract_strings(
            path,
            min_length=4,
            max_bytes=INTERACTIVE_MAX_BYTES,
            encoding="both",
        )
    except PermissionError:
        print(f"Error: Permission denied reading {path}")
        return 1
    except OSError as e:
        print(f"Error: {e}")
        return 1

    default_out = path.with_name(f"{path.stem}_strings.txt")
    choice = input("Output all extracted strings (unfiltered)? [y/N]: ").strip().lower()
    if choice in ("y", "yes"):
        out_raw = input(f"Output file [{default_out}]: ").strip() or str(default_out)
        out_path = Path(out_raw).expanduser().resolve()
        try:
            with open(out_path, "w", encoding="utf-8") as f:
                for s in sorted(strings):
                    f.write(s + "\n")
            print(f"Saved {len(strings)} strings -> {out_path}")
        except OSError as e:
            print(f"Error writing output: {e}")
            return 1
        return 0

    found = detect_patterns(strings, extract_embedded=True)
    obfuscated = is_likely_obfuscated(found, file_entropy, sensitive=True)
    choice = input("Generate AI prompt (otherwise filtered report)? [y/N]: ").strip().lower()
    do_ai = choice in ("y", "yes")
    out_raw = input(f"Output file [{default_out}]: ").strip() or str(default_out)
    out_path = Path(out_raw).expanduser().resolve()
    text = (
        generate_ai_prompt(found, file_entropy, obfuscated)
        if do_ai
        else generate_normal_output(found, file_entropy, obfuscated)
    )
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"Saved -> {out_path}")
    except OSError as e:
        print(f"Error writing output: {e}")
        return 1
    return 0


def _validate_file(path: Path) -> str | None:
    """Return error message if path is invalid, else None."""
    try:
        if not path.exists():
            return f"File not found: {path}"
        if not path.is_file():
            return f"Not a file: {path}"
        path.read_bytes()  # ensure readable
    except PermissionError:
        return f"Permission denied: {path}"
    except OSError as e:
        return str(e)
    return None


def main(args: list[str] | None = None) -> int:
    ns = parse_args(args)
    logging.basicConfig(
        level=logging.DEBUG if ns.verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
    )

    # Interactive: no file or explicit --interactive
    if ns.file is None or ns.interactive:
        return _run_interactive()

    path = ns.file.expanduser().resolve()
    err = _validate_file(path)
    if err:
        logger.error("%s", err)
        return 1

    try:
        file_entropy = compute_file_entropy(path, max_bytes=ns.max_bytes)
        strings = extract_strings(
            path,
            min_length=ns.min_length,
            max_bytes=ns.max_bytes,
            encoding=ns.encoding,
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
    else:
        out_path = out_path.expanduser().resolve()

    if ns.unfiltered:
        try:
            with open(out_path, "w", encoding="utf-8") as f:
                for s in sorted(strings):
                    f.write(s + "\n")
        except OSError as e:
            logger.error("Cannot write output: %s", e)
            return 1
        if not ns.quiet:
            print(f"Extracted {len(strings)} strings -> {out_path}")
        return 0

    found = detect_patterns(strings, extract_embedded=not ns.no_embedded)
    obfuscated = is_likely_obfuscated(found, file_entropy, sensitive=ns.sensitive)

    if ns.ai_prompt:
        text = generate_ai_prompt(found, file_entropy, obfuscated)
    else:
        text = generate_normal_output(found, file_entropy, obfuscated)

    try:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(text)
    except OSError as e:
        logger.error("Cannot write output: %s", e)
        return 1
    if not ns.quiet:
        mode = "AI prompt" if ns.ai_prompt else "Filtered results"
        print(f"{mode} saved -> {out_path}")
    return 0


def run() -> None:
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        sys.exit(130)
    except BrokenPipeError:
        sys.exit(0)


if __name__ == "__main__":
    run()
