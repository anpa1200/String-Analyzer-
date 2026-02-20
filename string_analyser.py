#!/usr/bin/env python3
"""
String Analyzer — backward-compatible launcher.

With no arguments: interactive mode (prompts for file path and options).
With arguments: delegates to the string_analyzer CLI (see python -m string_analyzer --help).
"""

import sys
from pathlib import Path

# Prefer package from current directory / venv
try:
    from string_analyzer import __version__
    from string_analyzer.analyzer import (
        compute_file_entropy,
        detect_patterns,
        extract_strings,
        generate_ai_prompt,
        generate_normal_output,
    )
    from string_analyzer.patterns import MIN_USEFUL_COUNT, ENTROPY_THRESHOLD
except ImportError:
    # Fallback: run as module so package is on path
    import subprocess
    sys.exit(subprocess.call([sys.executable, "-m", "string_analyzer"] + sys.argv[1:]))


def _main_interactive() -> None:
    try:
        filename = input("Path to file: ").strip()
        if not filename:
            print("No path given.")
            return
        path = Path(filename)
        if not path.exists():
            print("Error: File not found.")
            return
        if not path.is_file():
            print("Error: Not a file.")
            return

        file_entropy = compute_file_entropy(path)
        file_strings = extract_strings(path)
        default_output = path.with_name(f"{path.stem}_strings.txt")

        all_strings_choice = input(
            "Output all extracted strings (unfiltered)? (yes/no): "
        ).strip().lower()
        if all_strings_choice in ("yes", "y"):
            out_path = input(
                f"Output file (default: {default_output}): "
            ).strip() or str(default_output)
            with open(out_path, "w", encoding="utf-8") as f:
                for s in sorted(file_strings):
                    f.write(s + "\n")
            print(f"All extracted strings saved in {out_path}!")
            return

        found = detect_patterns(file_strings)
        useful_count = (
            len(found["WINDOWS_API_COMMANDS"])
            + len(found["DLLS"])
            + len(found["CMD_COMMANDS"])
            + len(found["POWERSHELL_COMMANDS"])
        )
        obfuscated = useful_count < MIN_USEFUL_COUNT and file_entropy > ENTROPY_THRESHOLD

        ai_choice = input(
            "Create AI prompt for filtered output? (yes/no): "
        ).strip().lower()
        out_path = input(
            f"Output file (default: {default_output}): "
        ).strip() or str(default_output)
        if ai_choice in ("yes", "y"):
            text = generate_ai_prompt(found, file_entropy, obfuscated)
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(text)
            print(f"AI prompt saved in {out_path}!")
        else:
            text = generate_normal_output(found, file_entropy, obfuscated)
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(text)
            print(f"Filtered results saved in {out_path}!")
    except FileNotFoundError as e:
        print(e)
    except KeyboardInterrupt:
        print("\nAborted.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        from string_analyzer.cli import main
        sys.exit(main())
    _main_interactive()
