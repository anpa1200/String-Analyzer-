# String Analyzer — Detailed documentation

This document provides extended reference for the String Analyzer tool: workflows, pattern semantics, API details, and troubleshooting.

---

## 1. Typical workflows

### Malware triage

1. Run with `--ai-prompt` to get a markdown prompt containing categorized strings and entropy.
2. Paste the prompt into an AI assistant or use it in your playbook to get a first-pass behavioral summary.
3. Optionally run with `--filtered` and `--verbose` to inspect categories (URLs, registry keys, APIs) manually.

### Reverse engineering

1. Use `--unfiltered -o strings.txt` to get all printable strings.
2. Grep or search for specific APIs, DLLs, or error messages.
3. Use the API in a script to combine with other tools (e.g. only extract and print URLs and IPs).

### Forensics / incident response

1. Run on a memory dump or disk image with `--max-bytes` to limit read size.
2. Save filtered report and AI prompt for documentation.
3. Use `analyze_file()` in Python to integrate with existing pipelines (e.g. batch processing of many files).

### Batch processing (API)

```python
from pathlib import Path
from string_analyzer import analyze_file

for path in Path("samples").glob("*.bin"):
    try:
        r = analyze_file(path, max_bytes=50_000_000)
        if r["obfuscated"]:
            print(f"High entropy / possible packer: {path}")
        # Write r["patterns"], r["entropy"], etc. to your storage or report
    except Exception as e:
        print(f"Error {path}: {e}")
```

---

## 2. Pattern detection details

### String extraction

- Only **printable ASCII** (code points 32–126) is considered part of a string.
- Consecutive printable bytes form one string; any other byte ends the current string and starts a new one.
- **Minimum length** is configurable (default 4). Shorter minimums yield more noise; longer ones can miss short indicators (e.g. short URLs or IP segments in other strings).

### Categories and precedence

Patterns are evaluated in a fixed order; the first match wins. For example, a string that is both a Windows API and contains a URL will be classified as **WINDOWS_API_COMMANDS**. Categories are produced by:

- **Exact matches** (case-insensitive): Windows API names, CMD commands, PowerShell commands.
- **Regex matches**: URLs, IPv4, IPv6, emails, registry keys, system paths, DLL names, file paths, obfuscation patterns.
- **Substring matches**: suspicious keywords, .NET suspicious keywords.
- **Decoding**: Base64 and hex candidates are decoded; if the result is mostly printable, the mapping is stored in DECODED_BASE64 or DECODED_HEX.

### Obfuscation heuristic

A file is marked **obfuscated** (in report and AI prompt) when:

- **Useful pattern count** (Windows API + DLLs + CMD + PowerShell) is below `MIN_USEFUL_COUNT` (default 10), and  
- **File entropy** is above `ENTROPY_THRESHOLD` (default 5.0).

This is a heuristic: packed or encrypted binaries often have high entropy and few readable API/command strings. Legitimate small utilities can also trigger it.

### Pattern data source

All pattern lists and regexes live in `string_analyzer/patterns.py` (single source of truth). Customizing categories or thresholds requires editing that module.

---

## 3. API reference (summary)

- **`analyze_file(filepath, min_length=4, max_bytes=None)`**  
  Returns a dict: `file`, `entropy`, `strings`, `patterns`, `obfuscated`. Raises `FileNotFoundError` or `ValueError` if the path is missing or not a file.

- **`extract_strings(filepath, min_length=4, max_bytes=None)`**  
  Returns a `set[str]` of unique strings. Does not raise for empty or unreadable files; use normal Python I/O handling if you need strict checks.

- **`detect_patterns(strings)`**  
  Accepts any iterable of strings. Returns a new dict; each key is a category name, each value is a set of strings. No global state; safe to call repeatedly.

- **`generate_normal_output(found_patterns, file_entropy, obfuscated=False)`**  
  Returns a single string (filtered report). Same structure as the default CLI filtered output.

- **`generate_ai_prompt(found_patterns, file_entropy, obfuscated=False)`**  
  Returns a single string (markdown prompt for AI analysis).

- **`is_likely_obfuscated(found_patterns, file_entropy)`**  
  Uses `MIN_USEFUL_COUNT` and `ENTROPY_THRESHOLD` from `string_analyzer.patterns`.

---

## 4. CLI behavior

- **Exit codes:** 0 = success, 1 = error (e.g. file not found, permission denied, write failure), 130 = interrupted (e.g. Ctrl+C).
- **Paths:** File and output paths support `~` (home directory). The CLI resolves them before checking existence or writing.
- **Interactive mode:** If no file argument is given (or `-i` is used), the program prompts for file path and output type. Input size is capped (e.g. 50 MB) in interactive mode to avoid accidental resource use.

---

## 5. Troubleshooting

| Issue | Suggestion |
|-------|------------|
| No strings or very few categories | Increase `--min-length` or check that the file actually contains printable ASCII (e.g. not fully packed/encrypted). |
| Tool is slow or uses a lot of memory | Use `--max-bytes` to limit how much of the file is read. |
| “Permission denied” | Ensure the process can read the file and write to the output path. Run with appropriate user/permissions. |
| Want different categories or thresholds | Edit `string_analyzer/patterns.py` (PATTERN_CATEGORIES, MIN_USEFUL_COUNT, ENTROPY_THRESHOLD, and the pattern lists/regexes). |
| Need to process huge or remote files | Use the API with `max_bytes` and your own I/O (e.g. stream or partial read) if you need behavior not provided by the current file-based API. |

---

## 6. Version and compatibility

- **Python:** 3.8+.
- **Dependencies:** None at runtime (stdlib only).
- **Package version:** Exposed as `string_analyzer.__version__` (e.g. `2.0.0`).

For release history and changes, see the repository [CHANGELOG.md](../CHANGELOG.md).
