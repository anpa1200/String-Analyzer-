# String Analyzer

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

**String Analyzer** extracts and analyzes printable strings from binary files. It is designed for **malware analysts**, **reverse engineers**, and **forensics investigators** who need to quickly surface URLs, IPs, registry keys, API names, and other indicators from executables, memory dumps, or disk images—and optionally generate an AI-ready analysis prompt.

- **Zero runtime dependencies** (Python standard library only).
- **Single entry point**: one CLI with batch and interactive modes.
- **Library-friendly API**: use `analyze_file()` or lower-level functions in your own scripts.

---

## Table of contents

- [Features](#-features)
- [Installation](#-installation)
- [Quick start](#-quick-start)
- [Usage](#-usage)
  - [Command-line options](#command-line-options)
  - [Output modes](#output-modes)
  - [Interactive mode](#interactive-mode)
- [Pattern categories](#-pattern-categories)
- [Programmatic API](#-programmatic-api)
- [Examples](#-examples)
- [Configuration and limits](#-configuration-and-limits)
- [Security and safety](#-security-and-safety)
- [Development](#-development)
- [License](#-license)

---

## Features

| Feature | Description |
|--------|-------------|
| **String extraction** | ASCII and UTF-16LE (Windows PE); configurable min length and `max_bytes`; chunked read for large files. |
| **Entropy** | Shannon entropy (chunked when `max_bytes` set); high entropy suggests packed/encrypted content. |
| **Pattern detection** | Strict IPv4 (0–255), IPv6 (full and abbreviated), URLs (http/https/ftp/file/ws/wss), obfuscated URLs (hxxp, etc.), emails, MAC addresses, registry keys, system paths, DLLs, 300+ Windows APIs, CMD/PowerShell, obfuscation patterns. |
| **Embedded extraction** | URLs, IPs, emails, MACs found *inside* long strings (not only whole-line matches). |
| **Decoding** | Base64 (standard and URL-safe) and hex; decoded candidates in report. |
| **Suspicious keywords** | Extended set: malware, miner, steal, persist, evasion, etc., plus .NET namespaces. |
| **Sensitive mode** | `--sensitive`: lower obfuscation thresholds and more keywords for stricter triage. |
| **Output formats** | Unfiltered dump, categorized report, or AI-ready markdown prompt. |
| **CLI & API** | Full CLI (`--encoding`, `--sensitive`, `--no-embedded`); programmatic `analyze_file()`; no global state. |

---

## Installation

**Requirements:** Python 3.8 or newer.

```bash
git clone https://github.com/anpa1200/String-Analyzer-.git && cd String-Analyzer-
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -e .
```

After installation you get the `string-analyzer` command. From the project root you can also run:

```bash
python -m string_analyzer
```

**Development (optional):** `pip install -e ".[dev]"` adds pytest and ruff for tests and linting.

---

## Quick start

```bash
# Categorized report (default)
string-analyzer /path/to/binary -o report.txt

# All extracted strings, no categorization
string-analyzer /path/to/binary --unfiltered -o strings.txt

# AI-ready analysis prompt
string-analyzer /path/to/binary --ai-prompt -o prompt.md

# Interactive: prompt for file and output type
string-analyzer
```

---

## Usage

### Command-line options

| Option | Description |
|--------|-------------|
| `file` | Path to the binary file. Omit to run **interactive mode**. |
| `-o`, `--output PATH` | Output file (default: `<basename>_strings.txt`). |
| `--min-length N` | Minimum string length to extract (default: 4). |
| `--max-bytes N` | Stop reading after N bytes (safety for very large files). |
| `--unfiltered` | Output all extracted strings, one per line (no categories). |
| `--filtered` | Output categorized report (default when not using `--unfiltered` or `--ai-prompt`). |
| `--ai-prompt` | Generate markdown prompt for an AI assistant. |
| `--analyze-with {gemini,codex}` | Send categorized prompt to **gemini-cli** or **codex-cli** and print the AI analysis. Saves the prompt to `-o`; use `--ai-output` to save the AI response. |
| `--ai-output PATH` | Save the AI response to this file (when using `--analyze-with`). |
| `--encoding {ascii,utf16,both}` | Extract ASCII only, UTF-16LE only, or both (default: both). |
| `--sensitive` | Lower obfuscation thresholds; more suspicious keywords. |
| `--no-embedded` | Do not extract URLs/IPs/emails from inside long strings. |
| `-i`, `--interactive` | Force interactive mode (prompt for file and options). |
| `-q`, `--quiet` | Suppress non-error messages. |
| `-v`, `--verbose` | Verbose logging. |
| `--version` | Show version. |
| `--help` | Show help. |

### Output modes

1. **Unfiltered** (`--unfiltered`): sorted list of all extracted strings. Use for grepping or feeding into other tools.
2. **Filtered** (default): categorized report with entropy, plus sections such as URLS, IPS, WINDOWS_API_COMMANDS, DLLS, OBFUSCATED, etc.
3. **AI prompt** (`--ai-prompt`): same categories in a markdown prompt asking an AI to analyze behavior and functionality (e.g. for malware triage).

### Interactive mode

Run `string-analyzer` with no file argument (or use `string-analyzer -i`). The tool will:

1. Ask for the file path.
2. Ask whether to output all strings (unfiltered) or a filtered report.
3. If filtered: ask whether to generate an AI prompt or a normal report.
4. Ask for the output file path (with a default suggestion).

Interactive mode limits input to 50 MB by default to avoid accidental resource use.

---

## Pattern categories

Strings are classified into the following categories (empty categories are omitted from output):

| Category | Description |
|----------|-------------|
| `WINDOWS_API_COMMANDS` | Known Windows API function names (300+). |
| `DLLS` | Strings matching typical DLL names (e.g. `*.dll`). |
| `URLS` | HTTP/HTTPS and similar URLs. |
| `IPS` | IPv4 addresses. |
| `IPV6` | IPv6 addresses. |
| `EMAILS` | Email-like strings. |
| `WINDOWS_REGISTRY_KEYS` | Registry path patterns. |
| `POWERSHELL_COMMANDS` | PowerShell cmdlets/commands. |
| `CMD_COMMANDS` | CMD shell commands. |
| `FILES` | File path / filename patterns. |
| `SYSTEM_PATHS` | System directory paths. |
| `OBFUSCATED` | Patterns suggesting obfuscation (e.g. `h[.]xxp`, dotted IPs). |
| `DECODED_BASE64` | Strings that successfully decode from Base64 to printable text. |
| `DECODED_HEX` | Strings that successfully decode from hex to printable text. |
| `SUSPICIOUS_KEYWORDS` | Substrings associated with malware (e.g. key terms). |
| `SUSPICIOUS_DOTNET` | .NET-related suspicious namespaces/keywords. |
| `MAC_ADDRESSES` | MAC addresses (e.g. `00:1A:2B:3C:4D:5E`). |

The tool also computes **file entropy**. Combined with a low count of “useful” patterns (APIs, DLLs, CMD/PowerShell), high entropy can indicate a **packed or obfuscated** binary; this is noted in the report and in the AI prompt.

---

## Programmatic API

Use the package in your own Python code:

```python
from string_analyzer import (
    analyze_file,
    extract_strings,
    detect_patterns,
    compute_file_entropy,
    generate_normal_output,
    generate_ai_prompt,
    shannon_entropy,
)
from string_analyzer.analyzer import (
    is_likely_obfuscated,
    is_mostly_printable,
    try_base64_decode,
    try_hex_decode,
)
```

### One-shot analysis

```python
result = analyze_file(
    "/path/to/binary",
    min_length=4,
    max_bytes=None,
    encoding="both",        # "ascii", "utf16", or "both"
    extract_embedded=True,  # find URLs/IPs inside long strings
    sensitive=False,        # True: lower obfuscation thresholds
)
# result["file"], result["entropy"], result["strings"], result["patterns"], result["obfuscated"]
```

### Step-by-step

```python
from pathlib import Path
path = Path("sample.bin")
entropy = compute_file_entropy(path)
strings = extract_strings(path, min_length=4, max_bytes=10_000_000)
patterns = detect_patterns(strings)  # New dict every time; no global state
obfuscated = is_likely_obfuscated(patterns, entropy)
report = generate_normal_output(patterns, entropy, obfuscated)
# Or: prompt_text = generate_ai_prompt(patterns, entropy, obfuscated)
```

### Function reference

| Function | Description |
|----------|-------------|
| `analyze_file(path, min_length=4, max_bytes=None)` | Full analysis; returns dict with `file`, `entropy`, `strings`, `patterns`, `obfuscated`. |
| `extract_strings(path, min_length=4, max_bytes=None)` | Extract unique printable strings; returns `set[str]`. |
| `compute_file_entropy(path)` | Shannon entropy of file bytes. |
| `shannon_entropy(s)` | Shannon entropy of a string. |
| `detect_patterns(strings)` | Categorize strings; returns new `dict[str, set[str]]`. |
| `is_likely_obfuscated(patterns, file_entropy)` | Heuristic: few “useful” patterns and entropy &gt; threshold. |
| `generate_normal_output(patterns, entropy, obfuscated)` | Formatted filtered report text. |
| `generate_ai_prompt(patterns, entropy, obfuscated)` | Markdown prompt text for AI analysis. |
| `is_mostly_printable(s, threshold=0.9)` | Whether the string is mostly printable ASCII. |
| `try_base64_decode(s)` | Decode Base64 if valid and printable; else `None`. |
| `try_hex_decode(s)` | Decode hex if valid and printable; else `None`. |

---

## Examples

**Malware triage — get an AI prompt for a sample:**

```bash
string-analyzer suspect.exe --ai-prompt -o triage_prompt.md
# Then paste triage_prompt.md into your AI assistant.
```

**Large file — limit read size and get a filtered report:**

```bash
string-analyzer memory.dump --max-bytes 100000000 -o report.txt
```

**Script — use API and only print URLs and IPs:**

```python
from string_analyzer import analyze_file
r = analyze_file("sample.bin")
for s in r["patterns"].get("URLS", []):
    print(s)
for s in r["patterns"].get("IPS", []):
    print(s)
```

**Longer strings only:**

```bash
string-analyzer binary --min-length 8 -o long_strings.txt
```

**Maximum sensitivity (UTF-16 + embedded URLs + lower obfuscation bar):**

```bash
string-analyzer suspect.exe --encoding both --sensitive -o report.txt
```

**Send to Gemini or Codex for AI analysis (requires gemini-cli or codex on PATH):**

```bash
string-analyzer suspect.exe --analyze-with gemini -o prompt.txt --ai-output analysis.md
string-analyzer suspect.exe --analyze-with codex --ai-output analysis.md
```

---

## Configuration and limits

- **Minimum string length:** `--min-length` (default 4). Longer values reduce noise and speed up analysis.
- **Maximum bytes read:** `--max-bytes`. Omit for no limit; set for very large files to avoid high memory use.
- **Obfuscation heuristic:** Implemented using `MIN_USEFUL_COUNT` (default 10) and `ENTROPY_THRESHOLD` (default 5.0) in `string_analyzer.patterns`. A file is flagged as likely obfuscated when the number of “useful” patterns (Windows API, DLLs, CMD, PowerShell) is below the count threshold and file entropy is above the entropy threshold.

---

## Security and safety

- **Input files:** String Analyzer only reads the file and extracts printable strings; it does not execute or interpret code. Still, avoid running it on untrusted binaries in a sensitive environment without proper isolation.
- **Large files:** Use `--max-bytes` (or the `max_bytes` parameter in the API) to cap how much is read; interactive mode uses a 50 MB default.
- **Output:** Reports may contain URLs, IPs, and other indicators. Handle output according to your security and privacy policies.

---

## Development

```bash
pip install -e ".[dev]"
ruff check string_analyzer tests
pytest tests/ -v
```

CI runs on push/PR: Ruff lint and pytest on Python 3.8, 3.10, and 3.12.

For more detail on patterns, heuristics, and workflows, see [docs/DOCUMENTATION.md](docs/DOCUMENTATION.md).

---

## License

Distributed under the **GNU General Public License v3.0**. See [LICENSE](LICENSE) for details.

Contributions are welcome; please open an issue or submit a pull request.
