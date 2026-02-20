# String Analyzer 🕵️‍♂️

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

A powerful Python tool to extract and analyze printable strings from binary files. Ideal for **malware analysts**, **reverse engineers**, and **forensics investigators** to uncover hidden indicators and generate AI-assisted analysis prompts.

---

## 🔍 Features

- **String extraction**: Printable ASCII sequences with configurable minimum length (default 4) and optional max read size for large files.
- **Entropy**: Shannon entropy for the whole file; high entropy can indicate packed or encrypted data.
- **Pattern detection**:
  - IPv4 & IPv6, URLs, emails, Windows registry keys, system paths, DLLs, filenames.
  - 300+ Windows API names, CMD and PowerShell commands.
  - Obfuscation patterns (e.g. `h[.]xxp`, dotted IPs).
- **Decoding**: Base64 and hex decoding of candidate strings.
- **Suspicious keywords**: Malware-related terms and .NET namespaces.
- **Output**: Unfiltered string dump, categorized report, or an AI-ready markdown prompt.
- **CLI & API**: Full CLI with options and a programmatic `analyze_file()` API; no global state.

---

## 📦 Installation

```bash
git clone https://github.com/anpa1200/String-Analyzer-.git && cd String-Analyzer-
python3 -m venv venv
source venv/bin/activate   # or: venv\Scripts\activate on Windows
pip install -e .
```

No external runtime dependencies (Python stdlib only). For development: `pip install -e ".[dev]"` (adds pytest and ruff).

---

## 🚀 Usage

### Command line

After `pip install -e .` you get the `string-analyzer` command. Or run from the project root: `python -m string_analyzer`.

```bash
# Filtered report (default)
string-analyzer /path/to/binary.bin -o report.txt

# Unfiltered: all extracted strings
string-analyzer /path/to/binary.bin --unfiltered -o strings.txt

# AI prompt
string-analyzer /path/to/binary.bin --ai-prompt -o prompt.md

# Options: --min-length 6, --max-bytes 10000000, --quiet, --verbose
string-analyzer --help
```

### Interactive (legacy)

```bash
python3 string_analyser.py
# Then enter file path and follow prompts (unfiltered / filtered / AI prompt).
```

### Programmatic API

```python
from string_analyzer import analyze_file, extract_strings, detect_patterns

result = analyze_file("sample.bin")
print(result["entropy"], result["obfuscated"])
print(result["patterns"]["URLS"])

# Or step by step:
strings = extract_strings("sample.bin", min_length=4)
patterns = detect_patterns(strings)  # Fresh dict every time
```

---

## 📖 Function overview

| Function | Description |
|----------|--------------|
| `extract_strings(path, min_length=4, max_bytes=None)` | Extract unique printable strings. |
| `compute_file_entropy(path)` | Shannon entropy over file bytes. |
| `shannon_entropy(s)` | Shannon entropy of a string. |
| `detect_patterns(strings)` | Returns a new dict of categories → sets (no global state). |
| `is_mostly_printable(s, threshold=0.9)` | Whether string is mostly printable ASCII. |
| `try_base64_decode(s)` / `try_hex_decode(s)` | Decode candidates; return decoded string or `None`. |
| `generate_normal_output(...)` / `generate_ai_prompt(...)` | Formatted report or AI prompt text. |
| `analyze_file(path, ...)` | Full analysis: entropy, strings, patterns, obfuscated flag. |

---

## 🛠️ Example

```bash
$ string-analyzer sample.bin --ai-prompt -o mal_prompt.txt
AI prompt saved -> mal_prompt.txt
```

---

## 🧪 Tests and CI

```bash
pytest tests/ -v
```

CI runs on push/PR: Ruff lint and pytest on Python 3.8, 3.10, 3.12.

---

## 📜 License

Distributed under the **GNU General Public License v3.0**. See [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome. Please open an issue or submit a pull request.
