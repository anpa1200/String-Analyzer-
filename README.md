# String Analyzer 🕵️‍♂️

[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A powerful Python script to extract and analyze printable strings from binaries. Ideal for **malware analysts**, **reverse engineers**, and **forensics investigators** to uncover hidden indicators and generate AI-assisted analysis prompts.

---

## 🔍 Features

This script provides a comprehensive suite of string extraction and analysis capabilities:

- **String Extraction**: Parses a binary file byte by byte to pull out all printable ASCII sequences of a configurable minimum length (default 4 characters). This helps you quickly surface embedded URLs, commands, file paths, and other human-readable artifacts.
- **Entropy Calculation**: Calculates Shannon entropy for both the entire file and individual strings. High entropy may indicate packed or encrypted data blobs, guiding further unpacking or decryption efforts.
- **Regex-Based Pattern Detection**:
  - **IPv4 & IPv6 Addresses**: Identifies potential IP indicators via strict regex, useful for mapping network-based indicators of compromise.
  - **URLs & Domains**: Captures HTTP/HTTPS endpoints embedded in the binary for phishing or command-and-control communication analysis.
  - **Email Addresses**: Finds credential or notification email references, often abused in social engineering or exfiltration tactics.
  - **Windows Registry Keys**: Detects registry access patterns (`HKLM\`, `HKCU\`) to reveal persistence or configuration modifications.
  - **System Paths & Filenames**: Matches common Windows system directories and executable extensions, uncovering potential file-dropping or auto-start locations.
- **Command Identification**:
  - **Windows API Calls**: Recognizes a curated list of 300+ Win32 API functions, indicating possible dynamic loading or function invocation patterns.
  - **CMD Commands**: Filters built-in Windows shell commands (e.g., `dir`, `copy`, `net user`) to detect batch-like activity or script snippets.
  - **PowerShell Cmdlets**: Flags PowerShell-specific commands (e.g., `Get-Process`, `Invoke-Command`) often used in modern attacks or post-exploitation scripts.
- **Obfuscation Pattern Matching**: Uses regex to detect bracketed, dotted, or substituted obfuscated IPs and URLs (e.g., `h[.]xxp[:]//`, `dot` notations), exposing attempts to evade simple string-based detection.
- **Automated Decoding**:
  - **Base64 Decoding**: Automatically decodes long, valid Base64 candidates into readable strings, revealing embedded configuration or secondary payloads.
  - **Hex Decoding**: Converts hex-encoded sequences back to ASCII, unmasking hidden or encoded strings.
- **Suspicious Keyword Flagging**: Cross-references extracted strings against a list of 300+ malware-related keywords (`ransomware`, `backdoor`, `exploit`) to prioritize high-risk indicators.
- **AI Analysis Prompt Generation**: Formats filtered findings into a structured markdown prompt, ready to feed into an AI model for deeper behavioral analysis or report drafting. It includes entropy, categories, and actual items for context.
- **Dual Mode Output**:
  - **Unfiltered Mode**: Dumps all extracted strings into a plain text file for manual triage.
  - **Filtered Mode**: Saves only categorized and relevant strings, reducing noise and focusing on actionable intelligence.

---

## 📦 Installation

```bash
# Download the script
curl -O https://raw.githubusercontent.com/anpa1200/String-Analyzer-/main/string_analyser.py

# (Optional) Clone the repository for examples and LICENSE
git clone https://github.com/anpa1200/String-Analyzer-.git && cd String-Analyzer-

# Create and activate virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# No external dependencies required (uses only Python stdlib) (uses only Python stdlib)
```

---

## 🚀 Usage

```bash
python3 string_analyser.py
```

1. **Enter path** to the binary when prompted.
2. **Choose mode**:
   - **Unfiltered**: Dump all extracted strings to file.
   - **Filtered**: Group strings by category and save.
3. **AI Prompt**: Optionally generate an AI-ready analysis prompt.
4. **Output**: Strings and reports saved in `<basename>_strings.txt` or custom filename.

---

## 📖 Function Overview

| Function                     | Description                                                  |
| ---------------------------- | ------------------------------------------------------------ |
| `extract_strings(file, min_length)` | Extracts unique printable strings ≥ `min_length`.         |
| `compute_file_entropy(file)` | Computes Shannon entropy over full file bytes.               |
| `shannon_entropy(s)`         | Calculates Shannon entropy for a given string.               |
| `detect_patterns(strings)`   | Categorizes strings into APIs, URLs, IPs, registry keys, etc. |
| `try_base64_decode(s)`       | Attempts Base64 decode if candidate string matches pattern.  |
| `try_hex_decode(s)`          | Attempts hex decode if candidate string matches pattern.     |
| `generate_normal_output(...)`| Creates filtered report grouped by type.                     |
| `generate_ai_prompt(...)`    | Builds AI analysis prompt with categorized strings.          |

---

## 🛠️ Example Workflow

```bash
$ python3 string_analyser.py
Path to file: samples/malware.bin
Output all extracted strings (unfiltered)? (yes/no): no
Create AI prompt for filtered output? (yes/no): yes
Output file (default: malware_strings.txt): mal_prompt.txt
AI prompt saved in mal_prompt.txt!
```

Contents of **mal_prompt.txt**:
```
File Entropy: 7.45

### WINDOWS API COMMANDS:
- CreateFile
- ReadFile
- WriteFile

### URLS:
- http://evil.example.com/payload

### IPS:
- 192.168.1.100

... etc.
```

---

## 🔗 No External Dependencies

This script relies solely on the **Python standard library** (no additional packages required).

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Please fork the repository and submit a pull request.

---

## 📜 License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.

