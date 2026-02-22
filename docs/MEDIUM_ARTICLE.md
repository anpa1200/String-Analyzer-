# The Complete Guide to String Analyzer: From Binary Blob to Actionable Intelligence

**One Python tool. Zero runtime dependencies. Categorized strings, entropy, obfuscation hints, and optional AI analysis — straight from the command line or your own scripts.**

---

Whether you’re triaging a suspicious executable, skimming a memory dump, or pulling indicators from a disk image, you’ve probably hit the same wall: `strings` dumps everything with no structure, and manual grepping doesn’t scale. You need **extraction** plus **classification** — URLs, IPs, registry keys, Windows APIs, obfuscation patterns — and, ideally, a way to hand that to an AI for a first-pass assessment.

**String Analyzer** does exactly that. It’s a single entry point: the `string-analyzer` command (or `python -m string_analyzer`). No GUI, no commercial license, no pip dependencies beyond the standard library. This guide walks you through installation, every major feature, and real workflows so you can use it confidently in production.

---

## What String Analyzer Actually Does

- **Extracts** printable strings from binaries — both **ASCII** and **UTF-16LE** (common in Windows PE).
- **Classifies** them into categories: URLs (including obfuscated like `hxxp`), IPv4/IPv6, emails, MAC addresses, Windows API names (300+), DLLs, CMD/PowerShell commands, registry keys, system paths, obfuscation patterns, Base64/hex decoded candidates, and suspicious keywords.
- **Finds indicators inside long strings** — not only when the whole line matches (e.g. a URL buried in a log line).
- **Computes file entropy** — high entropy plus few “useful” patterns suggests packing or obfuscation.
- **Outputs** either a categorized report, a raw string list, or an **AI-ready markdown prompt** — or **sends that prompt straight to Gemini or Codex** and prints the AI’s analysis.

All of this is available from the CLI and from a clean Python API with no global state.

---

## Install (under a minute)

**Requirements:** Python 3.8 or newer. No other runtime dependencies.

```bash
git clone https://github.com/anpa1200/String-Analyzer-.git && cd String-Analyzer-
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -e .
```

You get the `string-analyzer` command. From the project root you can also run `python -m string_analyzer`.

---

## Four Ways to Run It

### 1. Categorized report (default)

Best for a first look: file entropy plus strings grouped by type (URLs, IPs, APIs, DLLs, MACs, obfuscation, etc.).

```bash
string-analyzer /path/to/suspicious.exe -o report.txt
```

Open `report.txt`: entropy at the top, then sections like `### URLS`, `### IPS`, `### WINDOWS API COMMANDS`, `### MAC ADDRESSES`, and so on. Empty categories are omitted.

### 2. Unfiltered string dump

Every extracted string, one per line, sorted — for grepping or feeding other tools.

```bash
string-analyzer /path/to/binary --unfiltered -o strings.txt
```

### 3. AI-ready prompt (save and paste)

Generate a markdown prompt with categorized strings and a short instruction for an AI. Save it and paste into any assistant (ChatGPT, Claude, etc.).

```bash
string-analyzer /path/to/suspicious.exe --ai-prompt -o prompt.md
```

The prompt includes entropy, a “possibly packed/obfuscated” note when the heuristic fires, and all categorized sections.

### 4. Send directly to Gemini or Codex

If you have **gemini-cli** or **codex** on your PATH, you can pipe the same prompt into them and get the analysis in one step:

```bash
string-analyzer suspect.exe --analyze-with gemini -o prompt.txt --ai-output analysis.md
string-analyzer suspect.exe --analyze-with codex --ai-output analysis.md
```

The tool builds the categorized prompt, saves it to `-o` (optional), sends it to the chosen CLI via stdin, and prints the AI response. Use `--ai-output` to save that response to a file. Requires [Gemini CLI](https://github.com/google-gemini/gemini-cli) or [Codex CLI](https://codex.com) installed and configured.

---

## Interactive mode

Run with **no file argument** (or `string-analyzer -i`):

```bash
string-analyzer
```

You’ll be prompted for: file path, unfiltered vs filtered, filtered vs AI prompt, and output path. Useful when you’re exploring one file at a time. Interactive mode caps how much of the file is read (e.g. 50 MB) to avoid surprises on huge dumps.

---

## Options that actually matter

| Goal | Option |
|------|--------|
| Longer strings only (less noise) | `--min-length 8` (default 4) |
| Cap read size (e.g. 100 MB) | `--max-bytes 100000000` |
| Maximum sensitivity | `--encoding both --sensitive` (UTF-16 + lower obfuscation bar) |
| ASCII or UTF-16 only | `--encoding ascii` or `--encoding utf16` |
| Don’t pull URLs/IPs from inside long strings | `--no-embedded` |
| Send prompt to AI and save response | `--analyze-with gemini --ai-output report.md` |
| Quiet / verbose | `-q` / `-v` |

**Example: large dump, first 100 MB, filtered report**

```bash
string-analyzer memory.dump --max-bytes 100000000 -o report.txt
```

**Example: triage with Gemini and save both prompt and analysis**

```bash
string-analyzer suspect.exe --analyze-with gemini -o prompt.txt --ai-output analysis.md
```

---

## What gets detected (and why it matters)

String Analyzer **only reads** the file; it doesn’t execute anything. It classifies printable strings into:

- **URLs** — `http`, `https`, `ftp`, `file`, `ws`, `wss`, and obfuscated variants (`hxxp`, etc.)
- **IPs** — IPv4 (strict 0–255 octets), IPv6 (full and abbreviated)
- **Emails** — standard pattern
- **MAC addresses** — e.g. `00:1A:2B:3C:4D:5E`
- **Windows API names** — 300+ (CreateFile, VirtualAlloc, LoadLibrary, etc.)
- **DLLs** — e.g. `kernel32.dll`
- **CMD / PowerShell** — built-in commands and cmdlets
- **Registry keys** — HKCU, HKLM, etc.
- **System paths** — Windows, System32, Program Files, etc.
- **Obfuscation patterns** — dotted IPs, `[dot]`, `[at]`, `hxxp`, byte sequences
- **Base64 / hex** — decoded when the result looks like printable text
- **Suspicious keywords** — malware, miner, steal, persist, evasion, keylogger, etc., plus .NET namespaces

By default it also **extracts indicators from inside long strings** (e.g. a URL in the middle of a line), so you don’t miss buried IOCs.

---

## The “obfuscated” flag

The tool computes **Shannon entropy** over the file (or the first `max_bytes`). Packed or encrypted binaries often have **high entropy** and **few readable API/command strings**. String Analyzer combines:

- **Entropy** above a threshold (default 5.0; lower in sensitive mode), and  
- **Low count** of “useful” patterns (Windows APIs, DLLs, CMD, PowerShell)

into a single **“maybe obfuscated or packed”** note in the report and in the AI prompt. It’s a heuristic — not proof — but it helps prioritize what to dig into. Use `--sensitive` to lower the bar and flag more samples.

---

## Using it from Python

You can drive everything from scripts: one-shot analysis, step-by-step, or batch over many files.

**One-shot:**

```python
from string_analyzer import analyze_file

result = analyze_file("sample.exe")
print("Entropy:", result["entropy"])
print("Obfuscated?", result["obfuscated"])
print("URLs:", result["patterns"].get("URLS", set()))
print("IPs:", result["patterns"].get("IPS", set()))
```

**With options (encoding, embedded, sensitive):**

```python
result = analyze_file(
    "sample.exe",
    min_length=4,
    max_bytes=50_000_000,
    encoding="both",         # ascii | utf16 | both
    extract_embedded=True,  # find URLs/IPs inside long strings
    sensitive=False,        # True = lower obfuscation thresholds
)
```

**Step-by-step (e.g. custom reporting or piping to your own AI):**

```python
from string_analyzer import extract_strings, detect_patterns, compute_file_entropy
from string_analyzer.analyzer import is_likely_obfuscated, generate_ai_prompt

path = "sample.exe"
entropy = compute_file_entropy(path, max_bytes=50_000_000)
strings = extract_strings(path, min_length=4, max_bytes=50_000_000, encoding="both")
patterns = detect_patterns(strings, extract_embedded=True)
obfuscated = is_likely_obfuscated(patterns, entropy, sensitive=False)
prompt_text = generate_ai_prompt(patterns, entropy, obfuscated)
# Send prompt_text to your API or save it
```

**Batch:**

```python
from pathlib import Path
from string_analyzer import analyze_file

for f in Path("samples").glob("*.exe"):
    try:
        r = analyze_file(f, max_bytes=50_000_000, sensitive=True)
        if r["obfuscated"]:
            print(f"Possible packer: {f}")
        # Write r["patterns"], r["entropy"] to your DB or report
    except Exception as e:
        print(f"Error {f}: {e}")
```

`detect_patterns()` returns a new dict every time; no global state, so safe in loops or concurrent use.

---

## When to use which output

- **Filtered report (default)** — First look, sharing with colleagues, or when you want sections (URLs, IPs, APIs) in one place.
- **Unfiltered** — You need a plain string list for grep or other tools.
- **AI prompt (save)** — You want to paste into any AI assistant; the prompt is pre-written and filled with categories.
- **--analyze-with gemini | codex** — You want the AI analysis in one command and optionally saved to `--ai-output`.

---

## A simple triage workflow

1. Get a suspicious sample (e.g. `suspect.exe`).
2. Run:  
   `string-analyzer suspect.exe --analyze-with gemini --ai-output triage.md`  
   (or use `--ai-prompt -o prompt.md` and paste `prompt.md` into your assistant).
3. Read the AI summary (behavior, IOCs, risk).
4. For deeper inspection, run again without `--analyze-with` and open the filtered report to grep or skim categories.

---

## Safety in a few words

- String Analyzer **only reads** the file and extracts/classifies strings. It does **not** execute code.
- For very large files, use `--max-bytes` (or `max_bytes` in the API) to limit memory and CPU.
- Treat the output (URLs, IPs, paths) according to your security and privacy policies — it can contain sensitive or malicious indicators.

---

## Where to go from here

- **Repo and full docs:** [GitHub — String Analyzer](https://github.com/anpa1200/String-Analyzer-)  
- **Detailed reference:** `docs/DOCUMENTATION.md` in the repo (workflows, pattern details, API, troubleshooting).

String Analyzer is GPL-3.0, Python 3.8+, and dependency-free at runtime. If you’re doing malware analysis, reverse engineering, or forensics and you’ve outgrown plain `strings`, give it a try — and if you improve it, the project welcomes contributions.

---

*Summary: String Analyzer extracts and categorizes strings from binaries (ASCII + UTF-16LE), detects URLs, IPs, MACs, APIs, DLLs, obfuscation, and more — including indicators inside long strings. It computes entropy, flags likely packed/obfuscated files, and can output a filtered report, an AI-ready prompt, or send that prompt directly to Gemini or Codex. This guide covered installation, all main output modes, interactive mode, key options, what’s detected, Python API usage, and a simple triage workflow.*
