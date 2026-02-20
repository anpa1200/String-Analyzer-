"""
Core analysis logic: entropy, string extraction, pattern detection, output generation.
"""

import base64
import logging
from math import log2
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

from string_analyzer.patterns import (
    BASE64_CANDIDATE_RE,
    CMD_COMMAND_LIST,
    DLL_PATTERN,
    EMAIL_PATTERN,
    ENTROPY_THRESHOLD,
    FILE_PATTERN,
    HEX_CANDIDATE_RE,
    IP_PATTERN,
    IPV6_PATTERN,
    MIN_USEFUL_COUNT,
    OBFUSCATED_PATTERNS,
    POWERSHELL_COMMAND_LIST,
    REGISTRY_PATTERN,
    SYSTEM_PATH_PATTERN,
    SUSPICIOUS_DOTNET_KEYWORDS,
    SUSPICIOUS_KEYWORDS,
    URL_PATTERN,
    WINDOWS_API_COMMANDS,
    get_empty_found_patterns,
)

logger = logging.getLogger(__name__)

# Normalized lookup sets (compute once)
_WIN_API_LOWER: Set[str] = {c.lower() for c in WINDOWS_API_COMMANDS}


def shannon_entropy(s: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for char in s:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    length = len(s)
    for count in freq.values():
        p = count / length
        entropy -= p * log2(p)
    return entropy


def compute_file_entropy(filepath: str | Path) -> float:
    """Compute the Shannon entropy for the entire file content (bytes)."""
    path = Path(filepath)
    with open(path, "rb") as f:
        data = f.read()
    if not data:
        return 0.0
    freq: Dict[int, int] = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * log2(p)
    return entropy


def extract_strings(
    filepath: str | Path,
    min_length: int = 4,
    max_bytes: Optional[int] = None,
) -> Set[str]:
    """
    Extract printable ASCII strings from a binary file.
    Returns a set of unique strings of at least min_length characters.
    If max_bytes is set, stop reading after that many bytes (safety for huge files).
    """
    path = Path(filepath)
    result: Set[str] = set()
    current_string: List[str] = []
    length = 0
    total_read = 0
    with open(path, "rb") as f:
        while True:
            byte = f.read(1)
            if not byte:
                break
            total_read += 1
            if max_bytes is not None and total_read > max_bytes:
                logger.warning("Stopped reading after %s bytes (max_bytes)", max_bytes)
                break
            if 32 <= byte[0] <= 126:
                current_string.append(byte.decode("ascii", "ignore"))
                length += 1
            else:
                if length >= min_length:
                    result.add("".join(current_string).strip())
                current_string = []
                length = 0
        if length >= min_length:
            result.add("".join(current_string).strip())
    return result


def is_mostly_printable(s: str, threshold: float = 0.9) -> bool:
    """Check if a string is mostly printable ASCII."""
    if not s:
        return False
    printable = sum(1 for c in s if 32 <= ord(c) <= 126)
    return (printable / len(s)) >= threshold


def try_base64_decode(s: str) -> Optional[str]:
    """Attempt to decode a Base64-encoded string. Returns decoded string or None."""
    if len(s) <= 8 or not BASE64_CANDIDATE_RE.match(s):
        return None
    try:
        decoded_bytes = base64.b64decode(s, validate=True)
        decoded = decoded_bytes.decode("utf-8", errors="replace")
        if is_mostly_printable(decoded) and decoded != s:
            return decoded
    except Exception:
        pass
    return None


def try_hex_decode(s: str) -> Optional[str]:
    """Attempt to decode a hex-encoded string. Returns decoded string or None."""
    if len(s) <= 8 or len(s) % 2 != 0 or not HEX_CANDIDATE_RE.match(s):
        return None
    try:
        decoded_bytes = bytes.fromhex(s)
        decoded = decoded_bytes.decode("utf-8", errors="replace")
        if is_mostly_printable(decoded) and decoded != s:
            return decoded
    except Exception:
        pass
    return None


def detect_patterns(strings: Iterable[str]) -> Dict[str, Set[str]]:
    """
    Detect patterns in extracted strings and return a fresh category -> set dict.
    Does not mutate any global state; safe for repeated or library use.
    """
    found = get_empty_found_patterns()
    for line in strings:
        lower_line = line.lower()
        # Windows API
        if lower_line in _WIN_API_LOWER:
            found["WINDOWS_API_COMMANDS"].add(line)
        elif lower_line in CMD_COMMAND_LIST:
            found["CMD_COMMANDS"].add(line)
        elif lower_line in POWERSHELL_COMMAND_LIST:
            found["POWERSHELL_COMMANDS"].add(line)
        elif REGISTRY_PATTERN.search(line):
            found["WINDOWS_REGISTRY_KEYS"].add(line)
        elif SYSTEM_PATH_PATTERN.search(line):
            found["SYSTEM_PATHS"].add(line)
        elif DLL_PATTERN.search(line):
            found["DLLS"].add(line)
        elif URL_PATTERN.search(line):
            found["URLS"].add(line)
        elif IP_PATTERN.search(line):
            found["IPS"].add(line)
        elif IPV6_PATTERN.search(line):
            found["IPV6"].add(line)
        elif EMAIL_PATTERN.search(line):
            found["EMAILS"].add(line)
        elif FILE_PATTERN.search(line):
            found["FILES"].add(line)

        for pattern in OBFUSCATED_PATTERNS:
            if pattern.search(line):
                found["OBFUSCATED"].add(line)
                break

        is_known_command = (
            lower_line in _WIN_API_LOWER
            or lower_line in CMD_COMMAND_LIST
            or lower_line in POWERSHELL_COMMAND_LIST
        )
        if not is_known_command:
            for keyword in SUSPICIOUS_KEYWORDS:
                if keyword in lower_line:
                    found["SUSPICIOUS_KEYWORDS"].add(line)
                    break

        for dotnet_kw in SUSPICIOUS_DOTNET_KEYWORDS:
            if dotnet_kw in lower_line:
                found["SUSPICIOUS_DOTNET"].add(line)
                break

        decoded_b64 = try_base64_decode(line)
        if decoded_b64:
            found["DECODED_BASE64"].add(f"{line} -> {decoded_b64}")
        decoded_hex = try_hex_decode(line)
        if decoded_hex:
            found["DECODED_HEX"].add(f"{line} -> {decoded_hex}")

    return found


def _useful_count(found: Dict[str, Set[str]]) -> int:
    return (
        len(found["WINDOWS_API_COMMANDS"])
        + len(found["DLLS"])
        + len(found["CMD_COMMANDS"])
        + len(found["POWERSHELL_COMMANDS"])
    )


def is_likely_obfuscated(
    found: Dict[str, Set[str]],
    file_entropy: float,
) -> bool:
    """True if useful pattern count is low and file entropy is high (packed/obfuscated)."""
    return _useful_count(found) < MIN_USEFUL_COUNT and file_entropy > ENTROPY_THRESHOLD


def generate_ai_prompt(
    found_patterns: Dict[str, Set[str]],
    file_entropy: float,
    obfuscated: bool = False,
) -> str:
    """Generate an AI analysis prompt text based on filtered patterns."""
    header = ""
    if obfuscated:
        header += "maybe obfuscated or packed file\n\n"
    header += f"File Entropy: {file_entropy:.2f}\n\n"
    prompt_lines = [header]
    prompt_lines.append(
        "Please analyze the following extracted strings from a suspicious binary file. "
        "For each category, explain the functions and potential implications. "
        "Enrich any found URLs with context (if available) and provide a summary of the behavior and functionality based on these strings.\n"
    )
    for category in sorted(found_patterns.keys()):
        items = sorted(found_patterns[category])
        if items:
            prompt_lines.append(f"### {category.replace('_', ' ')}:")
            for item in items:
                prompt_lines.append(f"- {item}")
            prompt_lines.append("")
    prompt_lines.append(
        "Based on the above, please provide a comprehensive analysis of the malware's behavior and functionality."
    )
    return "\n".join(prompt_lines)


def generate_normal_output(
    found_patterns: Dict[str, Set[str]],
    file_entropy: float,
    obfuscated: bool = False,
) -> str:
    """Generate a normal output text with filtered strings, sorted by type."""
    output_lines = []
    header = f"File Entropy: {file_entropy:.2f}\n"
    if obfuscated:
        header = "maybe obfuscated or packed file\n" + header
    output_lines.append(header)
    for category in sorted(found_patterns.keys()):
        items = sorted(found_patterns[category])
        if items:
            output_lines.append(f"### {category.replace('_', ' ')}:")
            for item in items:
                output_lines.append(f"- {item}")
            output_lines.append("")
    return "\n".join(output_lines)


def analyze_file(
    filepath: str | Path,
    min_length: int = 4,
    max_bytes: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Programmatic API: analyze a file and return entropy, strings, and categorized patterns.
    Does not write any output; use for scripting or integration.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    if not path.is_file():
        raise ValueError(f"Not a file: {path}")

    file_entropy = compute_file_entropy(path)
    strings = extract_strings(path, min_length=min_length, max_bytes=max_bytes)
    found = detect_patterns(strings)
    obfuscated = is_likely_obfuscated(found, file_entropy)

    return {
        "file": str(path.resolve()),
        "entropy": file_entropy,
        "strings": strings,
        "patterns": found,
        "obfuscated": obfuscated,
    }
