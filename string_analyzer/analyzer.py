"""
Core analysis logic: entropy, string extraction, pattern detection, output generation.
"""

import base64
import re
import logging
from math import log2
from pathlib import Path
from typing import Any, Dict, Iterable, List, Literal, Optional, Set

from string_analyzer.patterns import (
    BASE64_CANDIDATE_RE,
    CMD_COMMAND_LIST,
    DLL_PATTERN,
    EMAIL_PATTERN,
    ENTROPY_THRESHOLD,
    ENTROPY_THRESHOLD_SENSITIVE,
    FILE_PATTERN,
    HEX_CANDIDATE_RE,
    IP_PATTERN,
    IPV6_ABBREV_PATTERN,
    IPV6_PATTERN,
    MAC_PATTERN,
    MIN_USEFUL_COUNT,
    MIN_USEFUL_COUNT_SENSITIVE,
    OBFUSCATED_PATTERNS,
    POWERSHELL_COMMAND_LIST,
    REGISTRY_PATTERN,
    SYSTEM_PATH_PATTERN,
    SUSPICIOUS_DOTNET_KEYWORDS,
    SUSPICIOUS_KEYWORDS,
    URL_OBFUSCATED_PATTERN,
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


def compute_file_entropy(filepath: str | Path, max_bytes: Optional[int] = None) -> float:
    """
    Compute the Shannon entropy for the file (or first max_bytes).
    Uses chunked read when max_bytes is set to limit memory.
    """
    path = Path(filepath)
    size = path.stat().st_size
    to_read = min(size, max_bytes) if max_bytes is not None else size
    if to_read == 0:
        return 0.0
    chunk_size = 1 << 20  # 1 MB
    freq: Dict[int, int] = {}
    total = 0
    with open(path, "rb") as f:
        while total < to_read:
            n = min(chunk_size, to_read - total)
            data = f.read(n)
            if not data:
                break
            for byte in data:
                freq[byte] = freq.get(byte, 0) + 1
            total += len(data)
    if total == 0:
        return 0.0
    entropy = 0.0
    for count in freq.values():
        p = count / total
        entropy -= p * log2(p)
    return entropy


def _extract_ascii_strings(
    data: bytes, min_length: int, start_offset: int, end_offset: int
) -> Set[str]:
    """Extract ASCII strings from a byte slice. Returns set of strings."""
    result: Set[str] = set()
    current: List[str] = []
    length = 0
    for i in range(start_offset, min(end_offset, len(data))):
        b = data[i]
        if 32 <= b <= 126:
            current.append(chr(b))
            length += 1
        else:
            if length >= min_length:
                result.add("".join(current).strip())
            current = []
            length = 0
    if length >= min_length:
        result.add("".join(current).strip())
    return result


def _extract_utf16le_strings(
    data: bytes, min_length: int, start_offset: int, end_offset: int
) -> Set[str]:
    """Extract UTF-16LE strings (Windows-style). Pairs of bytes; null every other byte."""
    result: Set[str] = set()
    current: List[str] = []
    length = 0
    i = start_offset
    end = min(end_offset, len(data))
    while i < end:
        if i + 1 < end and data[i + 1] == 0 and 32 <= data[i] <= 126:
            current.append(chr(data[i]))
            length += 1
            i += 2
        else:
            if length >= min_length:
                result.add("".join(current).strip())
            current = []
            length = 0
            if i + 1 < end and data[i + 1] == 0:
                i += 2
            else:
                i += 1
    if length >= min_length:
        result.add("".join(current).strip())
    return result


def extract_strings(
    filepath: str | Path,
    min_length: int = 4,
    max_bytes: Optional[int] = None,
    encoding: Literal["ascii", "utf16", "both"] = "both",
) -> Set[str]:
    """
    Extract printable strings from a binary file.
    - ascii: classic ASCII (0x20-0x7E) only.
    - utf16: UTF-16LE only (common in Windows PE).
    - both: merge ASCII + UTF-16LE (default; most sensitive).
    Uses chunked read when max_bytes is set for large files.
    """
    path = Path(filepath)
    result: Set[str] = set()
    read_limit = max_bytes
    chunk_size = 2 * (1 << 20)  # 2 MB buffer
    total_read = 0

    with open(path, "rb") as f:
        while True:
            to_read = chunk_size if read_limit is None else min(chunk_size, read_limit - total_read)
            if read_limit is not None and to_read <= 0:
                break
            data = f.read(to_read)
            if not data:
                break
            total_read += len(data)
            if read_limit is not None and total_read > read_limit:
                data = data[: len(data) - (total_read - read_limit)]
                total_read = read_limit
            if encoding in ("ascii", "both"):
                result |= _extract_ascii_strings(data, min_length, 0, len(data))
            if encoding in ("utf16", "both"):
                result |= _extract_utf16le_strings(data, min_length, 0, len(data))
            if read_limit is not None and total_read >= read_limit:
                break
    if read_limit is not None and total_read >= read_limit:
        logger.warning("Stopped reading after %s bytes (max_bytes)", read_limit)
    return result


def is_mostly_printable(s: str, threshold: float = 0.9) -> bool:
    """Check if a string is mostly printable ASCII."""
    if not s:
        return False
    printable = sum(1 for c in s if 32 <= ord(c) <= 126)
    return (printable / len(s)) >= threshold


def try_base64_decode(s: str) -> Optional[str]:
    """Attempt to decode Base64 (standard or URL-safe). Returns decoded string or None."""
    s_clean = s.replace("-", "+").replace("_", "/")
    if len(s_clean) <= 8:
        return None
    # Allow relaxed padding for sensitivity
    pad = 4 - (len(s_clean) % 4)
    if pad != 4:
        s_clean += "=" * pad
    if not BASE64_CANDIDATE_RE.match(s) and not re.match(r"^[A-Za-z0-9+/=_-]+$", s_clean):
        return None
    for raw in (s, s_clean):
        try:
            decoded_bytes = base64.b64decode(raw, validate=True)
            decoded = decoded_bytes.decode("utf-8", errors="replace")
            if is_mostly_printable(decoded) and decoded != s and len(decoded) >= 2:
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


def _add_embedded_matches(line: str, found: Dict[str, Set[str]]) -> None:
    """Extract URLs, IPs, emails, MACs from inside long strings (sensitive)."""
    for m in URL_PATTERN.finditer(line):
        found["URLS"].add(m.group(0))
    for m in URL_OBFUSCATED_PATTERN.finditer(line):
        found["URLS"].add(m.group(0))
    for m in IP_PATTERN.finditer(line):
        found["IPS"].add(m.group(0))
    for m in IPV6_PATTERN.finditer(line):
        found["IPV6"].add(m.group(0))
    for m in IPV6_ABBREV_PATTERN.finditer(line):
        found["IPV6"].add(m.group(0))
    for m in EMAIL_PATTERN.finditer(line):
        found["EMAILS"].add(m.group(0))
    for m in MAC_PATTERN.finditer(line):
        found["MAC_ADDRESSES"].add(m.group(0))


def detect_patterns(
    strings: Iterable[str],
    extract_embedded: bool = True,
) -> Dict[str, Set[str]]:
    """
    Detect patterns in extracted strings and return a fresh category -> set dict.
    If extract_embedded is True (default), also finds URLs/IPs/emails/MACs inside long strings.
    """
    found = get_empty_found_patterns()
    for line in strings:
        lower_line = line.lower()
        # Whole-line classification (first match wins)
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
        elif (url_obf := URL_OBFUSCATED_PATTERN.search(line)):
            found["URLS"].add(url_obf.group(0))
        elif IP_PATTERN.search(line):
            found["IPS"].add(line)
        elif IPV6_PATTERN.search(line) or IPV6_ABBREV_PATTERN.search(line):
            found["IPV6"].add(line)
        elif EMAIL_PATTERN.search(line):
            found["EMAILS"].add(line)
        elif FILE_PATTERN.search(line):
            found["FILES"].add(line)
        elif MAC_PATTERN.search(line):
            for m in MAC_PATTERN.finditer(line):
                found["MAC_ADDRESSES"].add(m.group(0))

        if extract_embedded and len(line) > 20:
            _add_embedded_matches(line, found)

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
    sensitive: bool = False,
) -> bool:
    """
    True if useful pattern count is low and file entropy is high (packed/obfuscated).
    If sensitive is True, uses lower thresholds to flag more samples.
    """
    count_thresh = MIN_USEFUL_COUNT_SENSITIVE if sensitive else MIN_USEFUL_COUNT
    entropy_thresh = ENTROPY_THRESHOLD_SENSITIVE if sensitive else ENTROPY_THRESHOLD
    return _useful_count(found) < count_thresh and file_entropy > entropy_thresh


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
    encoding: Literal["ascii", "utf16", "both"] = "both",
    extract_embedded: bool = True,
    sensitive: bool = False,
) -> Dict[str, Any]:
    """
    Programmatic API: analyze a file and return entropy, strings, and categorized patterns.
    - encoding: ascii, utf16, or both (default both for maximum sensitivity).
    - extract_embedded: find URLs/IPs/emails inside long strings (default True).
    - sensitive: use lower thresholds for obfuscation heuristic (default False).
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    if not path.is_file():
        raise ValueError(f"Not a file: {path}")

    file_entropy = compute_file_entropy(path, max_bytes=max_bytes)
    strings = extract_strings(
        path,
        min_length=min_length,
        max_bytes=max_bytes,
        encoding=encoding,
    )
    found = detect_patterns(strings, extract_embedded=extract_embedded)
    obfuscated = is_likely_obfuscated(found, file_entropy, sensitive=sensitive)

    return {
        "file": str(path.resolve()),
        "entropy": file_entropy,
        "strings": strings,
        "patterns": found,
        "obfuscated": obfuscated,
    }
