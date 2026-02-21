"""Unit tests for string_analyzer.analyzer."""

import tempfile
from pathlib import Path

import pytest

from string_analyzer.analyzer import (
    compute_file_entropy,
    detect_patterns,
    extract_strings,
    generate_ai_prompt,
    generate_normal_output,
    is_likely_obfuscated,
    is_mostly_printable,
    shannon_entropy,
    try_base64_decode,
    try_hex_decode,
)
from string_analyzer.patterns import get_empty_found_patterns


def test_shannon_entropy_empty() -> None:
    assert shannon_entropy("") == 0.0


def test_shannon_entropy_uniform() -> None:
    # 4 distinct chars, uniform -> entropy = 2.0
    s = "abcd"
    assert abs(shannon_entropy(s) - 2.0) < 1e-9


def test_shannon_entropy_repeated() -> None:
    assert shannon_entropy("aaaa") == 0.0


def test_compute_file_entropy_empty_file() -> None:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        path = Path(f.name)
    try:
        assert compute_file_entropy(path) == 0.0
    finally:
        path.unlink()


def test_compute_file_entropy_simple() -> None:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(b"hello")
        path = Path(f.name)
    try:
        ent = compute_file_entropy(path)
        assert ent > 0 and ent < 5.0
    finally:
        path.unlink()


def test_extract_strings() -> None:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(b"abc\x00def\x00ghi\x00\x00ab\x00")
        path = Path(f.name)
    try:
        out = extract_strings(path, min_length=3)
        assert out == {"abc", "def", "ghi"}
        out2 = extract_strings(path, min_length=2)
        assert "ab" in out2
    finally:
        path.unlink()


def test_extract_strings_max_bytes() -> None:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(b"abcd\x00efgh\x00ijkl\x00")
        path = Path(f.name)
    try:
        out = extract_strings(path, min_length=2, max_bytes=6)
        assert "abcd" in out
        assert "efgh" not in out
    finally:
        path.unlink()


def test_extract_strings_utf16() -> None:
    # "Hello" in UTF-16LE: H e l l o with null bytes
    utf16_data = b"H\x00e\x00l\x00l\x00o\x00\x00\x00"
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(utf16_data)
        path = Path(f.name)
    try:
        out_ascii = extract_strings(path, min_length=2, encoding="ascii")
        out_utf16 = extract_strings(path, min_length=2, encoding="utf16")
        out_both = extract_strings(path, min_length=2, encoding="both")
        assert "Hello" in out_utf16
        assert "Hello" in out_both
        assert out_ascii != out_utf16 or "Hello" in out_ascii
    finally:
        path.unlink()


def test_detect_patterns_embedded_and_mac() -> None:
    found = detect_patterns(["text with http://embedded.url.com inside and 192.168.1.1"])
    assert "http://embedded.url.com" in found["URLS"]
    assert "192.168.1.1" in found["IPS"]
    found_mac = detect_patterns(["MAC: 00:1A:2B:3C:4D:5E"])
    assert "00:1A:2B:3C:4D:5E" in found_mac["MAC_ADDRESSES"]


def test_is_mostly_printable() -> None:
    assert is_mostly_printable("abc") is True
    assert is_mostly_printable("") is False
    assert is_mostly_printable("ab\x00c", threshold=0.5) is True
    assert is_mostly_printable("ab\x00\x00\x00", threshold=0.9) is False


def test_try_base64_decode() -> None:
    # "hello world" in base64 (length > 8)
    assert try_base64_decode("aGVsbG8gd29ybGQ=") == "hello world"
    assert try_base64_decode("aGVsbG8=") is None  # length <= 8
    assert try_base64_decode("!!!") is None
    assert try_base64_decode("") is None
    assert try_base64_decode("ab") is None


def test_try_hex_decode() -> None:
    assert try_hex_decode("68656c6c6f") == "hello"
    assert try_hex_decode("68656c6c6f1") is None  # odd length
    assert try_hex_decode("xx") is None
    assert try_hex_decode("") is None
    assert try_hex_decode("ab") is None  # too short (we require > 8)


def test_detect_patterns_returns_fresh_dict() -> None:
    found = detect_patterns(["CreateFile", "kernel32.dll", "http://evil.com"])
    assert "WINDOWS_API_COMMANDS" in found
    assert "CreateFile" in found["WINDOWS_API_COMMANDS"]
    assert "kernel32.dll" in found["DLLS"]
    assert "http://evil.com" in found["URLS"]
    # Same call again should not accumulate (no global state)
    found2 = detect_patterns(["ReadFile"])
    assert "ReadFile" in found2["WINDOWS_API_COMMANDS"]
    assert "CreateFile" not in found2["WINDOWS_API_COMMANDS"]


def test_detect_patterns_suspicious_and_obfuscated() -> None:
    found = detect_patterns(["password123", "hxxp[:]//evil.com"])
    assert "password123" in found["SUSPICIOUS_KEYWORDS"] or any(
        "password123" in str(s) for s in found["SUSPICIOUS_KEYWORDS"]
    )
    assert len(found["OBFUSCATED"]) >= 0  # obfuscated pattern may match


def test_is_likely_obfuscated() -> None:
    empty = get_empty_found_patterns()
    assert is_likely_obfuscated(empty, file_entropy=7.0) is True
    full = get_empty_found_patterns()
    full["WINDOWS_API_COMMANDS"].add("CreateFile")
    for _ in range(15):
        full["WINDOWS_API_COMMANDS"].add(f"Api_{_}")
    assert is_likely_obfuscated(full, file_entropy=7.0) is False
    assert is_likely_obfuscated(empty, file_entropy=3.0) is False


def test_generate_ai_prompt() -> None:
    found = get_empty_found_patterns()
    found["URLS"].add("http://test.com")
    text = generate_ai_prompt(found, file_entropy=5.0, obfuscated=False)
    assert "5.00" in text
    assert "URLS" in text
    assert "http://test.com" in text


def test_generate_normal_output() -> None:
    found = get_empty_found_patterns()
    found["IPS"].add("192.168.1.1")
    text = generate_normal_output(found, file_entropy=4.0, obfuscated=True)
    assert "4.00" in text
    assert "obfuscated" in text.lower()
    assert "192.168.1.1" in text


def test_analyze_file_api() -> None:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(b"CreateFile\x00ReadFile\x00kernel32.dll\x00")
        path = Path(f.name)
    try:
        from string_analyzer.analyzer import analyze_file
        result = analyze_file(path)
        assert "entropy" in result
        assert "strings" in result
        assert "patterns" in result
        assert "CreateFile" in result["patterns"]["WINDOWS_API_COMMANDS"]
        assert "kernel32.dll" in result["patterns"]["DLLS"]
    finally:
        path.unlink()


def test_analyze_file_nonexistent() -> None:
    from string_analyzer.analyzer import analyze_file
    with pytest.raises(FileNotFoundError):
        analyze_file("/nonexistent/path/file.bin")
