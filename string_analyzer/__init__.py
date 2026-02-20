"""
String Analyzer — Extract and analyze printable strings from binary files.

Ideal for malware analysts, reverse engineers, and forensics investigators.
"""

from string_analyzer.analyzer import (
    analyze_file,
    compute_file_entropy,
    detect_patterns,
    extract_strings,
    generate_ai_prompt,
    generate_normal_output,
    shannon_entropy,
)

__version__ = "2.0.0"
__all__ = [
    "__version__",
    "analyze_file",
    "compute_file_entropy",
    "detect_patterns",
    "extract_strings",
    "generate_ai_prompt",
    "generate_normal_output",
    "shannon_entropy",
]
