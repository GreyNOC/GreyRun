"""Shannon-entropy analysis.

Encryption and strong compression produce output that is statistically
indistinguishable from random bytes, so its Shannon entropy approaches the
theoretical maximum of 8 bits/byte. Ordinary documents, source code and
text sit far lower. A *document-class* file whose entropy suddenly jumps to
near-random is one of the most reliable signals that it has been encrypted
in place by ransomware.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Optional

from .utils import file_ext, read_sample

# File classes whose contents are normally *low* entropy. A high-entropy
# reading on one of these is therefore highly suspicious.
LOW_ENTROPY_EXTS = {
    ".txt", ".csv", ".tsv", ".log", ".md", ".rtf",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods",
    ".json", ".xml", ".html", ".htm", ".yaml", ".yml", ".ini", ".cfg",
    ".py", ".js", ".ts", ".c", ".cpp", ".h", ".java", ".cs", ".go", ".rs",
    ".sql", ".sh", ".bat", ".ps1", ".php", ".rb", ".pl",
    ".bmp", ".wav", ".tif", ".tiff", ".svg",
    ".pdf",  # mixed, but rarely above ~7.6 across the head sample
}

# File classes that are *already* high entropy when healthy. Seeing high
# entropy here is normal and must not score as suspicious on its own.
HIGH_ENTROPY_EXTS = {
    ".zip", ".rar", ".7z", ".gz", ".bz2", ".xz", ".zst",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic",
    ".mp3", ".mp4", ".mkv", ".avi", ".mov", ".m4a", ".flac", ".webm",
    ".pdf", ".docx", ".xlsx", ".pptx",  # zip-based containers; overlap is fine
}

# Above this, a sample is treated as "indistinguishable from random".
ENCRYPTED_THRESHOLD = 7.8


def shannon_entropy(data: bytes) -> float:
    """Return the Shannon entropy of ``data`` in bits per byte (0..8)."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def file_entropy(path: str, sample_bytes: int = 262_144) -> Optional[float]:
    """Entropy of the head of a file, or ``None`` if unreadable/empty."""
    data = read_sample(path, sample_bytes)
    if not data:
        return None
    return shannon_entropy(data)


def is_document_class(path: str) -> bool:
    """True if the extension normally holds low-entropy content."""
    ext = file_ext(path)
    # Container formats appear in both sets; treat them as high-entropy.
    if ext in HIGH_ENTROPY_EXTS:
        return False
    return ext in LOW_ENTROPY_EXTS


def looks_encrypted(
    path: str,
    entropy: Optional[float] = None,
    threshold: float = ENCRYPTED_THRESHOLD,
) -> bool:
    """Heuristic: does this file look like it was encrypted in place?

    True only when a *document-class* file reads as near-random. This keeps
    healthy archives, images and media from tripping the detector. ``threshold``
    lets callers honour the user's configured ``entropy_threshold``.
    """
    if entropy is None:
        entropy = file_entropy(path)
    if entropy is None:
        return False
    return entropy >= threshold and is_document_class(path)


def classify(entropy: Optional[float]) -> str:
    if entropy is None:
        return "unknown"
    if entropy >= ENCRYPTED_THRESHOLD:
        return "random/encrypted"
    if entropy >= 6.5:
        return "compressed/media"
    if entropy >= 4.0:
        return "structured"
    return "plain"
