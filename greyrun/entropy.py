"""Shannon-entropy and byte-distribution analysis.

Encryption and strong compression produce output that is statistically
indistinguishable from random bytes, so its Shannon entropy approaches the
theoretical maximum of 8 bits/byte. Ordinary documents, source code and
text sit far lower. A *document-class* file whose entropy suddenly jumps to
near-random is one of the most reliable signals that it has been encrypted
in place by ransomware.

Entropy alone cannot separate *encrypted* from *compressed*: both saturate
near 8 bits/byte. The chi-square statistic over the same byte counts can.
Ciphertext is uniform to within sampling noise (chi-square ~ 255 on 255
degrees of freedom, 99.5th percentile ~318), while DEFLATE interiors, JPEG
scan data and base64 columns carry structure that lands well above that. So
"high entropy AND chi-square passes uniformity" means *cipher-like*, and
that distinction is what lets the detectors reach beyond plain-text formats.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
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

# Chi-square (255 degrees of freedom) stays at/under this for ciphertext;
# compressed and encoded data land higher. See module docstring.
CHI2_UNIFORM_MAX = 320.0

# Below this many bytes the chi-square approximation is unreliable (expected
# cell count < 4) and the sample proves nothing either way.
_CHI2_MIN_SAMPLE = 1024


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


@dataclass
class ByteStats:
    """Entropy and chi-square uniformity of one byte sample."""

    n: int
    entropy: float
    chi2: float


def byte_stats(data: Optional[bytes]) -> Optional[ByteStats]:
    """Shannon entropy and chi-square-vs-uniform of ``data``, from one
    counting pass. ``None`` for empty input."""
    if not data:
        return None
    counts = Counter(data)
    n = len(data)
    entropy = 0.0
    sum_sq = 0
    for count in counts.values():
        p = count / n
        entropy -= p * math.log2(p)
        sum_sq += count * count
    # Closed form of sum((c - n/256)^2 / (n/256)) over all 256 cells,
    # including the absent ones.
    chi2 = (256.0 / n) * sum_sq - n
    return ByteStats(n=n, entropy=entropy, chi2=chi2)


def cipher_like(
    stats: Optional[ByteStats],
    h_min: float = ENCRYPTED_THRESHOLD,
    chi2_max: float = CHI2_UNIFORM_MAX,
) -> bool:
    """True if a sample reads as ciphertext: near-max entropy AND a byte
    distribution uniform to within sampling noise. Compressed/encoded data
    passes the first test but fails the second.

    A sample too small to run the chi-square test is *not evidence* -- it is
    rejected, never accepted on entropy alone (a small compressed fragment
    clears the entropy bar easily, and calling it ciphertext would let one
    detector fire on it)."""
    if stats is None:
        return False
    if stats.entropy < h_min:
        return False
    if stats.n < _CHI2_MIN_SAMPLE:
        return False
    return stats.chi2 <= chi2_max


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


def inner_document_class(path: str) -> bool:
    """True if a document-class extension sits under the final suffix, so the
    content *should* be low entropy: 'report.txt.locked' exposes '.txt'.
    Containers (.docx, .zip) stay excluded -- their healthy content is high
    entropy and an entropy reading proves nothing about them."""
    import os

    stem = os.path.splitext(path)[0]
    return is_document_class(stem)


def looks_encrypted(
    path: str,
    entropy: Optional[float] = None,
    threshold: float = ENCRYPTED_THRESHOLD,
    chi2_max: Optional[float] = None,
) -> bool:
    """Heuristic: does this file look like it was encrypted in place?

    True only when a *document-class* file reads as near-random. This keeps
    healthy archives, images and media from tripping the detector. ``threshold``
    lets callers honour the user's configured ``entropy_threshold``.

    With ``chi2_max`` set, the sample must additionally pass the chi-square
    uniformity test (see :func:`cipher_like`), which rejects compressed and
    base64-like lookalikes. The default ``None`` keeps the entropy-only
    behaviour for existing callers.
    """
    if not is_document_class(path):
        return False
    if chi2_max is not None:
        stats = byte_stats(read_sample(path))
        return cipher_like(stats, threshold, chi2_max)
    if entropy is None:
        entropy = file_entropy(path)
    if entropy is None:
        return False
    return entropy >= threshold


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
