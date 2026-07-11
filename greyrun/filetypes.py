"""File-format structure checks (magic bytes).

Ransomware that encrypts a file in place and keeps its name defeats both the
extension detector (nothing was renamed) and the entropy detector (jpg/zip/
docx/pdf are high entropy when healthy, so entropy.py must skip them). But a
healthy file of those formats *starts with a known signature*, and ciphertext
does not. A file whose extension promises a format, whose head matches no
known format at all, and whose bytes read as uniform random has almost
certainly been encrypted in place.

Three gates keep this quiet on real machines:

* Own-extension magic matches -> healthy, done.
* Head matches *any* known signature -> the file is merely misnamed (a PNG
  saved as .jpg, an HTML bank export as .xls); never scored.
* Head must be cipher-like (entropy + chi-square) -> zero-filled
  preallocations and truncated/corrupt files don't count.
"""

from __future__ import annotations

from typing import Dict, Optional, Tuple

from .entropy import byte_stats, cipher_like
from .utils import file_ext, read_sample

# How many head bytes the checks need. 4 KiB also feeds the byte statistics.
HEAD_BYTES = 4096

_PK = ((0, b"PK\x03\x04"),), ((0, b"PK\x05\x06"),), ((0, b"PK\x07\x08"),)
_OLE = ((0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),)
_RIFF = b"RIFF"

# ext -> alternatives; an alternative is a tuple of (offset, bytes) pairs that
# must all match. Only formats whose signatures are reliable in practice.
MAGIC: Dict[str, Tuple[Tuple[Tuple[int, bytes], ...], ...]] = {
    ".zip": _PK, ".docx": _PK, ".xlsx": _PK, ".pptx": _PK,
    ".odt": _PK, ".ods": _PK, ".odp": _PK, ".jar": _PK,
    ".doc": (_OLE,), ".xls": (_OLE,), ".ppt": (_OLE,), ".msg": (_OLE,),
    ".jpg": (((0, b"\xff\xd8\xff"),),), ".jpeg": (((0, b"\xff\xd8\xff"),),),
    ".png": (((0, b"\x89PNG\r\n\x1a\n"),),),
    ".gif": (((0, b"GIF87a"),), ((0, b"GIF89a"),)),
    ".bmp": (((0, b"BM"),),),
    ".7z": (((0, b"7z\xbc\xaf\x27\x1c"),),),
    ".rar": (((0, b"Rar!\x1a\x07\x00"),), ((0, b"Rar!\x1a\x07\x01\x00"),)),
    ".gz": (((0, b"\x1f\x8b"),),),
    ".bz2": (((0, b"BZh"),),),
    ".xz": (((0, b"\xfd7zXZ\x00"),),),
    ".zst": (((0, b"\x28\xb5\x2f\xfd"),),),
    ".mkv": (((0, b"\x1aE\xdf\xa3"),),), ".webm": (((0, b"\x1aE\xdf\xa3"),),),
    ".avi": (((0, _RIFF), (8, b"AVI ")),),
    ".wav": (((0, _RIFF), (8, b"WAVE")),),
    ".webp": (((0, _RIFF), (8, b"WEBP")),),
    ".flac": (((0, b"fLaC"),),),
    ".tif": (((0, b"II*\x00"),), ((0, b"MM\x00*"),)),
    ".tiff": (((0, b"II*\x00"),), ((0, b"MM\x00*"),)),
    ".psd": (((0, b"8BPS"),),),
    # NB: no .sqlite entry -- SQLCipher databases (Signal, password managers)
    # are legitimately ciphertext from byte 0, exactly what this detector
    # would misread as an encryption victim.
    ".exe": (((0, b"MZ"),),), ".dll": (((0, b"MZ"),),),
}

# ISO-BMFF (mp4 family): size(4) + atom type at offset 4.
_BMFF_EXTS = frozenset({".mp4", ".m4a", ".m4v", ".mov", ".heic"})
_BMFF_ATOMS = (b"ftyp", b"moov", b"mdat", b"free", b"wide", b"skip")

# Formats with looser heads, matched by predicate rather than fixed offset.
_PDF_EXTS = frozenset({".pdf"})
_MP3_EXTS = frozenset({".mp3"})


def _is_bmff(head: bytes) -> bool:
    return len(head) >= 8 and head[4:8] in _BMFF_ATOMS


def _is_pdf(head: bytes) -> bool:
    # The spec allows leading junk before the %PDF header.
    return b"%PDF" in head[:1024]


def _is_mp3(head: bytes) -> bool:
    if head.startswith(b"ID3"):
        return True
    # Bare MPEG audio frame. The 11-bit sync alone matches ~1 in 2048 random
    # (i.e. encrypted) heads, so validate the rest of the frame header too:
    # version/layer must not be reserved, bitrate index not 0xF, sampling
    # rate not reserved.
    if len(head) < 3 or head[0] != 0xFF or (head[1] & 0xE0) != 0xE0:
        return False
    if (head[1] >> 3) & 0x3 == 0x1:      # reserved MPEG version
        return False
    if (head[1] >> 1) & 0x3 == 0x0:      # reserved layer
        return False
    if (head[2] >> 4) == 0xF:            # invalid bitrate index
        return False
    return (head[2] >> 2) & 0x3 != 0x3   # reserved sampling rate


def _matches(head: bytes, alternatives) -> bool:
    for alt in alternatives:
        if all(head[off : off + len(sig)] == sig for off, sig in alt):
            return True
    return False


def has_magic_for(path: str) -> bool:
    """True if this extension promises a format we can verify."""
    ext = file_ext(path)
    return ext in MAGIC or ext in _BMFF_EXTS or ext in _PDF_EXTS or ext in _MP3_EXTS


def check_header(path: str, head: bytes) -> Optional[bool]:
    """Does ``head`` match the format ``path``'s extension promises?
    ``None`` when the extension has no table entry."""
    ext = file_ext(path)
    if ext in MAGIC:
        return _matches(head, MAGIC[ext])
    if ext in _BMFF_EXTS:
        return _is_bmff(head)
    if ext in _PDF_EXTS:
        return _is_pdf(head)
    if ext in _MP3_EXTS:
        return _is_mp3(head)
    return None


# Every signature we know, plus formats that commonly live under the "wrong"
# extension with no table entry of their own. A head matching ANY of these is
# a real file that is at worst misnamed -- never an encryption victim.
_KNOWN_PREFIXES: Tuple[Tuple[int, bytes], ...] = tuple(
    sorted(
        {pair for alts in MAGIC.values() for alt in alts for pair in alt}
        | {
            (0, b"{\\rtf"),
            (0, b"MZ"),
            (0, b"%PDF"),
            (0, b"\x7fELF"),
            (0, b"\xef\xbb\xbf"),   # UTF-8 BOM: text
            (0, b"\xff\xfe"),        # UTF-16 BOM: text
            (0, b"\xfe\xff"),
        },
        key=lambda p: (p[0], p[1]),
    )
)
_KNOWN_TEXT_OPENERS = (b"<!do", b"<htm", b"<?xm", b"<svg")


def matches_any_known(head: bytes) -> bool:
    """True if ``head`` opens like *any* format we recognise."""
    if not head:
        return False
    for off, sig in _KNOWN_PREFIXES:
        if head[off : off + len(sig)] == sig:
            return True
    if head[:64].lstrip().lower().startswith(_KNOWN_TEXT_OPENERS):
        return True
    return _is_bmff(head) or _is_pdf(head) or _is_mp3(head)


def header_mismatch(
    path: str,
    min_size: int,
    entropy_threshold: float,
    chi2_max: float,
) -> Optional[str]:
    """The mismatch-to-random tri-gate. Returns a detail string when a file
    whose extension promises a verifiable format matches no known format at
    all and its head reads as ciphertext; ``None`` otherwise."""
    head = read_sample(path, HEAD_BYTES)
    if head is None or len(head) < min_size:
        return None
    if check_header(path, head):
        return None
    if matches_any_known(head):
        return None  # misnamed but real -- a PNG saved as .jpg is not a victim
    if not cipher_like(byte_stats(head), entropy_threshold, chi2_max):
        return None
    return f"expected {file_ext(path)} signature, head reads as random"
