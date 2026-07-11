"""Static signatures: known ransomware file extensions and ransom-note names.

These are *supporting* signals. GreyRun's strongest detections are behavioural
(canary tampering, entropy jumps, mass-modification bursts); signatures add
weight and human-readable context ("this looks like LockBit") but are never
relied on alone, because extensions are trivially changed by new variants.

This module also owns the *benign* filename knowledge the detectors need to
stay quiet: transient working files (Office save dances, browser download
shards), trailing extensions that legitimately wrap a document (.bak, .gpg),
and the split between high-confidence family extensions and generic ones that
collide with everyday tools (a bare ``backup.enc`` is usually openssl, not
ransomware).
"""

from __future__ import annotations

import os
import re
from typing import Optional

from .utils import file_ext

# Extensions appended by well-known ransomware families. Mapping the suffix to
# a family name lets GreyRun tell the user *what* it thinks it is seeing.
RANSOMWARE_EXTENSIONS = {
    ".wncry": "WannaCry", ".wcry": "WannaCry", ".wannacry": "WannaCry",
    ".locky": "Locky", ".zepto": "Locky", ".odin": "Locky", ".thor": "Locky",
    ".aesir": "Locky", ".zzzzz": "Locky",
    ".cerber": "Cerber", ".cerber3": "Cerber",
    ".locked": "generic-locker", ".crypto": "generic-locker",
    ".crypt": "CryptXXX", ".cryp1": "CryptXXX", ".crypz": "CryptXXX",
    ".cryptolocker": "CryptoLocker", ".encrypted": "generic-crypter",
    ".enc": "generic-crypter", ".crinf": "DXXD", ".r5a": "7ev3n",
    ".xtbl": "Shade", ".xrtn": "Shade", ".ytbl": "Shade",
    ".ccc": "TeslaCrypt", ".vvv": "TeslaCrypt", ".ecc": "TeslaCrypt",
    ".exx": "TeslaCrypt", ".micro": "TeslaCrypt",
    # NB: deliberately NOT including ".mp3"/".java" etc. Some ransomware reuses
    # common extensions, but flagging every music/Java file is a worse failure
    # for a defensive tool than missing those rare variants.
    ".vault": "VaultCrypt", ".petya": "Petya", ".cryptowall": "CryptoWall",
    ".sage": "Sage", ".purge": "Globe", ".globe": "Globe",
    ".dharma": "Dharma", ".onion": "Dharma",
    ".combo": "Dharma", ".gamma": "Dharma",
    ".phobos": "Phobos", ".eking": "Phobos", ".eight": "Phobos",
    ".devos": "Phobos", ".elbie": "Phobos",
    ".makop": "Makop", ".mkp": "Makop",
    ".stop": "STOP/Djvu", ".djvu": "STOP/Djvu", ".djvuu": "STOP/Djvu",
    ".puma": "STOP/Djvu", ".promo": "STOP/Djvu", ".promorad": "STOP/Djvu",
    ".coharos": "STOP/Djvu", ".gero": "STOP/Djvu", ".hese": "STOP/Djvu",
    ".ryuk": "Ryuk", ".ryk": "Ryuk",
    ".conti": "Conti", ".lockbit": "LockBit", ".abcd": "LockBit",
    ".sodinokibi": "REvil/Sodinokibi", ".revil": "REvil/Sodinokibi",
    ".darkside": "DarkSide", ".blackmatter": "BlackMatter",
    ".hive": "Hive", ".blackcat": "BlackCat/ALPHV", ".alphv": "BlackCat/ALPHV",
    ".play": "PLAY", ".royal": "Royal", ".akira": "Akira", ".powerrange": "Akira",
    ".basta": "BlackBasta", ".cactus": "Cactus", ".medusa": "Medusa",
    ".mallox": "Mallox", ".tohnichi": "Mallox", ".rhysida": "Rhysida",
    ".lol": "GandCrab", ".gdcb": "GandCrab", ".krab": "GandCrab",
    ".nemty": "Nemty", ".nephilim": "Nephilim",
    ".maze": "Maze", ".egregor": "Egregor", ".clop": "Clop", ".cl0p": "Clop",
    ".pzdc": "generic", ".good": "generic", ".lol!": "generic",
    ".omg!": "generic", ".rdm": "generic", ".rrk": "generic",
    ".magic": "generic", ".toxcrypt": "generic", ".bleep": "generic",
}

# Common ransom-note filenames (exact, case-insensitive).
RANSOM_NOTE_NAMES = {
    "decrypt_instruction.txt", "decrypt_instructions.txt",
    "how_to_decrypt.txt", "how_to_decrypt.html", "how_to_back_files.txt",
    "how to decrypt files.txt", "how to restore files.txt",
    "readme_for_decrypt.txt", "readme_to_decrypt.txt", "readme.hta",
    "help_decrypt.txt", "help_decrypt.html", "help_your_files.txt",
    "_readme.txt", "restore_files.txt", "restore-my-files.txt",
    "recover_files.txt", "recovery_key.txt", "your_files_are_encrypted.txt",
    "your_files_are_encrypted.html", "decrypt-files.txt", "unlock_files.txt",
    "ransom_note.txt",  # NB: not "important.txt"/"attention.txt" -- too common benign
    "lockbit_readme.txt", "restore-my-files.txt", "conti_readme.txt",
    "+how_to_decrypt.txt", "!!!readme!!!.txt", "!!!_recovery_!!!.txt",
}

# Filename patterns for notes whose names vary by victim/campaign.
RANSOM_NOTE_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"how[ _\-]?to[ _\-]?(decrypt|restore|recover|unlock)",
        r"(decrypt|restore|recover|unlock)[ _\-]?(your[ _\-]?)?files?",
        r"your[ _\-]?files?[ _\-]?(are|have been)?[ _\-]?(encrypted|locked)",
        r"read[ _\-]?me.*(decrypt|recover|restore|ransom)",
        r"(^|[ _\-!])ransom([ _\-]?note)?([ _\-!]|\.)",
        r"recovery[ _\-]?(key|instructions|manual)",
        r"\.(ransom|locked_info|readme)\b",
        r"decrypt[ _\-]?me",
    )
]


# Ransomware extensions that everyday tools also produce. A bare `backup.enc`
# is far more often openssl or a licensing tool than ransomware, so these score
# only as weak context on their own -- unless they are stacked over a real
# document extension (`report.docx.enc`), which is the append-a-suffix tell.
GENERIC_EXTENSIONS = {
    ".enc", ".encrypted", ".locked", ".crypt", ".crypto", ".onion",
    ".play", ".stop", ".good", ".magic", ".lol", ".eight", ".hive",
    ".royal", ".cactus", ".medusa", ".sage", ".purge", ".combo", ".gamma",
    ".pzdc", ".rdm", ".rrk", ".bleep", ".toxcrypt",
}

# Working files that normal software churns through constantly. They are never
# content-checked and (by default) don't count toward the change burst; their
# *deletions* still count, so a wiper stays visible.
TRANSIENT_EXTS = frozenset({
    ".tmp", ".temp", ".crdownload", ".part", ".partial", ".download",
    ".opdownload", ".swp", ".swx", ".swo", ".lock", ".db-wal", ".db-shm",
    ".etl", ".laccdb",
})
TRANSIENT_PREFIXES = ("~$", ".~", "~")

# A final suffix that legitimately wraps another file: backups, encryption the
# user asked for (gpg, age, AES Crypt, AxCrypt), checksums, download managers,
# sync placeholders. `report.docx.gpg` is the user's own work, not a stranded
# victim -- and single-file encryptors matter especially, because their output
# genuinely reads as ciphertext and would otherwise score.
BENIGN_TRAILING_EXTS = frozenset({
    ".bak", ".backup", ".old", ".orig", ".gpg", ".pgp", ".asc", ".sig",
    ".age", ".aes", ".axx", ".cpt", ".kdbx",
    ".sha256", ".md5", ".b64", ".torrent", ".aria2", ".!ut", ".icloud",
    ".sync", ".lnk", ".url",
}) | TRANSIENT_EXTS

# Extensions users actually keep data in. Used to recognise a document
# extension buried under a foreign suffix (`invoice.docx.k8s3x`). Kept local
# so signatures.py stays import-free of entropy.py.
USER_CONTENT_EXTS = frozenset({
    ".txt", ".csv", ".tsv", ".md", ".rtf",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".odt", ".ods", ".odp", ".pdf", ".eml", ".msg", ".pst", ".one", ".pub",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".heic",
    ".webp", ".svg", ".psd",
    ".mp3", ".m4a", ".wav", ".flac", ".mp4", ".mov", ".avi", ".mkv",
    ".zip", ".7z", ".rar", ".sql",
})


def is_transient(path: str) -> bool:
    """True for working files (lock/temp/partial-download) that normal
    software churns through and the per-file detectors must ignore."""
    name = os.path.basename(path)
    if name.startswith(TRANSIENT_PREFIXES):
        return True
    return file_ext(path) in TRANSIENT_EXTS


def _inner_ext(path: str) -> str:
    """The extension buried under the final suffix: 'a.docx.enc' -> '.docx'."""
    stem = os.path.splitext(os.path.basename(path))[0]
    return os.path.splitext(stem)[1].lower()


def is_double_document_ext(path: str) -> bool:
    """True if a real document extension sits directly under the final suffix
    (`report.docx.enc`) -- the shape left by suffix-appending ransomware."""
    return _inner_ext(path) in USER_CONTENT_EXTS


def is_stranded_document_ext(path: str) -> bool:
    """True if a document extension is stranded under an *unknown* final
    suffix: `invoice.docx.k8s3x`. Known ransomware suffixes are excluded
    (already scored as extension hits), and so are benign trailing suffixes
    and split-archive digits. This is a *name* test only -- callers must
    confirm the content looks encrypted before scoring it."""
    stem, final = os.path.splitext(os.path.basename(path))
    final = final.lower()
    if (
        not final
        or final in BENIGN_TRAILING_EXTS
        or final in RANSOMWARE_EXTENSIONS
        or final in USER_CONTENT_EXTS
    ):
        return False
    body = final[1:]
    if body.isdigit():  # .001 split archives, dated suffixes
        return False
    if not (2 <= len(body) <= 12 and body.isalnum()):
        return False
    return _inner_ext(path) in USER_CONTENT_EXTS


def ransomware_family(path: str) -> Optional[str]:
    """Return the family name if the extension is a known ransomware suffix."""
    return RANSOMWARE_EXTENSIONS.get(file_ext(path))


def is_ransomware_ext(path: str) -> bool:
    return file_ext(path) in RANSOMWARE_EXTENSIONS


def ext_confidence(path: str) -> Optional[str]:
    """'family' for a suffix specific to a known strain, 'generic' for one
    that everyday tools also produce, None for anything else."""
    ext = file_ext(path)
    if ext not in RANSOMWARE_EXTENSIONS:
        return None
    return "generic" if ext in GENERIC_EXTENSIONS else "family"


def is_ransom_note(path: str) -> bool:
    """True if the *filename* matches a known/likely ransom-note name."""
    name = os.path.basename(path).lower()
    if name in RANSOM_NOTE_NAMES:
        return True
    # Only treat note-like names with text/markup/script extensions as notes,
    # to avoid flagging e.g. a legitimately named source file.
    ext = file_ext(path)
    if ext not in (".txt", ".html", ".htm", ".hta", ".rtf", ".url", ".png", ".bmp", ""):
        return False
    return any(pat.search(name) for pat in RANSOM_NOTE_PATTERNS)
