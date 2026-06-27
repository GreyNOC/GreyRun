"""Static signatures: known ransomware file extensions and ransom-note names.

These are *supporting* signals. GreyRun's strongest detections are behavioural
(canary tampering, entropy jumps, mass-modification bursts); signatures add
weight and human-readable context ("this looks like LockBit") but are never
relied on alone, because extensions are trivially changed by new variants.
"""

from __future__ import annotations

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
    "ransom_note.txt", "attention.txt", "important.txt",
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


def ransomware_family(path: str) -> Optional[str]:
    """Return the family name if the extension is a known ransomware suffix."""
    return RANSOMWARE_EXTENSIONS.get(file_ext(path))


def is_ransomware_ext(path: str) -> bool:
    return file_ext(path) in RANSOMWARE_EXTENSIONS


def is_ransom_note(path: str) -> bool:
    """True if the *filename* matches a known/likely ransom-note name."""
    import os

    name = os.path.basename(path).lower()
    if name in RANSOM_NOTE_NAMES:
        return True
    # Only treat note-like names with text/markup/script extensions as notes,
    # to avoid flagging e.g. a legitimately named source file.
    ext = file_ext(path)
    if ext not in (".txt", ".html", ".htm", ".hta", ".rtf", ".url", ".png", ".bmp", ""):
        return False
    return any(pat.search(name) for pat in RANSOM_NOTE_PATTERNS)
