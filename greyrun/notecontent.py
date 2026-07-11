"""Ransom-note *content* analysis.

Filename matching misses any note named ``README.txt`` or ``info.hta`` -- and
notes are typically the first artifact dropped, before the encryption sweep
starts, so catching one by its body buys the earliest possible response.

The scorer only fires on the intersection of independent topics: payment
rails, anonymous contact channels, threat phrases, and decryption
instructions. Any single topic alone -- a crypto-news article, a backup
tool's README -- stays silent. A syntactically *valid* Bitcoin address
(base58 checksum verified, so git hashes and API keys can't collide) or a
v3 onion address is a near-forensic anchor that upgrades the match.
"""

from __future__ import annotations

import hashlib
import html
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .utils import file_ext, read_sample, safe_stat

# Extensions ransom notes actually use; everything else is never read.
NOTE_EXTS = frozenset({".txt", ".html", ".htm", ".hta", ".rtf", ""})

# Per-category term tables: (pattern, points). A category's score is capped
# so one topic repeated a hundred times still reads as one topic.
_CATEGORY_CAP = 6

_CATEGORIES: Dict[str, Tuple[Tuple[re.Pattern, int], ...]] = {
    "payment": tuple(
        (re.compile(p, re.IGNORECASE), pts)
        for p, pts in (
            (r"\bbitcoin\b", 3),
            (r"\bbtc\b", 3),
            (r"\bmonero\b", 3),
            (r"\bxmr\b", 3),
            (r"\bwallet\b", 2),
            (r"\bbuy (bitcoin|btc|monero|xmr)\b", 4),
        )
    ),
    "contact": tuple(
        (re.compile(p, re.IGNORECASE), pts)
        for p, pts in (
            (r"\.onion\b", 4),
            (r"\btor browser\b", 4),
            (r"\b(onionmail|protonmail|tutanota|cock\.li)\b", 3),
            (r"\b(qtox|tox chat|tox id)\b", 3),
        )
    ),
    # Phrase-level only -- no bare scary words, or every thriller novel hits.
    # Each phrase must be extortion-framed: "files are encrypted at rest" is
    # vendor copy, "in just 24 hours" is journalism; neither may count.
    "threat": tuple(
        (re.compile(p, re.IGNORECASE), pts)
        for p, pts in (
            (r"\b(files|data|documents) (are|have been|were) "
             r"(encrypted|locked)\b(?! at rest| in transit)", 4),
            (r"\bprivate key\b", 2),
            (r"\bwill be (deleted|doubled|published|permanently lost|leaked)\b", 3),
            (r"\bdo not (rename|modify|delete|attempt|try to)\b", 3),
            (r"\byou have (24|48|72|96) hours\b", 2),
            (r"\bprice will be doubled\b", 3),
            (r"\b(nobody|no one|only we) can (restore|recover|decrypt)\b", 3),
            (r"\bransom\b", 3),
        )
    ),
    # Decrypt-flavoured only. Generic support prose ("restore your files",
    # "recovery instructions", "contact us via") appears in backup-tool docs
    # and donation footers, and one such phrase next to a wallet address must
    # not read as a ransom note.
    "instruction": tuple(
        (re.compile(p, re.IGNORECASE), pts)
        for p, pts in (
            (r"\bhow to decrypt\b", 3),
            (r"\bdecrypt(ion)? (tool|software|key|id)\b", 3),
            (r"\bdecryptor\b", 3),
            (r"\bdecrypt your (files|data)\b", 3),
        )
    ),
}

# Payment/contact anchors. Case-sensitive on purpose: base58 and bech32 have
# defined alphabets, and case-folding would invent matches.
_RE_BTC_BASE58 = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
_RE_BTC_BECH32 = re.compile(r"\bbc1q[ac-hj-np-z02-9]{38,58}\b")
_RE_ONION_V3 = re.compile(r"\b[a-z2-7]{56}\.onion\b")
_RE_XMR = re.compile(r"\b[48][1-9A-HJ-NP-Za-km-z]{94}\b")

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58check_ok(addr: str) -> bool:
    """Verify a legacy Bitcoin address's double-SHA256 checksum. A random
    base58-looking token (git hash, API key) passes with probability 2^-32."""
    num = 0
    for ch in addr:
        idx = _B58_ALPHABET.find(ch)
        if idx < 0:
            return False
        num = num * 58 + idx
    body = num.to_bytes((num.bit_length() + 7) // 8, "big")
    pad = len(addr) - len(addr.lstrip("1"))
    raw = b"\x00" * pad + body
    if len(raw) != 25:  # version byte + 20-byte hash + 4-byte checksum
        return False
    digest = hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()
    return digest[:4] == raw[-4:]


def _find_anchor(text: str) -> Optional[str]:
    for m in _RE_BTC_BASE58.finditer(text):
        if _base58check_ok(m.group(0)):
            return "btc-address"
    if _RE_BTC_BECH32.search(text):
        return "btc-bech32"
    if _RE_ONION_V3.search(text):
        return "onion-v3"
    if _RE_XMR.search(text):
        return "xmr-address"
    return None


def _decode_note_bytes(data: bytes, ext: str) -> str:
    """Best-effort text out of note bytes. UTF-16-LE without a BOM is common
    on Windows (PowerShell's Out-File default); without this sniff, 'bitcoin'
    arrives as b'b\\x00i\\x00t...' and every pattern silently misses.

    The sniff counts NULs on each byte lane separately: UTF-16 text has all
    its NULs on one lane and essentially none on the other. A trailing NUL
    run is stripped first so zero-padded UTF-8 can't masquerade as UTF-16."""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = data.decode("utf-16", errors="ignore")
    elif data.startswith(b"\xef\xbb\xbf"):
        text = data.decode("utf-8-sig", errors="ignore")
    else:
        body = data.rstrip(b"\x00") or data
        even = body[0::2].count(0)
        odd = body[1::2].count(0)
        if len(body) >= 8 and odd > len(body) // 4 and even <= len(body) // 20:
            text = body.decode("utf-16-le", errors="ignore")
        elif len(body) >= 8 and even > len(body) // 4 and odd <= len(body) // 20:
            text = body.decode("utf-16-be", errors="ignore")
        else:
            text = body.decode("utf-8", errors="ignore")
    if ext in (".html", ".htm", ".hta"):
        # Space-replace tags so attribute runs can't concatenate into
        # pseudo-words, then unescape entities.
        text = html.unescape(re.sub(r"<[^>]{0,300}?>", " ", text))
    elif ext == ".rtf":
        text = re.sub(r"\\[a-zA-Z]{1,32}-?\d{0,10} ?", " ", text)
        text = text.replace("{", " ").replace("}", " ")
    return text


@dataclass
class NoteMatch:
    score: int
    categories: List[str]
    strong: bool


def analyze_note_text(text: str) -> Optional[NoteMatch]:
    """Score ransom-note likelihood. Fires only when at least two independent
    topics appear and the total clears a floor; ``strong`` when a verified
    anchor is corroborated by non-payment prose, or three prose topics agree.

    An anchor is payment-topic evidence, not its own topic: a wallet backup
    ("my cold wallet: <address>") is one topic and never fires. It takes
    threat/instruction/contact prose *around* the address to make a note."""
    hits: Dict[str, int] = {}
    for name, terms in _CATEGORIES.items():
        score = sum(pts for pat, pts in terms if pat.search(text))
        if score:
            hits[name] = min(score, _CATEGORY_CAP)
    anchor = _find_anchor(text)
    total = sum(hits.values()) + (6 if anchor else 0)
    topic_set = set(hits) | ({"payment"} if anchor else set())
    if len(topic_set) < 2 or total < 8:
        return None
    strong = (
        anchor is not None and any(c != "payment" for c in hits)
    ) or len(hits) >= 3
    categories = sorted(hits)
    if anchor:
        categories.append(f"anchor:{anchor}")
    return NoteMatch(score=total, categories=categories, strong=strong)


def looks_like_ransom_note_content(
    path: str, max_bytes: int = 32768
) -> Optional[NoteMatch]:
    """Read-and-score gate for one file. The extension and size gates run
    before any I/O: real notes are a few KB of text, so a thesis that
    mentions bitcoin is ineligible before it is ever read."""
    ext = file_ext(path)
    if ext not in NOTE_EXTS:
        return None
    st = safe_stat(path)
    if st is None or not 0 < st.st_size <= max_bytes:
        return None
    data = read_sample(path, max_bytes)
    if not data:
        return None
    return analyze_note_text(_decode_note_bytes(data, ext))
