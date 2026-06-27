"""External alerting over webhook and email (standard library only).

On a high-confidence incident GreyRun can notify you off-box:

* Webhook: an HTTP POST of a JSON payload. The payload includes a ``text``
  field, so it works with Slack, Discord, and Microsoft Teams incoming webhooks
  as well as a generic endpoint.
* Email: a plain SMTP message (TLS optional).

Secrets can be kept out of the config file via ``GREYRUN_WEBHOOK_URL`` and
``GREYRUN_SMTP_PASSWORD``. Sending uses short timeouts and never raises into the
caller, so a failed alert cannot take down the monitor.
"""

from __future__ import annotations

import ipaddress
import json
import os
import smtplib
import socket
import ssl
import urllib.request
from email.message import EmailMessage
from typing import List, Optional
from urllib.parse import urlparse

from . import console
from .config import Config
from .detector import Assessment


def _hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown-host"


def _webhook_url(config: Config) -> str:
    return os.environ.get("GREYRUN_WEBHOOK_URL") or config.webhook_url


def _smtp_password(config: Config) -> str:
    return os.environ.get("GREYRUN_SMTP_PASSWORD") or config.smtp_password


def build_summary(assessment: Assessment, actions: Optional[List[str]] = None) -> str:
    lines = [
        f"GreyRun ransomware alert on {_hostname()}",
        f"Threat level: {assessment.level} (score {assessment.score})",
    ]
    if assessment.families:
        lines.append("Likely family: " + ", ".join(assessment.families))
    if assessment.reasons:
        lines.append("Indicators:")
        lines += [f"  - {r}" for r in assessment.reasons[:6]]
    if assessment.suspect_paths:
        lines.append("Affected (sample):")
        lines += [f"  - {p}" for p in assessment.suspect_paths[:5]]
    if actions:
        lines.append("Actions taken:")
        lines += [f"  - {a}" for a in actions[:8]]
    return "\n".join(lines)


def _addr_blocked(ip: "ipaddress._BaseAddress") -> bool:
    # Block addresses that are never a legitimate webhook target. Loopback and
    # private ranges are deliberately allowed: self-hosted / internal webhooks
    # (Mattermost, Rocket.Chat, an internal relay) are a real use case.
    return ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified


def _is_blocked_host(host: str) -> bool:
    """True if the host is (or resolves to) a non-routable SSRF target: the
    cloud-metadata link-local address (169.254.169.254 / fe80::), or a
    reserved/multicast/unspecified address. Best-effort."""
    if not host:
        return True
    try:
        return _addr_blocked(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        for res in socket.getaddrinfo(host, None):
            if _addr_blocked(ipaddress.ip_address(res[4][0])):
                return True
    except Exception:
        return False
    return False


def send_webhook(url: str, assessment: Assessment, actions: Optional[List[str]], timeout: float = 6.0) -> bool:
    # Refuse non-routable destinations (e.g. 169.254.169.254 cloud metadata) so
    # a tampered config can't turn alerting into an SSRF/credential-theft vector.
    host = urlparse(url).hostname or ""
    if _is_blocked_host(host):
        console.audit("webhook_blocked", reason="non-routable address", host=host)
        return False
    summary = build_summary(assessment, actions)
    payload = {
        "text": summary,                  # Slack/Discord/Teams compatible
        "content": summary,               # Discord uses "content"
        "host": _hostname(),
        "level": assessment.level,
        "score": assessment.score,
        "families": assessment.families,
        "reasons": assessment.reasons[:10],
        "suspect_paths": assessment.suspect_paths[:10],
        "actions": (actions or [])[:10],
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except Exception as exc:
        console.audit("webhook_error", error=str(exc))
        return False


def send_email(config: Config, assessment: Assessment, actions: Optional[List[str]], timeout: float = 10.0) -> bool:
    if not (config.smtp_host and config.smtp_from and config.smtp_to):
        return False
    msg = EmailMessage()
    msg["Subject"] = f"[GreyRun] {assessment.level} ransomware alert on {_hostname()}"
    msg["From"] = config.smtp_from
    msg["To"] = config.smtp_to
    msg.set_content(build_summary(assessment, actions))
    try:
        with smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=timeout) as server:
            if config.smtp_tls:
                server.starttls(context=ssl.create_default_context())
            if config.smtp_user:
                server.login(config.smtp_user, _smtp_password(config))
            server.send_message(msg)
        return True
    except Exception as exc:
        console.audit("email_error", error=str(exc))
        return False


def channels_configured(config: Config) -> List[str]:
    out = []
    if _webhook_url(config):
        out.append("webhook")
    if config.smtp_host and config.smtp_from and config.smtp_to:
        out.append("email")
    return out


def dispatch(config: Config, assessment: Assessment, actions: Optional[List[str]] = None) -> List[str]:
    """Send to every configured channel. Returns human-readable results.

    Note: the payload includes this host's name and absolute file paths from
    the affected directories, so only point webhook_url/SMTP at endpoints you
    trust. A non-HTTPS webhook sends that data in cleartext and is flagged.
    """
    results: List[str] = []
    url = _webhook_url(config)
    if url:
        if not url.lower().startswith("https://"):
            results.append("WARNING: webhook is not HTTPS — alert sent in cleartext")
        ok = send_webhook(url, assessment, actions)
        results.append("webhook alert sent" if ok else "webhook alert FAILED")
    if config.smtp_host and config.smtp_from and config.smtp_to:
        ok = send_email(config, assessment, actions)
        results.append("email alert sent" if ok else "email alert FAILED")
    return results
