"""GreyRun -- a defensive anti-ransomware CLI.

GreyRun protects a set of "watched" directories using several layered,
behaviour-based detections (canary honeypots, Shannon-entropy analysis,
mass-modification bursts and known ransomware signatures) and can respond
to an active attack by alerting, suspending and ultimately terminating the
offending process before isolating the affected directories.

The package is intentionally dependency-light: it works on the Python
standard library alone, and *opportunistically* uses ``psutil`` (for
process-level response) and ``watchdog`` (for efficient file-system events)
when they are installed.
"""

__version__ = "1.1.0"
__app_name__ = "GreyRun"
__tagline__ = "Behaviour-based ransomware shield"

__all__ = ["__version__", "__app_name__", "__tagline__"]
