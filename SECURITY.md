# Security Policy

GreyRun is a **defensive** tool. We take the security of the tool itself
seriously — a flaw in something people run to protect their files matters.

## Reporting a vulnerability

Please report security issues **privately** via GitHub's
[Security Advisories](https://github.com/GreyNOC/GreyRun/security/advisories/new)
(Report a vulnerability) rather than opening a public issue.

Include where you can:
- affected file/function and version (`gr --version`),
- a description and, ideally, a minimal reproduction,
- the impact you believe it has.

We aim to acknowledge reports within a few days and to ship a fix or mitigation
promptly, crediting reporters who wish to be named.

## Scope & threat model

GreyRun runs with the privileges of the user (or elevated, for the scheduled-task
autostart). It has **no network listener** — webhook/email are outbound only.
Things we especially care about:

- Anything that lets a crafted input (a tampered manifest, config, or `--home`
  path) escalate into writing/locking/deleting files outside the intended scope.
- Mis-targeted process termination (killing the wrong/critical process).
- Data leaving the machine unexpectedly via the alert channels.

## Using GreyRun safely

- Prefer an `https://` webhook; a plain `http://` URL sends alert contents
  (hostname + absolute file paths) in cleartext.
- Keep SMTP credentials in `GREYRUN_SMTP_PASSWORD`, not `config.json`.
- The bundled **simulator only ever touches a marker-gated sandbox** it created
  — it is a drill tool and never produces or spreads real malware.

GreyRun is one layer of defense. Keep your OS patched and maintain offline,
immutable backups as well.
