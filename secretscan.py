"""Find plaintext credentials sitting in compose files, and rewrite them out.

WHY
---
lokey uploads every unit's docker-compose.yml into the locator's compose store,
and the store is committed and pushed (GIT_AUTO_PUSH). Any password typed
straight into an `environment:` block therefore ends up in git history on top of
being readable on the unit. This module finds those, and produces the exact
rewritten text that replaces the literal with a ${VAR} that compose interpolates
from a .env — which the locator then fills from OpenBao at deploy time.

WHY LINE-ORIENTED AND NOT yaml.safe_load
----------------------------------------
A parse loses line numbers, comments and formatting. Redaction has to put a file
back that a human still recognises and git still diffs sanely, and it has to
name the offending line for the report. So this walks lines, tracking just
enough block context to know when it is inside a service's environment:.

It handles both compose spellings:
    environment:
      KEY: value          (map form)
      - KEY=value         (list form)
"""

import re

# Key names that are credentials by nature. Anchored on word boundaries so
# PASSWORD_FILE (a path, not a secret) does not match the same way a bare
# PASSWORD does.
SECRET_KEY_RE = re.compile(
    r"(PASSWORD|PASSWD|_PW|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY"
    r"|CREDENTIAL|CLIENT_SECRET|SALT|PASSPHRASE|_DSN|ADMIN_KEY|AUTH_KEY)",
    re.I)

# Names that LOOK secret but are not: they point at a secret rather than being
# one, and rewriting them breaks the container.
NOT_SECRET_KEY_RE = re.compile(
    r"(_FILE$|_PATH$|_ENABLED$|_METHOD$|_TYPE$|_ALGORITHM$|_HEADER$"
    r"|_REQUIRED$|_TTL$|_EXPIRY$|_LENGTH$|_ROTATION$)", re.I)

# Values that are already safe: compose interpolation, an OpenBao reference, a
# docker secret path, or an empty string.
SAFE_VALUE_RE = re.compile(r"^\s*(\$\{[^}]*\}|\$[A-Za-z_]\w*|bao://\S+|/run/secrets/\S+|)\s*$")

# Placeholders a human obviously meant to replace. Still worth reporting, but
# they are not a live credential and must not be filed into OpenBao as one.
PLACEHOLDER_RE = re.compile(
    r"^(changeme|change_me|password|secret|todo|xxx+|placeholder|your[_-]?\w*"
    r"|<[^>]+>|none|null|example)$", re.I)

# user:password@host inside a connection string — the other common hiding place.
URL_CRED_RE = re.compile(r"[a-z][a-z0-9+.\-]*://[^:/\s]+:([^@/\s]{3,})@", re.I)

# An already-hashed credential (bcrypt/argon2/sha-crypt). Still sensitive, but
# it must not be auto-rewritten: compose escapes a literal $ as $$, and moving
# "$$2y$05$..." into a .env would need it unescaped to "$2y$05$...". Getting
# that backwards locks the user out of the service, so these are reported and
# left for a human.
HASHED_VALUE_RE = re.compile(r"^\$\$?(2[aby]|argon2[id]{1,2}|[156])\$")

# Booleans, numbers, and other values no scanner should call a credential.
BORING_VALUE_RE = re.compile(r"^(true|false|yes|no|on|off|\d+|\d+\.\d+|[a-z]{1,3})$", re.I)

ENV_KEY_RE = re.compile(r"^(?P<indent>\s*)(?P<key>[A-Za-z_][A-Za-z0-9_.]*)\s*:\s?(?P<value>.*)$")
ENV_LIST_RE = re.compile(r"^(?P<indent>\s*)-\s+(?P<key>[A-Za-z_][A-Za-z0-9_.]*)=(?P<value>.*)$")
BLOCK_RE = re.compile(r"^(?P<indent>\s*)(?P<name>[A-Za-z_][\w.-]*)\s*:\s*$")


def _strip_value(raw):
    """Unquote a compose scalar, dropping any trailing comment."""
    v = raw.strip()
    if v[:1] in ("'", '"') and v[-1:] == v[:1] and len(v) >= 2:
        return v[1:-1], v[:1]
    # Only an unquoted scalar can carry a trailing comment.
    if " #" in v:
        v = v.split(" #", 1)[0].rstrip()
    return v, ""


def classify(key, value):
    """(is_finding, severity, reason) for one KEY/VALUE pair."""
    if SAFE_VALUE_RE.match(value or ""):
        return False, None, "already indirect"
    if NOT_SECRET_KEY_RE.search(key):
        return False, None, "names a location, not a value"

    url_hit = URL_CRED_RE.search(value or "")
    name_hit = bool(SECRET_KEY_RE.search(key))

    if not (name_hit or url_hit):
        return False, None, "not credential-shaped"
    if BORING_VALUE_RE.match(value or ""):
        return False, None, "value is a flag or number"
    if PLACEHOLDER_RE.match((value or "").strip()):
        # Report it — a placeholder in a live compose file means the service is
        # either broken or running on a default nobody changed — but never file
        # it into OpenBao as though it were the real credential.
        return True, "placeholder", "placeholder value left in place"
    if HASHED_VALUE_RE.match((value or "").strip()):
        return True, "hashed", "hashed credential — $$ escaping makes this unsafe to auto-rewrite"
    if url_hit:
        return True, "high", "credential embedded in a connection string"
    return True, "high", "literal credential in an environment block"


def mask(value):
    """Enough to recognise a value, never enough to use it."""
    if value is None:
        return ""
    v = str(value)
    if len(v) <= 4:
        return "*" * len(v)
    return f"{v[:2]}{'*' * min(len(v) - 4, 12)}{v[-2:]} ({len(v)} chars)"


def scan_text(text, source=""):
    """Findings for one compose file.

    Each finding carries the 1-based line number, so the redactor edits the
    exact line and the report points a human straight at it.
    """
    findings = []
    lines = text.splitlines()
    in_env = False
    env_indent = None

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        block = BLOCK_RE.match(line)
        if block:
            name = block.group("name")
            indent = len(block.group("indent"))
            if name == "environment":
                in_env, env_indent = True, indent
                continue
            # Any other key at or above the environment: indent closes it.
            if in_env and indent <= env_indent:
                in_env = False
            continue

        if not in_env:
            continue

        indent = len(line) - len(line.lstrip())
        if indent <= env_indent:
            in_env = False
            continue

        m = ENV_LIST_RE.match(line)
        form = "list"
        if not m:
            m = ENV_KEY_RE.match(line)
            form = "map"
        if not m:
            continue

        key = m.group("key")
        value, quote = _strip_value(m.group("value"))
        hit, severity, reason = classify(key, value)
        if not hit:
            continue
        findings.append({
            "source": source,
            "line": i,
            "key": key,
            "form": form,
            "quote": quote,
            "severity": severity,
            "reason": reason,
            "masked": mask(value),
            "value": value,          # callers MUST NOT serialise this outward
        })
    return findings


def redact_text(text, findings):
    """Rewrite the flagged lines to ${KEY} interpolation.

    Returns (new_text, [keys_changed]). Placeholder findings are left alone:
    swapping a placeholder for a ${VAR} that resolves to nothing turns a
    visibly-wrong config into an invisibly-wrong one.
    """
    lines = text.splitlines()
    changed = []
    for f in findings:
        if f.get("severity") in ("placeholder", "hashed"):
            continue
        idx = f["line"] - 1
        if idx < 0 or idx >= len(lines):
            continue
        if f.get("form") not in ("map", "list"):
            # A .env finding has no compose line to rewrite. Rewriting one as
            # "KEY: ${KEY}" would turn an assignment into YAML and blank the
            # variable, so forms this function does not understand are skipped
            # rather than guessed at.
            continue
        line = lines[idx]
        key = f["key"]
        indent = line[:len(line) - len(line.lstrip())]
        if f["form"] == "list":
            lines[idx] = f"{indent}- {key}=${{{key}}}"
        else:
            lines[idx] = f"{indent}{key}: ${{{key}}}"
        changed.append(key)
    return "\n".join(lines) + ("\n" if text.endswith("\n") else ""), changed


# A .env assignment. `export ` is accepted because a file that is both sourced
# by a shell and read by compose is written that way.
ENV_ASSIGN_RE = re.compile(
    r"^\s*(?:export\s+)?(?P<key>[A-Za-z_][A-Za-z0-9_.]*)\s*=(?P<value>.*)$")


def scan_env_text(text, source=""):
    """Findings for one .env file. Same finding shape as scan_text().

    WHY THIS IS A SEPARATE FUNCTION
    -------------------------------
    scan_text walks compose block structure so it knows when it is inside a
    service's `environment:`. A .env has no blocks — every line is a bare
    assignment — so the compose scanner runs over one and finds nothing at all.
    That silence is the dangerous part: compose interpolates ${KEY} from the
    .env beside it *precisely so the value is not in the yaml*, which means the
    store scan reads clean exactly where the real credential lives. A fleet can
    therefore report zero findings while every unit has a password on disk.

    Findings carry raw values, same as scan_text — pass through public() before
    any of this leaves the process.
    """
    findings = []
    for i, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = ENV_ASSIGN_RE.match(line)
        if not m:
            continue
        key = m.group("key")
        # _strip_value only treats " #" (space-hash) as a comment, which is what
        # keeps a value like *E>e#Dma!w#Rk7@ intact — '#' is a perfectly ordinary
        # character in a generated password and truncating there would file a
        # silently wrong secret.
        value, quote = _strip_value(m.group("value"))
        hit, severity, reason = classify(key, value)
        if not hit:
            continue
        # classify() is shared with the compose scanner and words its generic
        # reason for that context. Restate it here so a .env report does not
        # send someone hunting for an environment: block that does not exist.
        if reason == "literal credential in an environment block":
            reason = "literal credential in a .env file"
        findings.append({
            "source": source,
            "line": i,
            "key": key,
            "form": "dotenv",
            "quote": quote,
            "severity": severity,
            "reason": reason,
            "masked": mask(value),
            "value": value,      # callers MUST NOT serialise this outward
        })
    return findings


def public(findings):
    """Findings with the raw values stripped — the only form safe to return
    from an HTTP endpoint or write to an event log."""
    return [{k: v for k, v in f.items() if k != "value"} for f in findings]
