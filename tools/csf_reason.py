"""Parse CSF/LFD grep output into an operator reason + customer-safe text."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

_TAG = re.compile(r"<[^>]+>")
_LFD_SVC = re.compile(r"\((\w+)\)")
_ATTEMPTS = re.compile(r"(\d+)\s+in the last\s+(\d+)\s+secs", re.I)
_COMMENT = re.compile(r"#\s*(.+)$")

_LIST_HINTS = (
    ("csf.tempban", "temporary deny (LFD)"),
    ("tempban", "temporary deny (LFD)"),
    ("csf.tempallow", "temporary allow"),
    ("tempallow", "temporary allow"),
    ("csf.deny", "permanent deny"),
    ("csf.allow", "allow list"),
    ("csf.ignore", "ignore list"),
    ("denyin", "iptables DENYIN"),
    ("denyout", "iptables DENYOUT"),
    ("deny", "deny"),
    ("allowin", "iptables ALLOWIN"),
    ("allow", "allow"),
)

# Map LFD/BFM tokens to a short label the customer can understand.
_SERVICE_LABEL = {
    "sshd": "SSH",
    "ssh": "SSH",
    "dovecot": "email (IMAP/POP)",
    "imapd": "email (IMAP)",
    "imap": "email (IMAP)",
    "pop3d": "email (POP3)",
    "pop3": "email (POP3)",
    "exim": "outgoing mail (SMTP)",
    "smtpauth": "mail password",
    "smtpd": "mail (SMTP)",
    "ftpd": "FTP",
    "pureftpd": "FTP",
    "proftpd": "FTP",
    "directadmin": "the control panel",
    "da": "the control panel",
    "wordpress": "WordPress",
    "wp": "WordPress",
    "cxs": "a malware scan",
    "modsec": "the web application firewall",
    "lf_modsec": "the web application firewall",
    "htpasswd": "a password-protected page",
}


def as_text(payload: Any) -> str:
    if payload is None:
        return ""
    if isinstance(payload, (bytes, bytearray)):
        payload = payload.decode("utf-8", errors="replace")
    if not isinstance(payload, str):
        payload = str(payload)
    return _TAG.sub("\n", payload)


def _list_name(line: str) -> Optional[str]:
    lowered = line.lower()
    for needle, label in _LIST_HINTS:
        if needle in lowered:
            return label
    return None


def parse_csf_grep(payload: Any, address: str) -> Dict[str, Any]:
    """Turn plugin `action=grep` / csf -g HTML into structured hits."""
    text = as_text(payload)
    hits: List[Dict[str, Any]] = []
    current_list: Optional[str] = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        hinted = _list_name(line)
        if hinted and address not in line:
            current_list = hinted
            continue
        if address not in line:
            continue
        comment = None
        match = _COMMENT.search(line)
        if match:
            comment = match.group(1).strip()
        svc = None
        if comment:
            found = _LFD_SVC.search(comment)
            if found:
                svc = found.group(1).lower()
        attempts = None
        window = None
        if comment:
            found = _ATTEMPTS.search(comment)
            if found:
                attempts = found.group(1)
                window = found.group(2)
        where = hinted or current_list or "csf grep"
        hits.append(
            {
                "list": where,
                "service": svc,
                "attempts": attempts,
                "window_seconds": window,
                "comment": comment,
                "line": line[:400],
            }
        )
    summaries = []
    for hit in hits:
        bits = [hit["list"]]
        if hit.get("service"):
            bits.append(f"({hit['service']})")
        if hit.get("attempts"):
            bits.append(f"{hit['attempts']} hits")
        if hit.get("comment"):
            bits.append(hit["comment"])
        summaries.append(" ".join(bits))
    return {
        "listed": bool(hits),
        "hits": hits,
        "reason": summaries[0] if summaries else None,
        "raw_excerpt": text[:2000],
    }


def _label(service: Optional[str]) -> Optional[str]:
    if not service:
        return None
    return _SERVICE_LABEL.get(service.lower(), service)


def customer_messages(ip: str, *, csf: Optional[Dict[str, Any]] = None, bfm: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """Plain language for the operator to paste to the customer. No host paths."""
    labels: List[str] = []
    attempts = None
    temporary = False
    listed = False

    if csf and csf.get("listed"):
        listed = True
        for hit in csf.get("hits") or []:
            label = _label(hit.get("service"))
            if label and label not in labels:
                labels.append(label)
            if hit.get("attempts") and not attempts:
                attempts = hit["attempts"]
            where = (hit.get("list") or "").lower()
            if "temporary" in where or "temp" in where:
                temporary = True

    if bfm:
        if bfm.get("listed") or bfm.get("blocked"):
            listed = True
        for event in bfm.get("events") or []:
            label = _label(event.get("service"))
            if label and label not in labels:
                labels.append(label)
            if event.get("attempts") and not attempts:
                attempts = event["attempts"]

    if not listed:
        return {
            "en": f"{ip} is not listed in CSF or Brute Force Monitor right now.",
            "bg": f"{ip} в момента не фигурира в CSF или Brute Force Monitor.",
        }

    what = " and ".join(labels) if labels else "the server"
    count = f" after {attempts} failed attempts" if attempts else ""
    kind = "temporarily blocked" if temporary else "blocked"

    en = (
        f"Your IP address ({ip}) was {kind} by the server firewall because of "
        f"failed login attempts on {what}{count}. "
        "This is automatic protection against password guessing. "
        "After we unblock it, please use the correct password or reset it. "
        "If you use a mobile network or VPN, the address may change and look like a new attacker."
    )
    bg = (
        f"IP адресът ви ({ip}) беше "
        f"{'временно блокиран' if temporary else 'блокиран'} от защитната стена на сървъра "
        f"заради неуспешни опити за вход към {what}{(' след ' + str(attempts) + ' опита') if attempts else ''}. "
        "Това е автоматична защита срещу познаване на пароли. "
        "След отблокиране ползвайте правилната парола или я сменете. "
        "При мобилна мрежа или VPN адресът може да се смени и да изглежда като нов атакуващ."
    )
    return {"en": en, "bg": bg}
