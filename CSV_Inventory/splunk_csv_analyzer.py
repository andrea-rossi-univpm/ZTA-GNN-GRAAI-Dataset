#!/usr/bin/env python3
"""
splunk_csv_to_latex.py - Splunk CSV Export → Console + .log + .tex

Usage:
    python3 splunk_csv_to_latex.py <csv_file>

Output:
    - Console: general dataset info
    - <csv_basename>_report.log   : plain-text tables
    - <csv_basename>_tables.tex   : LaTeX tables

Tables generated:
    1. Summary       (Host × Source × Sourcetype)
    2. Per-Host
    3. Per-Sourcetype
    4. Traffic Class  (logical grouping: Auth, Model, Chat, Honeypot, …)
"""

import csv
import json
import re
import sys
import os
from datetime import datetime
from collections import defaultdict

# ─────────────────────────── Time parsing ────────────────────────

TIME_FORMATS = [
    "%d-%b-%Y %H:%M:%S",
    "%d-%b-%Y %H:%M",
    "%d/%m/%Y %H:%M",
    "%d/%m/%Y %H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
]


def parse_time(raw: str) -> datetime | None:
    raw = raw.strip().rstrip("\r")
    for fmt in TIME_FORMATS:
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return None


def fmt_ts(dt: datetime) -> str:
    return dt.strftime("%H:%M:%S")


def fmt_duration(seconds: float) -> str:
    if seconds < 1:
        return "<1 sec"
    if seconds < 60:
        return f"{seconds:.0f} sec"
    if seconds < 3600:
        m = seconds / 60
        return f"{m:.2f} min" if m < 10 else f"{m:.0f} min"
    h = seconds / 3600
    return f"{h:.1f} h"


def fmt_n(n: int) -> str:
    return f"{n:,}"


def fmt_size(nbytes: int) -> str:
    if nbytes < 1024:
        return f"{nbytes} B"
    if nbytes < 1024 * 1024:
        return f"{nbytes / 1024:.1f} KB"
    return f"{nbytes / (1024 * 1024):.2f} MB"


# ─────────────────────────── LaTeX escaping ──────────────────────

def esc(s: str) -> str:
    s = s.replace("\\", "\x00BK\x00")
    s = s.replace("{", "\\{")
    s = s.replace("}", "\\}")
    s = s.replace("\x00BK\x00", "\\textbackslash{}")
    for ch, repl in [("_", "\\_"), ("&", "\\&"), ("%", "\\%"),
                     ("#", "\\#"), ("~", "\\textasciitilde{}"),
                     ("^", "\\textasciicircum{}")]:
        s = s.replace(ch, repl)
    return s


# ──────────────────────── Security classification ────────────────

SECURITY_SOURCETYPES = {
    "security:badrequest", "security:badraequest",
    "security:honeypot", "security:alert",
    "security:ratelimit", "security:forbidden",
    "security:audit", "security:jwt", "security:log",
}

SEC_COLOR = "darkred"


def is_sec_st(st: str) -> bool:
    return st.lower() in SECURITY_SOURCETYPES


def color(text: str, security: bool) -> str:
    if security:
        return f"\\textcolor{{{SEC_COLOR}}}{{\\textbf{{{text}}}}}"
    return text


# ──────────────────── Traffic Class classification ───────────────
# Derives a human-readable traffic class dynamically from the
# source/sourcetype namespace convention:
#     sourcetype = "category:subtype"   e.g. security:ratelimit
#     source     = "Blazor:ver:AuditType"  e.g. Blazor:2.0.0.2:AuthAudit
#
# No hardcoded if/elif chains — parses the colon-delimited taxonomy.

# Known abbreviation expansions (lowercase key → title-cased label)
_ABBREV = {
    "db":    "Database",
    "iis":   "IIS",
    "mssql": "MSSQL",
    "jwt":   "JWT",
    "ntpd":  "NTPd",
    "ids":   "IDS",
    "hec":   "HEC",
    "tcp":   "TCP",
    "arp":   "ARP",
    "p0f":   "p0f",
    "ntp":   "NTP",
    "dns":   "DNS",
}

# Concatenated lowercase words commonly found in Splunk sourcetypes.
# Maps lowered token → space-separated words for humanization.
_COMPOUNDS = {
    "badrequest":   "Bad Request",
    "badraequest":  "Bad Request",      # known typo variant
    "ratelimit":    "Rate Limit",
    "filterlog":    "Filter Log",
    "errorlog":     "Error Log",
    "httperr":      "HTTP Error",
    "wineventlog":  "Event Log",
    "xmlwineventlog": "Event Log",
    "cmdshell":     "Cmd Shell",
    "userlogin":    "User Login",
    "userlogout":   "User Logout",
}

# CamelCase / compound word splitter:
#   "badrequest"  → "Bad Request"
#   "filterlog"   → "Filterlog"
#   "ratelimit"   → "Rate Limit"
#   "db-backup"   → "Database Backup"
_COMPOUND_SPLIT = re.compile(r"""
    [A-Z][a-z]+           |   # CamelCase word
    [A-Z]+(?=[A-Z][a-z])  |   # ACRONYM before CamelCase
    [A-Z]+                |   # trailing ACRONYM
    [a-z]+                    # lowercase word
""", re.VERBOSE)


def _humanize(token: str) -> str:
    """Turn a sourcetype token into a human-readable label.
       'badrequest' → 'Bad Request', 'db-backup' → 'Database Backup',
       'jwt:attack' → 'JWT Attack'
    """
    # Check compound words first (whole token, before splitting)
    if token.lower() in _COMPOUNDS:
        return _COMPOUNDS[token.lower()]

    # Split on hyphens, underscores, and colons (multi-level subtypes)
    parts = re.split(r"[-_:]", token)
    words = []
    for part in parts:
        if not part:
            continue
        lo = part.lower()
        # Known compound sub-part?
        if lo in _COMPOUNDS:
            words.append(_COMPOUNDS[lo])
            continue
        # Known abbreviation?
        if lo in _ABBREV:
            words.append(_ABBREV[lo])
            continue
        # Try CamelCase split
        found = _COMPOUND_SPLIT.findall(part)
        if found:
            words.extend(found)
        else:
            words.append(part)
    return " ".join(w.capitalize() if w == w.lower() else w for w in words)


def _parse_sourcetype(sourcetype: str) -> tuple[str, str]:
    """Split 'category:subtype[:extra]' → (category, subtype_humanized).
       Single-token sourcetypes → (token, token).
    """
    parts = sourcetype.split(":")
    if len(parts) >= 2:
        category = parts[0].lower()
        subtype = ":".join(parts[1:])  # preserve 'iis:auto', 'conn:json'
        return category, _humanize(subtype)
    return parts[0].lower(), _humanize(parts[0])


def _extract_blazor_audit_type(source: str) -> str | None:
    """'Blazor:2.0.0.2:AuthAudit' → 'AuthAudit', else None."""
    parts = source.split(":")
    for p in reversed(parts):
        if "audit" in p.lower():
            return p
    return None


def classify_traffic(source: str, sourcetype: str) -> tuple[str, bool]:
    """Returns (traffic_class_label, is_security_class)."""
    src_lo = source.lower()
    st_lo = sourcetype.lower()
    category, _ = _parse_sourcetype(sourcetype)
    is_security = (category == "security")

    # ── Blazor audit sources: derive class from audit type + sourcetype ──
    audit_type = _extract_blazor_audit_type(source)
    if audit_type:
        at_lo = audit_type.lower()
        _, subtype_label = _parse_sourcetype(sourcetype)

        # AuthAudit → "Authentication" (sourcetype is just 'fingerprint')
        if "auth" in at_lo and "application" not in at_lo:
            if category == "fingerprint" or st_lo == "fingerprint":
                return "Authentication", False
            return f"Auth: {subtype_label}", is_security

        # ApplicationAudit → label from sourcetype namespace.
        # Guard against generic subtype labels (e.g. security:log → "Log")
        # that lose category context. Prefix with category when the subtype
        # token alone is ambiguous.
        _GENERIC_SUBLABELS = {"log", "data", "event", "record", "error", "info", "audit"}
        if category in ("security", "application"):
            if subtype_label.lower() in _GENERIC_SUBLABELS:
                prefix = "Security" if category == "security" else "App"
                return f"{prefix} {subtype_label}", is_security
            return subtype_label, is_security
        if st_lo == "fingerprint":
            return "App Fingerprint", False
        return subtype_label, is_security

    # ── Infrastructure: derive from source name or sourcetype ──
    if src_lo == "p0f":
        return "Network Fingerprint (p0f)", False
    if "arp-watch" in src_lo or "arp" in src_lo.split("/")[-1]:
        return "ARP Watch", False
    if "captive" in src_lo:
        return "Captive Portal", False
    if "hec-diagnostic" in src_lo or "hec_diagnostic" in src_lo:
        return "HEC Diagnostic", False

    # Derive from sourcetype taxonomy
    _, subtype_label = _parse_sourcetype(sourcetype)

    if category == "opnsense":
        return f"OPNsense {subtype_label}", False
    if category in ("ms", "xmlwineventlog"):
        if "iis" in st_lo:
            return f"IIS {subtype_label}" if subtype_label != "IIS" else "IIS", False
        return f"Windows {subtype_label}" if category == "ms" else "Sysmon", False
    if category == "mssql":
        return f"MSSQL {subtype_label}", False
    if category == "bro":
        return f"Zeek {subtype_label}", False
    if category == "iis":
        return f"IIS {subtype_label}", False

    # Catch-all: prefix category when subtype alone is a generic/ambiguous word.
    # Prevents "Error" (apache:error), "Access" (nginx:access), etc.
    _GENERIC_SUBLABELS = {"log", "data", "event", "record", "error", "info",
                          "audit", "access", "alert", "status", "output"}
    if subtype_label.lower() in _GENERIC_SUBLABELS and category:
        return f"{category.capitalize()} {subtype_label}", is_security
    return subtype_label, is_security


def build_tc_security_map(rows) -> dict[str, bool]:
    """Build {traffic_class_name: is_security} from loaded rows."""
    m = {}
    for r in rows:
        tc = r["traffic_class"]
        if tc not in m:
            m[tc] = r["traffic_is_sec"]
    return m


# ──────────────── Traffic Class LITE (dataset composition) ───────
# Groups events by logical function: CRUD, Auth, Chat, Honeypot, Fingerprint, etc.
# No sections — just a flat label derived from source + sourcetype.

def classify_traffic_lite(source: str, sourcetype: str) -> str:
    """Returns a single high-level label for dataset composition."""
    src_lo = source.lower()
    st_lo = sourcetype.lower()

    # Blazor sources → check audit type first
    audit_type = _extract_blazor_audit_type(source)
    if audit_type:
        at_lo = audit_type.lower()

        # AuthAudit → "Authentication" (even if sourcetype=fingerprint)
        if "auth" in at_lo and "application" not in at_lo:
            return "Authentication"

        # ApplicationAudit → derive from sourcetype
        category, subtype_label = _parse_sourcetype(sourcetype)
        if st_lo == "application:model":
            return "CRUD Operations"
        if st_lo == "application:chat":
            return "Chat"
        if st_lo == "application:document":
            return "Document"
        if st_lo == "application:db-backup":
            return "Database Backup"
        if st_lo == "application:exception":
            return "Exception"
        # security:* → humanized (Bad Request, Honeypot, Rate Limit, ...)
        # Guard against generic single-word labels losing category context.
        _GENERIC_SUBLABELS = {"log", "data", "event", "record", "error", "info", "audit"}
        if category == "security":
            if subtype_label.lower() in _GENERIC_SUBLABELS:
                return f"Security {subtype_label}"
            return subtype_label
        # fingerprint on ApplicationAudit → App Fingerprint
        if st_lo == "fingerprint":
            return "Fingerprint"
        if category == "application":
            if subtype_label.lower() in _GENERIC_SUBLABELS:
                return f"App {subtype_label}"
        return subtype_label

    # Non-Blazor: fingerprint sourcetype (p0f, arp-watch, HEC) → Fingerprint
    if st_lo == "fingerprint":
        return "Fingerprint"

    # Infrastructure → humanize from sourcetype
    category, subtype_label = _parse_sourcetype(sourcetype)
    if category == "opnsense":
        return f"OPNsense {subtype_label}"
    if category == "iis" or (category == "ms" and "iis" in st_lo):
        return "IIS"
    if category == "mssql":
        return "MSSQL"
    if category == "bro":
        return f"Zeek {subtype_label}"
    if st_lo == "snort":
        return "Snort IDS"
    if st_lo == "tcpdump":
        return "tcpdump"

    # Catch-all: prefix category when subtype alone is a generic/ambiguous word.
    # Prevents "Error" (apache:error), "Access" (nginx:access), etc.
    _GENERIC_SUBLABELS = {"log", "data", "event", "record", "error", "info",
                          "audit", "access", "alert", "status", "output"}
    if subtype_label.lower() in _GENERIC_SUBLABELS and category:
        return f"{category.capitalize()} {subtype_label}"
    return subtype_label


# ──────────────────────────── Data model ─────────────────────────

class Acc:
    """Accumulator: count, min/max time, suspicious count."""
    __slots__ = ("count", "first", "last", "sus")

    def __init__(self):
        self.count = 0
        self.first = None
        self.last = None
        self.sus = 0

    def add(self, ts: datetime, suspicious=None):
        self.count += 1
        if self.first is None or ts < self.first:
            self.first = ts
        if self.last is None or ts > self.last:
            self.last = ts
        if suspicious is True:
            self.sus += 1

    @property
    def duration(self) -> float:
        if self.first and self.last:
            return (self.last - self.first).total_seconds()
        return 0.0

    @property
    def time_range_str(self) -> str:
        if self.first and self.last:
            return f"{fmt_ts(self.first)} - {fmt_ts(self.last)}"
        return ""


# ──────────────────────────── CSV loader ─────────────────────────

def load(path: str):
    rows = []
    with open(path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ts = parse_time(row.get("time", ""))
            if ts is None:
                continue

            host = row.get("host", "").strip()
            source = row.get("source", "").strip()
            sourcetype = row.get("sourcetype", "").strip()
            msg_raw = row.get("message", "").strip()

            suspicious = None
            event_type = ""
            ip = ""
            user = ""
            try:
                msg = json.loads(msg_raw)
                suspicious = msg.get("Suspicious")
                event_type = msg.get("EventType", "")
                ip = msg.get("IP", "")
                user = msg.get("User", "")
            except (json.JSONDecodeError, TypeError):
                pass

            traffic_class, traffic_is_sec = classify_traffic(source, sourcetype)
            traffic_lite = classify_traffic_lite(source, sourcetype)

            rows.append({
                "ts": ts, "host": host, "source": source,
                "sourcetype": sourcetype, "sus": suspicious,
                "event_type": event_type, "ip": ip, "user": user,
                "traffic_class": traffic_class,
                "traffic_is_sec": traffic_is_sec,
                "traffic_lite": traffic_lite,
            })
    return rows


def csv_file_info(path: str) -> dict:
    """Get file metadata: name, size, row count."""
    size_bytes = os.path.getsize(path)
    with open(path, "r", encoding="utf-8-sig") as f:
        row_count = sum(1 for _ in f) - 1  # minus header
    return {
        "filename": os.path.basename(path),
        "fullpath": os.path.abspath(path),
        "size_bytes": size_bytes,
        "size_str": fmt_size(size_bytes),
        "rows": row_count,
    }


# ────────────────────────── Aggregation ──────────────────────────

def aggregate(rows, key_fn) -> dict:
    buckets = defaultdict(Acc)
    for r in rows:
        buckets[key_fn(r)].add(r["ts"], r["sus"])
    return dict(sorted(buckets.items(), key=lambda x: -x[1].count))


# ─────────────────────── Console output ──────────────────────────

def print_console(rows, finfo):
    total = len(rows)
    sus = sum(1 for r in rows if r["sus"] is True)
    non_sus = total - sus
    pct_sus = (sus / total * 100) if total else 0
    pct_non = (non_sus / total * 100) if total else 0

    first = min(r["ts"] for r in rows)
    last = max(r["ts"] for r in rows)
    dur = (last - first).total_seconds()

    print("=" * 60)
    print(f"  File:               {finfo['filename']}")
    print(f"  Size:               {finfo['size_str']} ({finfo['rows']} rows)")
    print(f"  Processed:          {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Total events:       {fmt_n(total)}")
    print(f"  Suspicious:         {fmt_n(sus):>10}  ({pct_sus:.1f}%)")
    print(f"  Non-suspicious:     {fmt_n(non_sus):>10}  ({pct_non:.1f}%)")
    print(f"  Dataset balance:    {pct_sus:.1f}% malicious / {pct_non:.1f}% benign")
    print(f"  First event:        {first.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Last event:         {last.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Duration:           {fmt_duration(dur)} ({dur:.2f} sec)")
    print(f"  Unique hosts:       {len(set(r['host'] for r in rows))}")
    print(f"  Unique sourcetypes: {len(set(r['sourcetype'] for r in rows))}")
    print(f"  Traffic classes:    {len(set(r['traffic_class'] for r in rows))}")
    print("=" * 60)


# ──────────────────────── .log generator ─────────────────────────

def write_log(rows, path, finfo):
    total = len(rows)
    sus = sum(1 for r in rows if r["sus"] is True)
    non_sus = total - sus
    first = min(r["ts"] for r in rows)
    last = max(r["ts"] for r in rows)
    dur = (last - first).total_seconds()

    L = []
    L.append("=" * 90)
    L.append("SPLUNK CSV REPORT")
    L.append("=" * 90)
    L.append(f"File:               {finfo['filename']}")
    L.append(f"Path:               {finfo['fullpath']}")
    L.append(f"File size:          {finfo['size_str']}")
    L.append(f"CSV rows:           {fmt_n(finfo['rows'])}")
    L.append(f"Report generated:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    L.append("-" * 90)
    L.append(f"Total events:       {fmt_n(total)}")
    L.append(f"Suspicious:         {fmt_n(sus)} ({sus/total*100:.1f}%)")
    L.append(f"Non-suspicious:     {fmt_n(non_sus)} ({non_sus/total*100:.1f}%)")
    L.append(f"Time window:        {first} -> {last}")
    L.append(f"Duration:           {fmt_duration(dur)} ({dur:.2f} sec)")
    L.append("")

    # ── Table 1: Summary (Host × Source × Sourcetype) ──
    L.append("-" * 90)
    L.append("SUMMARY: HOST x SOURCE x SOURCETYPE")
    L.append("-" * 90)
    hdr = f"{'Host':<20} {'Source':<40} {'Evt':>7} {'Sus':>7} {'Sourcetype':<28} {'Time Range'}"
    L.append(hdr)
    L.append("-" * len(hdr))
    by_hss = aggregate(rows, lambda r: (r["host"], r["source"], r["sourcetype"]))
    for (h, src, st), acc in by_hss.items():
        L.append(f"{h:<20} {src:<40} {acc.count:>7} {acc.sus:>7} {st:<28} {acc.time_range_str}")
    L.append("")

    # ── Table 2: Per-Host ──
    L.append("-" * 90)
    L.append("PER-HOST")
    L.append("-" * 90)
    hdr = f"{'Host':<20} {'Events':>8} {'Suspicious':>10} {'First':>10} {'Last':>10} {'Duration':>12}"
    L.append(hdr)
    L.append("-" * len(hdr))
    by_host = aggregate(rows, lambda r: r["host"])
    for host, acc in by_host.items():
        L.append(f"{host:<20} {acc.count:>8} {acc.sus:>10} {fmt_ts(acc.first):>10} {fmt_ts(acc.last):>10} {fmt_duration(acc.duration):>12}")
    L.append("")

    # ── Table 3: Per-Sourcetype ──
    L.append("-" * 90)
    L.append("PER-SOURCETYPE")
    L.append("-" * 90)
    hdr = f"{'Sourcetype':<30} {'Events':>8} {'Suspicious':>10} {'First':>10} {'Last':>10} {'Duration':>12}"
    L.append(hdr)
    L.append("-" * len(hdr))
    by_st = aggregate(rows, lambda r: r["sourcetype"])
    for st, acc in by_st.items():
        L.append(f"{st:<30} {acc.count:>8} {acc.sus:>10} {fmt_ts(acc.first):>10} {fmt_ts(acc.last):>10} {fmt_duration(acc.duration):>12}")
    L.append("")

    # ── Table 4: Traffic Class ──
    L.append("-" * 90)
    L.append("TRAFFIC CLASS")
    L.append("-" * 90)
    hdr = f"{'Traffic Class':<28} {'Events':>8} {'Suspicious':>10} {'First':>10} {'Last':>10} {'Duration':>12}"
    L.append(hdr)
    L.append("-" * len(hdr))
    by_tc = aggregate(rows, lambda r: r["traffic_class"])
    for tc, acc in by_tc.items():
        L.append(f"{tc:<28} {acc.count:>8} {acc.sus:>10} {fmt_ts(acc.first):>10} {fmt_ts(acc.last):>10} {fmt_duration(acc.duration):>12}")
    L.append("")

    # ── Table 5: Dataset Composition ──
    L.append("-" * 90)
    L.append("DATASET COMPOSITION")
    L.append("-" * 90)
    hdr = f"{'Traffic Class':<32} {'Events':>8} {'Suspicious':>12} {'Not Suspicious':>16} {'Duration':>12}"
    L.append(hdr)
    L.append("-" * len(hdr))

    by_lite = aggregate(rows, lambda r: r["traffic_lite"])
    total_sus = 0
    total_not = 0
    for label, acc in by_lite.items():
        not_sus = acc.count - acc.sus
        total_sus += acc.sus
        total_not += not_sus
        L.append(f"{label:<32} {acc.count:>8} {acc.sus:>12} {not_sus:>16} {fmt_duration(acc.duration):>12}")

    L.append("-" * len(hdr))
    L.append(f"{'TOTAL':<32} {fmt_n(total):>8} {total_sus:>12} {total_not:>16}")
    L.append("")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L))


# ──────────────────────── .tex generator ─────────────────────────

def write_tex(rows, path, label_prefix):
    total = len(rows)
    sus = sum(1 for r in rows if r["sus"] is True)
    first = min(r["ts"] for r in rows)
    last = max(r["ts"] for r in rows)
    dur = (last - first).total_seconds()

    T = []
    T.append(f"% Generated by splunk_csv_to_latex.py")
    T.append(f"% Total: {fmt_n(total)} events | Suspicious: {fmt_n(sus)} | Duration: {fmt_duration(dur)}")
    T.append("")

    # ═══════════ Table 1: Summary (Host × Source × Sourcetype) ═══════════
    by_hss = aggregate(rows, lambda r: (r["host"], r["source"], r["sourcetype"]))

    T.append(r"\begin{table}[hbtp]")
    T.append(f"\\caption{{Event volume by host, source, and sourcetype ({fmt_duration(dur)})}}")
    T.append(f"\\label{{tab:{label_prefix}_volume}}")
    T.append(r"\centering")
    T.append(r"\scriptsize")
    T.append(r"\begin{tabular}{|l|l|r|r|l|l|}")
    T.append(r"\hline")
    T.append(r"\textbf{Host} & \textbf{Source} & \textbf{Events} & \textbf{Suspicious} & \textbf{Sourcetype} & \textbf{Time Range} \\")
    T.append(r"\hline")

    for (host, source, sourcetype), acc in by_hss.items():
        sec = is_sec_st(sourcetype)
        src_d = esc(source)
        if "ApplicationAudit" in source or "AuthAudit" in source:
            src_d = f"\\textbf{{{src_d}}}"

        T.append(
            f"{esc(host)} & {src_d} & {color(fmt_n(acc.count), sec)} "
            f"& {color(fmt_n(acc.sus), sec) if acc.sus else str(acc.sus)} "
            f"& {color(esc(sourcetype), sec)} & {acc.time_range_str} \\\\"
        )

    T.append(r"\hline")
    T.append(
        f"\\multicolumn{{2}}{{|r|}}{{\\textbf{{Total}}}} & \\textbf{{{fmt_n(total)}}} "
        f"& \\textbf{{{fmt_n(sus)}}} & & \\\\"
    )
    T.append(r"\hline")
    T.append(r"\end{tabular}")
    T.append(r"\end{table}")
    T.append("")

    # ═══════════ Table 2: Per-Host ═══════════
    by_host = aggregate(rows, lambda r: r["host"])

    T.append(r"\begin{table}[hbtp]")
    T.append(f"\\caption{{Per-host event distribution}}")
    T.append(f"\\label{{tab:{label_prefix}_host}}")
    T.append(r"\centering")
    T.append(r"\scriptsize")
    T.append(r"\begin{tabular}{|l|r|r|l|l|l|}")
    T.append(r"\hline")
    T.append(r"\textbf{Host} & \textbf{Events} & \textbf{Suspicious} & \textbf{First Event} & \textbf{Last Event} & \textbf{Duration} \\")
    T.append(r"\hline")

    for host, acc in by_host.items():
        T.append(
            f"{esc(host)} & {fmt_n(acc.count)} & {fmt_n(acc.sus)} "
            f"& {fmt_ts(acc.first)} & {fmt_ts(acc.last)} & {fmt_duration(acc.duration)} \\\\"
        )

    T.append(r"\hline")
    T.append(r"\end{tabular}")
    T.append(r"\end{table}")
    T.append("")

    # ═══════════ Table 3: Per-Sourcetype ═══════════
    by_st = aggregate(rows, lambda r: r["sourcetype"])

    T.append(r"\begin{table}[hbtp]")
    T.append(f"\\caption{{Per-sourcetype event distribution}}")
    T.append(f"\\label{{tab:{label_prefix}_sourcetype}}")
    T.append(r"\centering")
    T.append(r"\scriptsize")
    T.append(r"\begin{tabular}{|l|r|r|l|l|l|}")
    T.append(r"\hline")
    T.append(r"\textbf{Sourcetype} & \textbf{Events} & \textbf{Suspicious} & \textbf{First Event} & \textbf{Last Event} & \textbf{Duration} \\")
    T.append(r"\hline")

    for st, acc in by_st.items():
        sec = is_sec_st(st)
        T.append(
            f"{color(esc(st), sec)} & {color(fmt_n(acc.count), sec)} & {color(fmt_n(acc.sus), sec) if acc.sus else str(acc.sus)} "
            f"& {fmt_ts(acc.first)} & {fmt_ts(acc.last)} & {fmt_duration(acc.duration)} \\\\"
        )

    T.append(r"\hline")
    T.append(r"\end{tabular}")
    T.append(r"\end{table}")
    T.append("")

    # ═══════════ Table 4: Traffic Class ═══════════
    by_tc = aggregate(rows, lambda r: r["traffic_class"])
    tc_sec_map = build_tc_security_map(rows)

    T.append(r"\begin{table}[hbtp]")
    T.append(f"\\caption{{Traffic class distribution}}")
    T.append(f"\\label{{tab:{label_prefix}_traffic_class}}")
    T.append(r"\centering")
    T.append(r"\scriptsize")
    T.append(r"\begin{tabular}{|l|r|r|l|l|l|}")
    T.append(r"\hline")
    T.append(r"\textbf{Traffic Class} & \textbf{Events} & \textbf{Suspicious} & \textbf{First Event} & \textbf{Last Event} & \textbf{Duration} \\")
    T.append(r"\hline")

    for tc, acc in by_tc.items():
        sec = tc_sec_map.get(tc, False)
        T.append(
            f"{color(esc(tc), sec)} & {color(fmt_n(acc.count), sec)} & {color(fmt_n(acc.sus), sec) if acc.sus else str(acc.sus)} "
            f"& {fmt_ts(acc.first)} & {fmt_ts(acc.last)} & {fmt_duration(acc.duration)} \\\\"
        )

    T.append(r"\hline")
    T.append(r"\end{tabular}")
    T.append(r"\end{table}")
    T.append("")

    # ═══════════ Table 5: Dataset Composition ═══════════
    by_lite = aggregate(rows, lambda r: r["traffic_lite"])
    total_sus = sum(a.sus for _, a in by_lite.items())
    total_not = total - total_sus

    T.append(r"\begin{table}[hbtp]")
    T.append(f"\\caption{{Dataset composition: event volume per traffic class}}")
    T.append(f"\\label{{tab:{label_prefix}_dataset}}")
    T.append(r"\centering")
    T.append(r"\small")
    T.append(r"\begin{tabular}{lrrrr}")
    T.append(r"\toprule")
    T.append(r"\textbf{Traffic Class} & \textbf{Events} & \textbf{Suspicious} & \textbf{Not Suspicious} & \textbf{Duration} \\")
    T.append(r"\midrule")

    for label, acc in by_lite.items():
        not_sus = acc.count - acc.sus
        sec = (acc.sus > 0 and acc.sus == acc.count)  # fully suspicious → red
        T.append(
            f"{color(esc(label), sec)} & {color(fmt_n(acc.count), sec)} "
            f"& {color(fmt_n(acc.sus), sec) if acc.sus else '0'} "
            f"& {fmt_n(not_sus)} & {fmt_duration(acc.duration)} \\\\"
        )

    T.append(r"\midrule")
    T.append(
        f"\\textbf{{Total}} & \\textbf{{{fmt_n(total)}}} "
        f"& \\textbf{{{fmt_n(total_sus)}}} & \\textbf{{{fmt_n(total_not)}}} & \\\\"
    )
    T.append(r"\bottomrule")
    T.append(r"\end{tabular}")
    T.append(r"\end{table}")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(T))


# ──────────────────────────── Main ───────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <csv_file>", file=sys.stderr)
        sys.exit(1)

    csv_path = sys.argv[1]
    if not os.path.isfile(csv_path):
        print(f"Error: file not found: {csv_path}", file=sys.stderr)
        sys.exit(1)

    finfo = csv_file_info(csv_path)
    rows = load(csv_path)
    if not rows:
        print("Error: no valid records parsed.", file=sys.stderr)
        sys.exit(1)

    base = os.path.splitext(os.path.basename(csv_path))[0]
    out_dir = os.path.dirname(os.path.abspath(csv_path))
    log_path = os.path.join(out_dir, f"{base}_report.log")
    tex_path = os.path.join(out_dir, f"{base}_tables.tex")
    label_prefix = base.replace("-", "_").replace(" ", "_")

    print_console(rows, finfo)
    write_log(rows, log_path, finfo)
    write_tex(rows, path=tex_path, label_prefix=label_prefix)

    print(f"\n  -> {log_path}")
    print(f"  -> {tex_path}")


if __name__ == "__main__":
    main()
