"""The simulations' events as ECS: the datasets a scenario's logs come from, the time of an event in
its raw line, and the mapping of each event to an ECS document, with the index templates that type it.

A scenario's log files (sim/scenarios/<id>/logs/) hold each event as its source wrote it. For Splunk's
Boss of the SOC v1, a line is {"preview":..., "offset":..., "result": {...}}: the Splunk event with
its search-time fields (CIM names such as src_ip, EventCode, Image) and the original event in _raw.
map_event() turns one into an ECS document shaped like the output of Elastic's own integrations
(Windows/Sysmon, System, Suricata, IIS, FortiGate, Network Packet Capture), so Elastic's prebuilt
rules and Sigma rules converted with an ECS pipeline find the fields they query. An event that is
already an ECS document passes through.

Every document also keeps:
  event.original   the original event (_raw), stored but not indexed
  botes.splunk     Splunk's own fields for the event (one flattened field, so they can't cause
                   mapping conflicts), for hunting with the names BOTS v1 write-ups use.
The botes.* fields keep the names the scenarios' answers search for (botes.scenario,
botes.replay.run_id). The replay sets @timestamp, original_timestamp, event.ingested and
data_stream.* itself (app/services/sim/replay.py). Standard library only.
"""

from __future__ import annotations

import html
import ipaddress
import json
import ntpath
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

# ── The datasets ────────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Dataset:
    key: str            # the source's name in a scenario's logs (logs/<key>.ndjson.gz)
    stem: str           # its file's name in the BOTS v1 dataset (botsv1.<stem>.json.gz)
    sourcetype: str     # the Splunk sourcetype
    ds: str             # data stream dataset: events go to logs-<ds>-<namespace>
    module: str         # event.module
    group: str          # windows | network | web | firewall | vuln
    aliases: tuple = ()


DATASETS: dict[str, Dataset] = {d.key: d for d in [
    Dataset("sysmon", "XmlWinEventLog-Microsoft-Windows-Sysmon-Operational",
            "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational", "windows.sysmon_operational", "sysmon",
            "windows", ("xmlwineventlog-sysmon",)),
    Dataset("security", "WinEventLog-Security", "WinEventLog:Security", "system.security", "system",
            "windows", ("winevent-security", "wineventlog-security")),
    Dataset("system", "WinEventLog-System", "WinEventLog:System", "system.system", "system",
            "windows", ("winevent-system", "wineventlog-system")),
    Dataset("application", "WinEventLog-Application", "WinEventLog:Application", "system.application",
            "system", "windows", ("winevent-application", "wineventlog-application")),
    Dataset("winregistry", "winregistry", "WinRegistry", "windows.registry", "winregmon", "windows",
            ("registry",)),
    Dataset("suricata", "suricata", "suricata", "suricata.eve", "suricata", "network"),
    Dataset("iis", "iis", "iis", "iis.access", "iis", "web"),
    Dataset("fgt_traffic", "fgt_traffic", "fgt_traffic", "fortinet_fortigate.log", "fortinet_fortigate",
            "firewall"),
    Dataset("fgt_utm", "fgt_utm", "fgt_utm", "fortinet_fortigate.log", "fortinet_fortigate", "firewall"),
    Dataset("fgt_event", "fgt_event", "fgt_event", "fortinet_fortigate.log", "fortinet_fortigate", "firewall"),
    Dataset("nessus", "nessus-scan", "nessus:scan", "nessus.scan", "nessus", "vuln", ("nessus-scan",)),
    Dataset("stream-http", "stream-http", "stream:http", "network_traffic.http", "network_traffic", "web"),
    Dataset("stream-dns", "stream-dns", "stream:dns", "network_traffic.dns", "network_traffic", "network"),
    Dataset("stream-tcp", "stream-tcp", "stream:tcp", "network_traffic.flow", "network_traffic", "network"),
    Dataset("stream-ip", "stream-ip", "stream:ip", "network_traffic.flow", "network_traffic", "network"),
    Dataset("stream-icmp", "stream-icmp", "stream:icmp", "network_traffic.icmp", "network_traffic", "network"),
    Dataset("stream-dhcp", "stream-dhcp", "stream:dhcp", "network_traffic.dhcpv4", "network_traffic",
            "network"),
    Dataset("stream-smb", "stream-smb", "stream:smb", "network_traffic.smb", "network_traffic", "network"),
    Dataset("stream-ldap", "stream-ldap", "stream:ldap", "network_traffic.ldap", "network_traffic", "network"),
    Dataset("stream-mapi", "stream-mapi", "stream:mapi", "network_traffic.mapi", "network_traffic", "network"),
    Dataset("stream-sip", "stream-sip", "stream:sip", "network_traffic.sip", "network_traffic", "network"),
    Dataset("stream-snmp", "stream-snmp", "stream:snmp", "network_traffic.snmp", "network_traffic", "network"),
]}

# Named selections of sources. "attack" is the set the two BOTS v1 attacks show up in.
DATASET_GROUPS: dict[str, list[str]] = {
    "all": list(DATASETS),
    "attack": ["sysmon", "security", "system", "winregistry", "suricata", "iis", "fgt_utm",
               "stream-http", "stream-dns", "stream-smb"],
    "windows": [k for k, d in DATASETS.items() if d.group == "windows"],
    "network": [k for k, d in DATASETS.items() if d.group in ("network", "firewall", "web")],
}


def dataset_for_stem(stem: str) -> Dataset:
    """The catalogue entry for a file stem (one BOTS v1 doesn't have gets a generic entry)."""
    for d in DATASETS.values():
        if d.stem.lower() == stem.lower():
            return d
    key = stem.lower()
    return Dataset(key, stem, stem, "sim." + key.replace("-", "_"), "sim", "other")


def dataset(key: str) -> Dataset:
    """The catalogue entry for a pack file's source: a BOTS v1 dataset ('sysmon'), an ECS dataset an
    imported file named itself ('zeek.conn', replayed to its own data stream), or a generic entry for
    any other Splunk sourcetype."""
    if key in DATASETS:
        return DATASETS[key]
    if "." in key:
        return Dataset(key, key, key, key, key.split(".", 1)[0], "other")
    return dataset_for_stem(key)


def for_sourcetype(sourcetype: str) -> str:
    """The dataset key for a Splunk sourcetype: a BOTS v1 one, or a key made from its name."""
    st = str(sourcetype or "").strip().lower()
    for d in DATASETS.values():
        if st in (d.sourcetype.lower(), d.stem.lower(), d.key, *d.aliases):
            return d.key
    return re.sub(r"[^a-z0-9_-]+", "-", st).strip("-") or "splunk"


def for_ecs_dataset(name: str) -> str:
    """The dataset key for an ECS event.dataset: a BOTS v1 one with that data stream, or the name itself."""
    name = str(name or "").strip().lower()
    for d in DATASETS.values():
        if d.ds == name:
            return d.key
    return re.sub(r"[^a-z0-9._-]+", "_", name).strip("._-")


def resolve(names: list[str] | None) -> list[str]:
    """Sources named by keys, aliases, stems or group names, as catalogue keys, in order."""
    if not names:
        return list(DATASETS)
    lookup = {}
    for d in DATASETS.values():
        for n in (d.key, d.stem, *d.aliases):
            lookup[n.lower()] = d.key
    out: list[str] = []
    for raw in names:
        for name in (p.strip().lower() for p in raw.split(",")):
            if not name:
                continue
            if name in DATASET_GROUPS:
                keys = DATASET_GROUPS[name]
            elif name in lookup:
                keys = [lookup[name]]
            else:
                choices = ", ".join(sorted([*DATASETS, *DATASET_GROUPS]))
                raise ValueError(f"Unknown dataset '{name}'. Choose from: {choices}")
            out.extend(k for k in keys if k not in out)
    return out


# ── Time ────────────────────────────────────────────────────────────────────────────────────────

def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ── ECS ─────────────────────────────────────────────────────────────────────────────────────────

ECS_VERSION = "8.11.0"

# Splunk's own bookkeeping, dropped from botes.splunk.
SPLUNK_INTERNAL = {
    "_bkt", "_cd", "_si", "_serial", "_indextime", "_eventtype_color", "_sourcetype", "_subsecond",
    "_kv", "_pre_msg", "_raw", "_time", "punct", "splunk_server", "linecount", "index", "timestartpos",
    "timeendpos", "timestamp", "body", "Message", "tag::eventtype", "date_hour", "date_mday",
    "date_minute", "date_month", "date_second", "date_wday", "date_year", "date_zone",
}

# Time zones Splunk printed in _time (BOTS v1 was indexed in US Mountain time).
TZ_HOURS = {"MDT": -6, "MST": -7, "UTC": 0, "GMT": 0, "Z": 0, "PDT": -7, "PST": -8, "CDT": -5,
            "CST": -6, "EDT": -4, "EST": -5}

# Per-dataset corrections added to Splunk's _time, for a source whose clock was wrong. None is needed
# for BOTS v1: checked against the defacement, where the scanner's traffic lines up to the second in
# Suricata, stream:http and IIS. (Suricata's file simply runs six hours past the other sources.)
CLOCK_OFFSETS: dict[str, timedelta] = {}

_TIME_KEYS = (b'"_time":"', b'"@timestamp":"')


# ── Time ─────────────────────────────────────────────────────────────────────────────────────────

def parse_splunk_time(value: str) -> datetime | None:
    """'2016-08-28 17:59:00.000 MDT' (or ISO 8601) -> aware UTC datetime."""
    if not value:
        return None
    try:
        if "T" in value[:11]:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
        parts = value.split(" ")
        dt = datetime.strptime(" ".join(parts[:2]), "%Y-%m-%d %H:%M:%S.%f")
        hours = TZ_HOURS.get(parts[2] if len(parts) > 2 else "UTC", 0)
        return dt.replace(tzinfo=timezone(timedelta(hours=hours))).astimezone(timezone.utc)
    except (ValueError, IndexError):
        return None


def line_time(line: bytes) -> datetime | None:
    """The event time of a raw line, without parsing the whole JSON (used for seeking and merging)."""
    for key in _TIME_KEYS:
        i = line.rfind(key)
        if i >= 0:
            j = line.find(b'"', i + len(key))
            if j > 0:
                return parse_splunk_time(line[i + len(key):j].decode("ascii", "replace"))
    return None


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


# ── Small helpers ───────────────────────────────────────────────────────────────────────────────

EMPTY = (None, "", "-", "N/A", "n/a", "unknown", [], {})


def first(value):
    """The first non-empty item of a Splunk multi-value field (or the value itself)."""
    if isinstance(value, list):
        for v in value:
            if v not in EMPTY:
                return v
        return None
    return None if value in EMPTY else value


def uniq(value) -> list:
    out = []
    for v in value if isinstance(value, list) else [value]:
        if v not in EMPTY and v not in out:
            out.append(v)
    return out


def as_ip(value) -> str | None:
    for v in uniq(value):
        try:
            ip = ipaddress.ip_address(str(v).strip().strip("[]").split("%")[0])
            if ip.version == 6 and ip.ipv4_mapped:
                ip = ip.ipv4_mapped
            return str(ip)
        except ValueError:
            continue
    return None


def as_int(value) -> int | None:
    v = first(value)
    if v is None:
        return None
    s = str(v).strip()
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(float(s))
    except ValueError:
        return None


def as_port(value) -> int | None:
    n = as_int(value)
    return n if n is not None and 0 <= n <= 65535 else None


def put(doc: dict, path: str, value) -> None:
    """doc['a']['b']['c'] = value for 'a.b.c'; empty values are skipped."""
    if value in EMPTY:
        return
    node = doc
    *parents, leaf = path.split(".")
    for p in parents:
        node = node.setdefault(p, {})
    node[leaf] = value


def get(doc: dict, path: str):
    node = doc
    for p in path.split("."):
        if not isinstance(node, dict) or p not in node:
            return None
        node = node[p]
    return node


def win_base(path) -> str | None:
    return ntpath.basename(path) if path not in EMPTY else None


def split_user(value) -> tuple[str | None, str | None]:
    """'DOMAIN\\user' -> (domain, user)."""
    v = first(value)
    if not v:
        return None, None
    if "\\" in str(v):
        domain, _, name = str(v).partition("\\")
        return domain or None, name or None
    return None, str(v)


def win_args(cmd: str | None) -> list[str]:
    """Split a Windows command line the way CommandLineToArgvW does."""
    if not cmd:
        return []
    args, cur, quoted, have, i = [], [], False, False, 0
    while i < len(cmd):
        c = cmd[i]
        if c == "\\":
            j = i
            while j < len(cmd) and cmd[j] == "\\":
                j += 1
            n = j - i
            if j < len(cmd) and cmd[j] == '"':
                cur.append("\\" * (n // 2))
                if n % 2:
                    cur.append('"')
                    j += 1
                i, have = j, True
                continue
            cur.append("\\" * n)
            i, have = j, True
            continue
        if c == '"':
            quoted, have = not quoted, True
        elif c in " \t" and not quoted:
            if have:
                args.append("".join(cur))
                cur, have = [], False
        else:
            cur.append(c)
            have = True
        i += 1
    if have:
        args.append("".join(cur))
    return args


def set_process(doc: dict, prefix: str, executable=None, pid=None, command_line=None, entity_id=None,
                name=None) -> None:
    executable = first(executable)
    put(doc, f"{prefix}.executable", executable)
    put(doc, f"{prefix}.name", name or win_base(executable))
    put(doc, f"{prefix}.pid", as_int(pid))
    put(doc, f"{prefix}.entity_id", first(entity_id))
    command_line = first(command_line)
    if command_line:
        put(doc, f"{prefix}.command_line", command_line)
        args = win_args(command_line)
        put(doc, f"{prefix}.args", args)
        put(doc, f"{prefix}.args_count", len(args) or None)


def set_file(doc: dict, path, prefix: str = "file") -> None:
    path = first(path)
    if not path:
        return
    put(doc, f"{prefix}.path", path)
    put(doc, f"{prefix}.name", ntpath.basename(path))
    put(doc, f"{prefix}.directory", ntpath.dirname(path))
    ext = ntpath.splitext(path)[1].lstrip(".").lower()
    put(doc, f"{prefix}.extension", ext or None)


def set_hashes(doc: dict, value, prefix: str) -> None:
    """Sysmon's 'SHA1=..,MD5=..,SHA256=..,IMPHASH=..' -> <prefix>.hash.*, <prefix>.pe.imphash."""
    for part in str(first(value) or "").split(","):
        algo, _, digest = part.partition("=")
        algo, digest = algo.strip().lower(), digest.strip().lower()
        if not digest:
            continue
        if algo == "imphash":
            put(doc, f"{prefix}.pe.imphash", digest)
        elif algo in ("md5", "sha1", "sha256", "sha512"):
            put(doc, f"{prefix}.hash.{algo}", digest)


def set_host(doc: dict, name, windows: bool = False) -> None:
    name = first(name)
    if not name:
        return
    name = str(name).lower()
    short, _, domain = name.partition(".")
    # A stable id per host, as an agent would give: rules group and track new terms by host.id.
    put(doc, "host.id", str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{short}.botes")))
    put(doc, "host.name", short)
    put(doc, "host.hostname", short)
    put(doc, "host.domain", domain or None)
    if windows:
        doc.setdefault("host", {})["os"] = {"type": "windows", "family": "windows", "platform": "windows",
                                            "name": "Windows"}


def set_endpoints(doc: dict, r: dict, src_ip="src_ip", src_port="src_port", dst_ip="dest_ip",
                  dst_port="dest_port") -> None:
    put(doc, "source.ip", as_ip(r.get(src_ip)))
    put(doc, "source.port", as_port(r.get(src_port)))
    put(doc, "destination.ip", as_ip(r.get(dst_ip)))
    put(doc, "destination.port", as_port(r.get(dst_port)))
    for side, key in (("source", "src_mac"), ("destination", "dest_mac")):
        mac = first(r.get(key))
        if mac:
            put(doc, f"{side}.mac", str(mac).upper().replace(":", "-"))


def slug(text) -> str | None:
    text = first(text)
    if not text:
        return None
    return re.sub(r"[^a-z0-9]+", "-", str(text).lower()).strip("-") or None


def ns_duration(value, unit_ns: int) -> int | None:
    n = as_int(value)
    return n * unit_ns if n is not None else None


IANA_TRANSPORT = {"1": "icmp", "6": "tcp", "17": "udp", "58": "ipv6-icmp", "47": "gre", "50": "esp"}


# ── Windows: Sysmon (XmlWinEventLog) ─────────────────────────────────────────────────────────────

_XML_DATA = re.compile(r"<Data Name='([^']+)'(?:>(.*?)</Data>|\s*/>)", re.S)
_XML_SYSTEM = {
    "provider_name": re.compile(r"<Provider Name='([^']*)'"),
    "provider_guid": re.compile(r"<Provider Name='[^']*' Guid='([^']*)'"),
    "event_id": re.compile(r"<EventID[^>]*>(\d+)</EventID>"),
    "version": re.compile(r"<Version>(\d+)</Version>"),
    "level": re.compile(r"<Level>(\d+)</Level>"),
    "task": re.compile(r"<Task>(\d+)</Task>"),
    "opcode": re.compile(r"<Opcode>(\d+)</Opcode>"),
    "record_id": re.compile(r"<EventRecordID>(\d+)</EventRecordID>"),
    "process_id": re.compile(r"<Execution ProcessID='(\d+)'"),
    "thread_id": re.compile(r"ThreadID='(\d+)'"),
    "channel": re.compile(r"<Channel>([^<]*)</Channel>"),
    "computer_name": re.compile(r"<Computer>([^<]*)</Computer>"),
    "user_id": re.compile(r"<Security UserID='([^']*)'"),
}

SYSMON_EVENTS = {
    "1": (["process"], ["start"], "Process Create (rule: ProcessCreate)"),
    "2": (["file"], ["change"], "File creation time changed (rule: FileCreateTime)"),
    "3": (["network"], ["connection", "start"], "Network connection detected (rule: NetworkConnect)"),
    "4": (["process"], ["change"], "Sysmon service state changed"),
    "5": (["process"], ["end"], "Process terminated (rule: ProcessTerminate)"),
    "6": (["driver"], ["start"], "Driver loaded (rule: DriverLoad)"),
    "7": (["library"], ["start"], "Image loaded (rule: ImageLoad)"),
    "8": (["process"], ["change"], "CreateRemoteThread detected (rule: CreateRemoteThread)"),
    "9": (["process"], ["access"], "RawAccessRead detected (rule: RawAccessRead)"),
    "10": (["process"], ["access"], "Process accessed (rule: ProcessAccess)"),
    "11": (["file"], ["creation"], "File created (rule: FileCreate)"),
    "12": (["registry"], ["change"], "Registry object added or deleted (rule: RegistryEvent)"),
    "13": (["registry"], ["change"], "Registry value set (rule: RegistryEvent)"),
    "14": (["registry"], ["change"], "Registry object renamed (rule: RegistryEvent)"),
    "15": (["file"], ["creation"], "File stream created (rule: FileCreateStreamHash)"),
    "16": (["configuration"], ["change"], "Sysmon config state changed"),
    "17": (["file"], ["creation"], "Pipe Created (rule: PipeEvent)"),
    "18": (["file"], ["access"], "Pipe Connected (rule: PipeEvent)"),
    "22": (["network"], ["protocol", "info"], "Dns query (rule: DnsQuery)"),
    "23": (["file"], ["deletion"], "File Delete archived (rule: FileDelete)"),
    "255": (["process"], ["error"], "Error report"),
}

SYSMON_FROM_SPLUNK = (  # fallback when _raw isn't usable XML
    "UtcTime", "ProcessGuid", "ProcessId", "Image", "CommandLine", "CurrentDirectory", "User", "LogonGuid",
    "LogonId", "TerminalSessionId", "IntegrityLevel", "Hashes", "ParentProcessGuid", "ParentProcessId",
    "ParentImage", "ParentCommandLine", "TargetFilename", "CreationUtcTime", "PreviousCreationUtcTime",
    "Protocol", "Initiated", "SourceIsIpv6", "SourceIp", "SourceHostname", "SourcePort", "SourcePortName",
    "DestinationIsIpv6", "DestinationIp", "DestinationHostname", "DestinationPort", "DestinationPortName",
    "ImageLoaded", "Signed", "Signature", "SignatureStatus", "SourceProcessGuid", "SourceProcessId",
    "SourceImage", "TargetProcessGuid", "TargetProcessId", "TargetImage", "NewThreadId", "StartAddress",
    "StartModule", "StartFunction", "GrantedAccess", "CallTrace", "TargetObject", "Details", "EventType",
    "QueryName", "QueryStatus", "QueryResults", "RuleName", "State", "Device",
)


def map_sysmon(r: dict) -> dict:
    raw = r.get("_raw") or ""
    data = {k: html.unescape(v or "") for k, v in _XML_DATA.findall(raw)}
    system = {}
    for key, rx in _XML_SYSTEM.items():
        m = rx.search(raw)
        if m:
            system[key] = html.unescape(m.group(1))
    if not data:
        data = {k: str(first(r.get(k))) for k in SYSMON_FROM_SPLUNK if first(r.get(k)) is not None}
    code = system.get("event_id") or str(first(r.get("EventCode")) or "")
    category, etype, action = SYSMON_EVENTS.get(code, (["host"], ["info"], first(r.get("EventDescription"))))

    doc: dict = {"event": {"kind": "event", "category": category, "type": etype, "code": code,
                           "provider": system.get("provider_name") or "Microsoft-Windows-Sysmon"}}
    put(doc, "event.action", action)
    computer = system.get("computer_name") or first(r.get("Computer"))
    set_host(doc, computer, windows=True)
    winlog = {
        "channel": system.get("channel") or "Microsoft-Windows-Sysmon/Operational",
        "provider_name": system.get("provider_name") or "Microsoft-Windows-Sysmon",
        "provider_guid": system.get("provider_guid"),
        "event_id": code,
        "record_id": system.get("record_id") or first(r.get("RecordID")),
        "computer_name": computer,
        "api": "wineventlog",
        "version": as_int(system.get("version")),
        "task": system.get("task"),
        "opcode": system.get("opcode"),
        "process": {"pid": as_int(system.get("process_id")), "thread": {"id": as_int(system.get("thread_id"))}},
        "user": {"identifier": system.get("user_id")},
        "event_data": {k: v for k, v in data.items() if v != ""},
    }
    for k, v in winlog.items():
        put(doc, f"winlog.{k}", v)
    put(doc, "log.level", {"4": "information", "3": "warning", "2": "error"}.get(system.get("level", "4")))
    put(doc, "rule.name", data.get("RuleName"))

    d = data.get
    if code in ("8", "10"):  # the acting process is the source; the target stays in event_data
        set_process(doc, "process", d("SourceImage"), d("SourceProcessId"), entity_id=d("SourceProcessGuid"))
        put(doc, "process.thread.id", as_int(d("SourceThreadId")))
    else:
        set_process(doc, "process", d("Image"), d("ProcessId"), d("CommandLine"), d("ProcessGuid"))
    put(doc, "process.working_directory", d("CurrentDirectory"))
    if code == "1":
        set_process(doc, "process.parent", d("ParentImage"), d("ParentProcessId"), d("ParentCommandLine"),
                    d("ParentProcessGuid"))
        set_hashes(doc, d("Hashes"), "process")
        put(doc, "process.pe.file_version", d("FileVersion"))
        put(doc, "process.pe.description", d("Description"))
        put(doc, "process.pe.product", d("Product"))
        put(doc, "process.pe.company", d("Company"))
        put(doc, "process.pe.original_file_name", d("OriginalFileName"))
    domain, name = split_user(d("User"))
    put(doc, "user.domain", domain)
    put(doc, "user.name", name)
    put(doc, "user.id", system.get("user_id"))
    put(doc, "winlog.logon.id", d("LogonId"))

    if code in ("2", "11", "15", "23"):
        set_file(doc, d("TargetFilename"))
    elif code == "6":
        set_file(doc, d("ImageLoaded"))
        set_hashes(doc, d("Hashes"), "file")
    elif code == "7":
        set_file(doc, d("ImageLoaded"))
        set_file(doc, d("ImageLoaded"), "dll")
        set_hashes(doc, d("Hashes"), "file")
        set_hashes(doc, d("Hashes"), "dll")
    if code in ("6", "7"):
        signed = (d("Signed") or "").lower()
        put(doc, "file.code_signature.signed", signed == "true" if signed in ("true", "false") else None)
        put(doc, "file.code_signature.subject_name", d("Signature"))
        put(doc, "file.code_signature.status", d("SignatureStatus"))
    if code == "3":
        put(doc, "source.ip", as_ip(d("SourceIp")))
        put(doc, "source.port", as_port(d("SourcePort")))
        put(doc, "source.domain", d("SourceHostname"))
        put(doc, "destination.ip", as_ip(d("DestinationIp")))
        put(doc, "destination.port", as_port(d("DestinationPort")))
        put(doc, "destination.domain", d("DestinationHostname"))
        put(doc, "network.transport", (d("Protocol") or "").lower() or None)
        put(doc, "network.protocol", d("DestinationPortName"))
        initiated = (d("Initiated") or "").lower()
        put(doc, "network.direction", {"true": "egress", "false": "ingress"}.get(initiated))
        put(doc, "network.type", "ipv6" if (d("SourceIsIpv6") or "").lower() == "true" else "ipv4")
    if code in ("12", "13", "14"):
        op = d("EventType") or ""
        set_registry(doc, d("TargetObject"), data=d("Details"), value_in_path=op in ("SetValue", "DeleteValue"))
        put(doc, "event.type", ["creation"] if op == "CreateKey" else
            ["deletion"] if op.startswith("Delete") else ["change"])
    if code == "22":
        put(doc, "dns.question.name", d("QueryName"))
        results = [x for x in (d("QueryResults") or "").split(";") if x]
        put(doc, "dns.resolved_ip", [ip for ip in (as_ip(x.replace("::ffff:", "")) for x in results) if ip])
    return doc


def set_registry(doc: dict, path, value=None, data=None, data_type=None, value_in_path=False) -> None:
    """registry.* from a full path; with value_in_path the last component is the value's name."""
    path = first(path)
    if not path:
        return
    path = re.sub(r"^HKEY_LOCAL_MACHINE", "HKLM", str(path), flags=re.I)
    path = re.sub(r"^HKEY_USERS", "HKU", path, flags=re.I)
    path = re.sub(r"^HKEY_CURRENT_USER", "HKCU", path, flags=re.I)
    hive, _, key = path.partition("\\")
    put(doc, "registry.path", path)
    put(doc, "registry.hive", hive.upper())
    if value_in_path:
        key, _, value = key.rpartition("\\")
    elif value and key.endswith("\\" + value):
        key = key[: -len(value) - 1]
    put(doc, "registry.key", key)
    put(doc, "registry.value", value)
    put(doc, "registry.data.strings", [str(data)] if data not in EMPTY else None)
    put(doc, "registry.data.type", data_type)


# ── Windows: classic event logs (WinEventLog:Security / System / Application) ───────────────────

_FIELD_LINE = re.compile(r"^(\t*)([^\t:][^\t]*?):(?:\t+|\s{2,}|\s*$)(.*)$")

ACCOUNT_SECTIONS = {
    "Subject": "Subject", "Creator Subject": "Subject",
    "New Logon": "Target", "Account For Which Logon Failed": "Target", "Target Account": "Target",
    "Target Subject": "Target", "New Account": "Target", "Account Whose Credentials Were Used": "Target",
    "Account Information": "Target", "Account That Was Locked Out": "Target", "Target": "Target",
}
ACCOUNT_LABELS = {"Security ID": "UserSid", "Account Name": "UserName", "Account Domain": "DomainName",
                  "Logon ID": "LogonId", "Linked Logon ID": "LinkedLogonId"}
LABELS = {
    "Logon Type": "LogonType", "Impersonation Level": "ImpersonationLevel", "Logon GUID": "LogonGuid",
    "Restricted Admin Mode": "RestrictedAdminMode", "Virtual Account": "VirtualAccount",
    "Elevated Token": "ElevatedToken", "Process ID": "ProcessId", "Process Name": "ProcessName",
    "New Process ID": "NewProcessId", "New Process Name": "NewProcessName",
    "Token Elevation Type": "TokenElevationType", "Mandatory Label": "MandatoryLabel",
    "Creator Process ID": "ProcessId", "Creator Process Name": "ParentProcessName",
    "Process Command Line": "CommandLine", "Workstation Name": "WorkstationName",
    "Source Network Address": "IpAddress", "Source Port": "IpPort", "Network Address": "IpAddress",
    "Port": "IpPort", "Client Address": "IpAddress", "Client Port": "IpPort", "Source Address": "IpAddress",
    "Source Workstation": "Workstation", "Caller Workstation": "Workstation",
    "Logon Process": "LogonProcessName", "Authentication Package": "AuthenticationPackageName",
    "Transited Services": "TransmittedServices", "Package Name (NTLM only)": "LmPackageName",
    "Key Length": "KeyLength", "Failure Reason": "FailureReason", "Status": "Status",
    "Sub Status": "SubStatus", "Failure Code": "Status", "Error Code": "Status",
    "Object Server": "ObjectServer", "Object Type": "ObjectType", "Object Name": "ObjectName",
    "Handle ID": "HandleId", "Resource Attributes": "ResourceAttributes", "Transaction ID": "TransactionId",
    "Accesses": "AccessList", "Access Reasons": "AccessReason", "Access Mask": "AccessMask",
    "Privileges Used for Access Check": "PrivilegeList", "Restricted SID Count": "RestrictedSidCount",
    "Share Name": "ShareName", "Share Path": "ShareLocalPath", "Relative Target Name": "RelativeTargetName",
    "Service Name": "ServiceName", "Service File Name": "ServiceFileName", "Service Type": "ServiceType",
    "Service Start Type": "ServiceStartType", "Service Account": "ServiceAccount", "Service ID": "ServiceSid",
    "Target Server Name": "TargetServerName", "Additional Information": "TargetInfo",
    "Ticket Options": "TicketOptions", "Ticket Encryption Type": "TicketEncryptionType",
    "Pre-Authentication Type": "PreAuthType", "Privileges": "PrivilegeList",
    "Enabled Privileges": "EnabledPrivilegeList", "Disabled Privileges": "DisabledPrivilegeList",
    "Task Name": "TaskName", "Task Content": "TaskContent", "Group Name": "TargetUserName",
    "Group Domain": "TargetDomainName", "Logon Account": "TargetUserName", "Direction": "Direction",
    "Destination Address": "DestAddress", "Destination Port": "DestPort", "Protocol": "Protocol",
    "Application Name": "Application", "Layer Name": "LayerName", "Filter Run-Time ID": "FilterRTID",
}
SECTION_LABELS = {
    ("Member", "Security ID"): "MemberSid", ("Member", "Account Name"): "MemberName",
    ("Group", "Security ID"): "TargetSid", ("Application Information", "Process ID"): "ProcessID",
}
WFP_EVENTS = {"5152", "5154", "5155", "5156", "5157", "5158", "5159"}
WFP_LABELS = {"Source Address": "SourceAddress", "Source Port": "SourcePort"}
SYSTEM_7045 = {"Service Name": "ServiceName", "Service File Name": "ImagePath", "Service Type": "ServiceType",
               "Service Start Type": "StartType", "Service Account": "AccountName"}


def camel(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", text.title()) or "Field"


def parse_message(message: str, code: str = "") -> dict:
    """The 'Section:' / '\\tLabel:\\t\\tValue' body of a classic event -> event_data, using Windows' names."""
    data: dict[str, list[str]] = {}
    section = None
    last: str | None = None
    for line in (message or "").replace("\r", "").split("\n")[1:]:
        if not line.strip():
            last = None
            continue
        m = _FIELD_LINE.match(line)
        if not m:
            if last and line.startswith("\t"):          # continuation of a list (privileges, accesses)
                data[last].append(line.strip())
            continue
        indent, label, value = m.group(1), m.group(2).strip(), m.group(3).strip()
        if not indent and not value:                     # 'Subject:' starts a section
            section, last = label, None
            name = LABELS.get(label)
            if name:                                      # 'Enabled Privileges:' followed by a list
                last = name
                data.setdefault(name, [])
            continue
        if not indent:
            section = None
        if section == "Application Information" and label == "Process ID":
            name = "ProcessID"
        elif (section, label) in SECTION_LABELS:
            name = SECTION_LABELS[(section, label)]
        elif section in ACCOUNT_SECTIONS and label in ACCOUNT_LABELS:
            name = ACCOUNT_SECTIONS[section] + ACCOUNT_LABELS[label]
        elif code in WFP_EVENTS and label in WFP_LABELS:
            name = WFP_LABELS[label]
        elif code == "7045" and label in SYSTEM_7045:
            name = SYSTEM_7045[label]
        else:
            name = LABELS.get(label) or camel(label)
        if name in data and data[name] and section:
            name = camel(section) + name
        data.setdefault(name, []).append(value)
        last = name
    out = {}
    for k, values in data.items():
        values = [v for v in values if v != ""]
        if values:
            out[k] = values[0] if len(values) == 1 else " ".join(values) if k.endswith("List") else values[0]
    return out


SECURITY_EVENTS = {
    "1102": ("audit-log-cleared", ["iam"], ["admin", "change"]),
    "4624": ("logged-in", ["authentication"], ["start"]),
    "4625": ("logon-failed", ["authentication"], ["start"]),
    "4634": ("logged-out", ["authentication"], ["end"]),
    "4647": ("logged-out", ["authentication"], ["end"]),
    "4648": ("logged-in-explicit", ["authentication"], ["start"]),
    "4656": ("requested-handle-to-object", ["file"], ["access"]),
    "4658": ("closed-handle-to-object", ["file"], ["info"]),
    "4660": ("deleted-object", ["file"], ["deletion"]),
    "4662": ("object-operation-performed", ["iam"], ["access"]),
    "4663": ("attempted-access-to-object", ["file"], ["access"]),
    "4670": ("permissions-changed", ["iam"], ["admin", "change"]),
    "4672": ("logged-in-special", ["iam"], ["admin"]),
    "4673": ("privileged-service-called", ["iam"], ["admin"]),
    "4674": ("privileged-operation", ["iam"], ["admin"]),
    "4688": ("created-process", ["process"], ["start"]),
    "4689": ("exited-process", ["process"], ["end"]),
    "4697": ("service-installed", ["iam", "configuration"], ["admin", "change"]),
    "4698": ("scheduled-task-created", ["iam", "configuration"], ["creation", "admin"]),
    "4699": ("scheduled-task-deleted", ["iam", "configuration"], ["deletion", "admin"]),
    "4702": ("scheduled-task-updated", ["iam", "configuration"], ["change", "admin"]),
    "4703": ("token-right-adjusted", ["iam"], ["admin", "change"]),
    "4719": ("changed-audit-config", ["iam", "configuration"], ["admin", "change"]),
    "4720": ("added-user-account", ["iam"], ["user", "creation"]),
    "4722": ("enabled-user-account", ["iam"], ["user", "change"]),
    "4723": ("changed-password", ["iam"], ["user", "change"]),
    "4724": ("reset-password", ["iam"], ["user", "change"]),
    "4725": ("disabled-user-account", ["iam"], ["user", "change"]),
    "4726": ("deleted-user-account", ["iam"], ["user", "deletion"]),
    "4728": ("added-member-to-group", ["iam"], ["group", "change"]),
    "4732": ("added-member-to-group", ["iam"], ["group", "change"]),
    "4756": ("added-member-to-group", ["iam"], ["group", "change"]),
    "4729": ("removed-member-from-group", ["iam"], ["group", "change"]),
    "4733": ("removed-member-from-group", ["iam"], ["group", "change"]),
    "4757": ("removed-member-from-group", ["iam"], ["group", "change"]),
    "4738": ("modified-user-account", ["iam"], ["user", "change"]),
    "4740": ("locked-out-user-account", ["iam"], ["user", "info"]),
    "4768": ("kerberos-authentication-ticket-requested", ["authentication"], ["start"]),
    "4769": ("kerberos-service-ticket-requested", ["authentication"], ["start"]),
    "4771": ("kerberos-preauth-failed", ["authentication"], ["start"]),
    "4776": ("credential-validated", ["authentication"], ["start"]),
    "4798": ("group-membership-enumerated", ["iam"], ["user", "info"]),
    "4799": ("user-member-enumerated", ["iam"], ["group", "info"]),
    "5140": ("network-share-object-accessed", ["network", "file"], ["access", "connection"]),
    "5145": ("network-share-object-access-checked", ["network", "file"], ["access", "connection"]),
    "5156": ("windows-firewall-connection-allowed", ["network"], ["connection", "allowed"]),
    "5157": ("windows-firewall-connection-blocked", ["network"], ["connection", "denied"]),
    "5158": ("windows-firewall-bind-allowed", ["network"], ["connection", "allowed"]),
}
TARGET_IS_USER = {"4624", "4625", "4634", "4647", "4768", "4769", "4771", "4776", "4740"}
LOGON_TYPES = {"2": "Interactive", "3": "Network", "4": "Batch", "5": "Service", "7": "Unlock",
               "8": "NetworkCleartext", "9": "NewCredentials", "10": "RemoteInteractive",
               "11": "CachedInteractive", "12": "CachedRemoteInteractive", "13": "CachedUnlock"}
SYSTEM_EVENTS = {
    "7045": ("service-installed", ["configuration"], ["creation"]),
    "7036": ("service-state-changed", ["configuration"], ["change"]),
    "7040": ("service-start-type-changed", ["configuration"], ["change"]),
    "7034": ("service-crashed", ["process"], ["end"]),
    "104": ("log-cleared", ["iam"], ["admin", "change"]),
    "6005": ("event-log-started", ["host"], ["start"]),
    "6006": ("event-log-stopped", ["host"], ["end"]),
}
PROVIDERS = {"Microsoft Windows security auditing.": "Microsoft-Windows-Security-Auditing"}


def map_wineventlog(r: dict, channel: str) -> dict:
    code = str(first(r.get("EventCode")) or "")
    message = r.get("Message") or r.get("body") or ""
    if isinstance(message, list):
        message = message[0]
    data = parse_message(message, code)
    table = SECURITY_EVENTS if channel == "Security" else SYSTEM_EVENTS
    action, category, etype = table.get(code, (slug(r.get("TaskCategory")) or slug(r.get("SourceName")),
                                               ["host"], ["info"]))
    provider = first(r.get("SourceName"))
    provider = PROVIDERS.get(provider, provider)
    keywords = uniq(r.get("Keywords"))
    doc: dict = {"event": {"kind": "event", "category": category, "type": etype, "code": code}}
    put(doc, "event.action", action)
    put(doc, "event.provider", provider)
    if "Audit Failure" in keywords:
        put(doc, "event.outcome", "failure")
    elif "Audit Success" in keywords:
        put(doc, "event.outcome", "success")
    put(doc, "message", message or None)
    computer = first(r.get("ComputerName")) or first(r.get("host"))
    set_host(doc, computer, windows=True)
    put(doc, "log.level", str(first(r.get("Type")) or "").lower() or None)
    for k, v in {"channel": channel, "provider_name": provider, "event_id": code, "computer_name": computer,
                 "record_id": first(r.get("RecordNumber")), "api": "wineventlog",
                 "task": first(r.get("TaskCategory")), "opcode": first(r.get("OpCode")),
                 "keywords": keywords or None, "event_data": data or None}.items():
        put(doc, f"winlog.{k}", v)

    d = data.get
    def account(prefix: str) -> dict:
        return {"name": d(prefix + "UserName"), "domain": d(prefix + "DomainName"), "id": d(prefix + "UserSid")}
    subject, target = account("Subject"), account("Target")
    if code in TARGET_IS_USER and target["name"] not in EMPTY:
        user, other = target, None
    else:
        user, other = (subject, target) if subject["name"] not in EMPTY else (target, None)
    for k, v in user.items():
        put(doc, f"user.{k}", v)
    if other and other["name"] not in EMPTY and other != user:
        for k, v in other.items():
            put(doc, f"user.target.{k}", v)
    put(doc, "source.ip", as_ip(d("IpAddress") or d("SourceAddress")))
    put(doc, "source.port", as_port(d("IpPort") or d("SourcePort")))
    put(doc, "source.domain", d("WorkstationName") or d("Workstation"))
    put(doc, "destination.ip", as_ip(d("DestAddress")))
    put(doc, "destination.port", as_port(d("DestPort")))
    put(doc, "winlog.logon.type", LOGON_TYPES.get(str(d("LogonType") or "")))
    put(doc, "winlog.logon.id", d("TargetLogonId") or d("SubjectLogonId"))
    if code == "4688":
        set_process(doc, "process", d("NewProcessName"), d("NewProcessId"), d("CommandLine"))
        set_process(doc, "process.parent", d("ParentProcessName"), d("ProcessId"))
    elif code == "4689":
        set_process(doc, "process", d("ProcessName"), d("ProcessId"))
    elif first(d("ProcessName")) or first(d("Application")):
        set_process(doc, "process", first(d("ProcessName")) or d("Application"), d("ProcessId") or d("ProcessID"))
    if d("ObjectType") == "File":
        set_file(doc, d("ObjectName"))
    if code in ("5140", "5145"):
        share = (d("ShareLocalPath") or "").replace("\\??\\", "")
        rel = d("RelativeTargetName")
        set_file(doc, ntpath.join(share, rel) if share and rel else rel or share or None)
    put(doc, "service.name", d("ServiceName"))
    if code == "7045":
        set_process(doc, "process", d("ImagePath"))
    return doc


# ── Windows: registry monitor (Splunk WinRegMon) ────────────────────────────────────────────────

def map_winregistry(r: dict) -> dict:
    op = str(first(r.get("registry_type")) or first(r.get("vendor_action")) or "")
    etype = ("creation" if op.startswith("Create") else "deletion" if op.startswith("Delete")
             else "change" if op.startswith("Set") or op.startswith("Rename") else "access")
    doc: dict = {"event": {"kind": "event", "category": ["registry"], "type": [etype], "action": op or None}}
    status = first(r.get("status"))
    put(doc, "event.outcome", {"success": "success", "failure": "failure"}.get(status))
    set_host(doc, r.get("host"), windows=True)
    value = first(r.get("registry_value_name"))
    key_path = first(r.get("key_path")) or first(r.get("registry_path"))
    path = f"{key_path}\\{value}" if value and key_path else key_path
    set_registry(doc, path, value=value, data=first(r.get("registry_value_data")) or first(r.get("data")),
                 data_type=first(r.get("registry_value_type")) or first(r.get("data_type")))
    set_process(doc, "process", r.get("process_image"), r.get("pid"))
    put(doc, "message", first(r.get("msg")))
    return doc


# ── Network: Suricata EVE ───────────────────────────────────────────────────────────────────────

def map_suricata(r: dict) -> dict:
    try:
        eve = json.loads(r.get("_raw") or "{}")
    except json.JSONDecodeError:
        eve = {}
    if not isinstance(eve, dict) or not eve:
        eve = {k: v for k, v in r.items() if not k.startswith("_") and k not in SPLUNK_INTERNAL}
    et = str(eve.get("event_type") or first(r.get("event_type")) or "")
    doc: dict = {"event": {"kind": "alert" if et == "alert" else "event", "category": ["network"],
                           "type": ["protocol"] if et in ("dns", "http", "tls", "smtp", "ssh") else ["connection"]}}
    put(doc, "suricata.eve", {k: v for k, v in eve.items() if k != "timestamp"})
    put(doc, "source.ip", as_ip(eve.get("src_ip") or r.get("src_ip")))
    put(doc, "source.port", as_port(eve.get("src_port") or r.get("src_port")))
    put(doc, "destination.ip", as_ip(eve.get("dest_ip") or r.get("dest_ip")))
    put(doc, "destination.port", as_port(eve.get("dest_port") or r.get("dest_port")))
    put(doc, "network.transport", str(eve.get("proto") or "").lower() or None)
    put(doc, "network.protocol", eve.get("app_proto") or (et if et in ("dns", "http", "tls") else None))
    put(doc, "observer.hostname", first(r.get("host")))
    put(doc, "observer.name", first(r.get("host")))
    put(doc, "observer.type", "ids")
    put(doc, "observer.vendor", "OISF")
    put(doc, "observer.product", "Suricata")
    put(doc, "observer.ingress.interface.name", eve.get("in_iface"))
    put(doc, "event.action", et or None)

    alert = eve.get("alert") if isinstance(eve.get("alert"), dict) else {}
    if alert:
        doc["event"]["category"] = ["network", "intrusion_detection"]
        doc["event"]["type"] = ["denied"] if alert.get("action") == "blocked" else ["allowed"]
        put(doc, "event.severity", as_int(alert.get("severity")))
        put(doc, "rule.id", str(alert.get("signature_id")) if alert.get("signature_id") is not None else None)
        put(doc, "rule.name", alert.get("signature"))
        put(doc, "rule.category", alert.get("category"))
        put(doc, "message", alert.get("signature"))
    http = eve.get("http") if isinstance(eve.get("http"), dict) else {}
    if http:
        doc["event"]["category"] = sorted(set(doc["event"]["category"]) | {"web"})
        put(doc, "http.request.method", http.get("http_method"))
        put(doc, "http.response.status_code", as_int(http.get("status")))
        put(doc, "http.response.body.bytes", as_int(http.get("length")))
        put(doc, "http.request.referrer", http.get("http_refer"))
        put(doc, "http.response.mime_type", str(http.get("http_content_type") or "").split(";")[0] or None)
        put(doc, "http.version", str(http.get("protocol") or "").replace("HTTP/", "") or None)
        put(doc, "user_agent.original", http.get("http_user_agent"))
        put(doc, "url.domain", http.get("hostname"))
        url = http.get("url")
        if url:
            put(doc, "url.original", url)
            path, _, query = url.partition("?")
            put(doc, "url.path", path)
            put(doc, "url.query", query or None)
    dns = eve.get("dns") if isinstance(eve.get("dns"), dict) else {}
    if dns:
        put(doc, "dns.type", dns.get("type"))
        put(doc, "dns.id", str(dns.get("id")) if dns.get("id") is not None else None)
        put(doc, "dns.question.name", dns.get("rrname"))
        put(doc, "dns.question.type", dns.get("rrtype"))
        put(doc, "dns.response_code", dns.get("rcode"))
        if dns.get("type") == "answer" and dns.get("rdata") is not None:
            put(doc, "dns.answers", [{"name": dns.get("rrname"), "type": dns.get("rrtype"),
                                       "data": str(dns.get("rdata")), "ttl": as_int(dns.get("ttl"))}])
            put(doc, "dns.resolved_ip", [as_ip(dns.get("rdata"))] if as_ip(dns.get("rdata")) else None)
    tls = eve.get("tls") if isinstance(eve.get("tls"), dict) else {}
    if tls:
        put(doc, "tls.client.server_name", tls.get("sni"))
        put(doc, "tls.server.subject", tls.get("subject"))
        put(doc, "tls.server.issuer", tls.get("issuerdn"))
        put(doc, "tls.version", str(tls.get("version") or "").replace("TLS ", "") or None)
    fileinfo = eve.get("fileinfo") if isinstance(eve.get("fileinfo"), dict) else {}
    if fileinfo:
        doc["event"]["category"] = sorted(set(doc["event"]["category"]) | {"file"})
        put(doc, "file.name", win_base(fileinfo.get("filename")) or fileinfo.get("filename"))
        put(doc, "file.size", as_int(fileinfo.get("size")))
    flow = eve.get("flow") if isinstance(eve.get("flow"), dict) else {}
    if flow:
        sb, db = as_int(flow.get("bytes_toserver")), as_int(flow.get("bytes_toclient"))
        put(doc, "source.bytes", sb)
        put(doc, "destination.bytes", db)
        put(doc, "source.packets", as_int(flow.get("pkts_toserver")))
        put(doc, "destination.packets", as_int(flow.get("pkts_toclient")))
        put(doc, "network.bytes", (sb or 0) + (db or 0) if sb is not None or db is not None else None)
    return doc


# ── Web: IIS W3C access log ─────────────────────────────────────────────────────────────────────

def map_iis(r: dict) -> dict:
    status = as_int(r.get("sc_status"))
    doc: dict = {"event": {"kind": "event", "category": ["web", "network"], "type": ["access"]}}
    put(doc, "event.outcome", None if status is None else "success" if status < 400 else "failure")
    set_host(doc, r.get("host"), windows=True)
    put(doc, "source.ip", as_ip(r.get("c_ip")))
    put(doc, "source.address", first(r.get("c_ip")))
    put(doc, "destination.ip", as_ip(r.get("s_ip")))
    put(doc, "destination.port", as_port(r.get("s_port")))
    put(doc, "http.request.method", first(r.get("cs_method")))
    put(doc, "http.response.status_code", status)
    put(doc, "http.request.referrer", first(r.get("cs_Referer")))
    put(doc, "url.path", first(r.get("cs_uri_stem")))
    query = first(r.get("cs_uri_query"))
    put(doc, "url.query", query)
    stem = first(r.get("cs_uri_stem"))
    put(doc, "url.original", f"{stem}?{query}" if stem and query else stem)
    ua = first(r.get("cs_User_Agent"))
    put(doc, "user_agent.original", ua.replace("+", " ") if ua else None)
    put(doc, "user.name", first(r.get("cs_username")))
    put(doc, "event.duration", ns_duration(r.get("time_taken"), 1_000_000))
    put(doc, "iis.access.sub_status", as_int(r.get("sc_substatus")))
    put(doc, "iis.access.win32_status", as_int(r.get("sc_win32_status")))
    put(doc, "message", r.get("_raw"))
    return doc


# ── Network: Splunk Stream (stream:*) ───────────────────────────────────────────────────────────

def map_stream(r: dict, proto: str) -> dict:
    doc: dict = {"event": {"kind": "event", "category": ["network"], "type": ["connection", "protocol"]}}
    set_endpoints(doc, r)
    transport = first(r.get("transport"))
    put(doc, "network.transport", str(transport).lower() if transport else None)
    put(doc, "network.protocol", proto)
    put(doc, "network.bytes", as_int(r.get("bytes")))
    put(doc, "network.packets", as_int(r.get("packets")))
    put(doc, "source.bytes", as_int(r.get("bytes_in")))
    put(doc, "destination.bytes", as_int(r.get("bytes_out")))
    put(doc, "source.packets", as_int(r.get("packets_in")))
    put(doc, "destination.packets", as_int(r.get("packets_out")))
    put(doc, "event.duration", ns_duration(r.get("time_taken"), 1000))
    put(doc, "observer.hostname", first(r.get("host")))
    put(doc, "observer.name", first(r.get("capture_hostname")) or first(r.get("host")))
    put(doc, "observer.type", "sensor")
    put(doc, "observer.product", "Splunk Stream")
    put(doc, "network.application", first(r.get("app")))

    if proto == "http":
        doc["event"]["category"] = ["network", "web"]
        status = as_int(r.get("status"))
        put(doc, "event.outcome", None if status is None else "success" if status < 400 else "failure")
        put(doc, "http.request.method", first(r.get("http_method")))
        put(doc, "http.response.status_code", status)
        put(doc, "http.request.referrer", first(r.get("http_referrer")))
        put(doc, "http.request.body.content", first(r.get("form_data")))
        put(doc, "http.response.body.bytes", as_int(r.get("http_content_length")))
        put(doc, "http.response.mime_type", str(first(r.get("http_content_type")) or "").split(";")[0] or None)
        put(doc, "http.version", first(r.get("cs_version{}")) or first(r.get("cs_version")))
        put(doc, "user_agent.original", first(r.get("http_user_agent")))
        site, uri = first(r.get("site")), first(r.get("uri"))
        put(doc, "url.domain", site)
        put(doc, "url.path", first(r.get("uri_path")))
        put(doc, "url.query", first(r.get("uri_query")))
        put(doc, "url.original", uri)
        if site and uri:
            scheme = "https" if as_port(r.get("dest_port")) == 443 else "http"
            put(doc, "url.full", f"{scheme}://{site}{uri}")
            put(doc, "url.scheme", scheme)
        put(doc, "http.request.cookie", first(r.get("cookie")))
    elif proto == "dns":
        names = uniq(r.get("query{}") or r.get("query") or r.get("name{}"))
        put(doc, "dns.question.name", names[0] if names else None)
        put(doc, "dns.question.type", first(r.get("query_type{}")) or first(r.get("record_type")))
        put(doc, "dns.id", first(r.get("transaction_id")))
        codes = uniq(r.get("reply_code{}") or r.get("reply_code"))
        put(doc, "dns.type", "answer" if codes else "query")
        put(doc, "dns.response_code", str(codes[0]).upper() if codes else None)
        answers = uniq(r.get("answer") or r.get("host_addr{}"))
        put(doc, "dns.answers", [{"data": str(a)} for a in answers] or None)
        put(doc, "dns.resolved_ip", [ip for ip in (as_ip(a) for a in uniq(r.get("host_addr{}"))) if ip] or None)
    elif proto == "smb":
        set_file(doc, first(r.get("filename")) or first(r.get("file_name")) or first(r.get("path")))
        put(doc, "smb.share", first(r.get("share")) or first(r.get("share_name")))
        put(doc, "event.action", first(r.get("command")) or first(r.get("smb_command")))
        put(doc, "user.name", first(r.get("username")) or first(r.get("user")))
    elif proto == "dhcp":
        put(doc, "client.mac", str(first(r.get("dest_mac")) or "").upper().replace(":", "-") or None)
        put(doc, "client.ip", as_ip(r.get("offer_addr")))
        put(doc, "client.domain", first(r.get("hostname")))
    elif proto == "ldap":
        put(doc, "event.action", first(r.get("operation")) or first(r.get("command")))
        put(doc, "user.name", first(r.get("bind_name")) or first(r.get("user")))
    return doc


# ── Firewall: FortiGate (fgt_traffic / fgt_utm / fgt_event) ─────────────────────────────────────

_FGT_OK = {"accept", "pass", "passthrough", "allowed", "allow", "close", "server-rst", "client-rst",
           "timeout", "success", "monitored"}
_FGT_BLOCK = {"deny", "block", "blocked", "dropped", "drop", "reset", "denied", "failure"}


def map_fortigate(r: dict) -> dict:
    ftype, subtype = first(r.get("type")), first(r.get("subtype"))
    action = first(r.get("ftnt_action")) or first(r.get("vendor_action")) or first(r.get("action"))
    if ftype == "traffic":
        category, etype = ["network"], ["connection", "end"]
    elif ftype == "utm":
        category = ["network", "intrusion_detection"] if subtype in ("ips", "anomaly", "virus") else \
            ["network", "web"] if subtype == "webfilter" else ["network"]
        etype = ["denied"] if str(action).lower() in _FGT_BLOCK else ["allowed"]
    else:
        category, etype = ["host"], ["info"]
    doc: dict = {"event": {"kind": "alert" if subtype in ("ips", "anomaly", "virus") else "event",
                           "category": category, "type": etype}}
    put(doc, "event.action", action)
    a = str(action or "").lower()
    put(doc, "event.outcome", "failure" if a in _FGT_BLOCK else "success" if a in _FGT_OK else None)
    set_endpoints(doc, r, "srcip", "srcport", "dstip", "dstport")
    proto = str(first(r.get("proto")) or "")
    put(doc, "network.iana_number", proto or None)
    put(doc, "network.transport", IANA_TRANSPORT.get(proto))
    put(doc, "network.application", str(first(r.get("app")) or "").lower() or None)
    sb, db = as_int(r.get("sentbyte")), as_int(r.get("rcvdbyte"))
    put(doc, "source.bytes", sb)
    put(doc, "destination.bytes", db)
    put(doc, "source.packets", as_int(r.get("sentpkt")))
    put(doc, "destination.packets", as_int(r.get("rcvdpkt")))
    put(doc, "network.bytes", (sb or 0) + (db or 0) if sb is not None or db is not None else None)
    put(doc, "observer.name", first(r.get("devname")))
    put(doc, "observer.hostname", first(r.get("devname")))
    put(doc, "observer.serial_number", first(r.get("devid")))
    put(doc, "observer.ip", as_ip(r.get("host")))
    put(doc, "observer.vendor", "Fortinet")
    put(doc, "observer.product", "Fortigate")
    put(doc, "observer.type", "firewall")
    put(doc, "observer.ingress.interface.name", first(r.get("srcintf")))
    put(doc, "observer.egress.interface.name", first(r.get("dstintf")))
    put(doc, "rule.id", first(r.get("attackid")) or first(r.get("policyid")))
    put(doc, "rule.name", first(r.get("attack")) or first(r.get("virus")) or first(r.get("policyname")))
    put(doc, "rule.category", first(r.get("catdesc")) or first(r.get("appcat")))
    put(doc, "rule.ruleset", subtype)
    hostname = first(r.get("hostname"))
    put(doc, "url.domain", hostname)
    url = first(r.get("url"))
    put(doc, "url.original", url)
    if url and hostname and url.startswith(hostname):
        put(doc, "url.path", url[len(hostname):] or "/")
    user = first(r.get("user"))
    put(doc, "user.name", user)
    put(doc, "message", first(r.get("msg")))
    put(doc, "log.level", first(r.get("level")))
    for k in ("type", "subtype", "logid", "level", "vd", "sessionid", "policyid", "service", "attackid",
              "severity", "crscore", "craction", "ref", "apprisk", "profile"):
        put(doc, f"fortinet.firewall.{k}", first(r.get(k)))
    put(doc, "fortinet.firewall.eventtype", first(r.get("vendor_eventtype")))
    return doc


# ── Vulnerability scan: Nessus ──────────────────────────────────────────────────────────────────

def map_nessus(r: dict) -> dict:
    doc: dict = {"event": {"kind": "state", "category": ["vulnerability"], "type": ["info"]}}
    put(doc, "host.ip", as_ip(r.get("dest_ip")) or as_ip(r.get("dest")))
    set_host(doc, first(r.get("dest_dns")) or first(r.get("dest_nt_host")) or first(r.get("dest")))
    put(doc, "vulnerability.id", first(r.get("cve")) or first(r.get("plugin_id")))
    put(doc, "vulnerability.severity", first(r.get("severity")))
    put(doc, "vulnerability.description", first(r.get("signature")) or first(r.get("description")))
    put(doc, "vulnerability.scanner.vendor", "Tenable")
    put(doc, "vulnerability.category", uniq(r.get("category")) or None)
    put(doc, "rule.id", first(r.get("signature_id")) or first(r.get("plugin_id")))
    return doc


# ── Anything else: Splunk CIM field names ───────────────────────────────────────────────────────

def map_generic(r: dict) -> dict:
    doc: dict = {"event": {"kind": "event", "category": ["network"], "type": ["info"]}}
    set_endpoints(doc, r)
    put(doc, "user.name", first(r.get("user")))
    put(doc, "message", r.get("_raw") if isinstance(r.get("_raw"), str) and len(r["_raw"]) < 4096 else None)
    return doc


# ── Entry point ─────────────────────────────────────────────────────────────────────────────────

def unwrap(line: bytes | str) -> dict:
    """One file line -> the event's fields (the 'result' of a Splunk export, or the object itself)."""
    obj = json.loads(line)
    return obj.get("result", obj) if isinstance(obj, dict) else {}


def _expand(flat: dict) -> dict:
    out: dict = {}
    for k, v in flat.items():
        put(out, k, v) if "." in k else out.__setitem__(k, v)
    return out


def is_ecs(r: dict) -> bool:
    """Whether an event is already an ECS document (an imported ECS file), not a Splunk event to map."""
    return "_raw" not in r and "_time" not in r


def map_event(key: str, r: dict, keep_original: bool = True) -> dict:
    """ECS document for one event of dataset `key` (without @timestamp / data_stream)."""
    if is_ecs(r):
        return _ecs_event(key, r, keep_original)
    if key == "sysmon":
        doc = map_sysmon(r)
    elif key in ("security", "system", "application"):
        doc = map_wineventlog(r, {"security": "Security", "system": "System", "application": "Application"}[key])
    elif key == "winregistry":
        doc = map_winregistry(r)
    elif key == "suricata":
        doc = map_suricata(r)
    elif key == "iis":
        doc = map_iis(r)
    elif key.startswith("fgt_"):
        doc = map_fortigate(r)
    elif key.startswith("stream-"):
        doc = map_stream(r, key.split("-", 1)[1])
    elif key == "nessus":
        doc = map_nessus(r)
    else:
        doc = map_generic(r)

    raw = r.get("_raw")
    if keep_original:
        put(doc, "event.original", raw if isinstance(raw, str) else None)
        splunk = {k: v for k, v in r.items() if k not in SPLUNK_INTERNAL and not k.startswith("tag::")}
        put(doc, "botes.splunk", splunk or None)
    put(doc, "botes.sourcetype", first(r.get("sourcetype")))
    put(doc, "botes.dataset", key)

    related_ip = uniq([get(doc, p) for p in ("source.ip", "destination.ip", "host.ip")])
    put(doc, "related.ip", [ip for ip in related_ip if isinstance(ip, str)] or None)
    related_user = uniq([get(doc, "user.name"), get(doc, "user.target.name")])
    put(doc, "related.user", related_user or None)
    related_hosts = uniq([get(doc, "host.name"), get(doc, "source.domain"), get(doc, "destination.domain")])
    put(doc, "related.hosts", related_hosts or None)
    doc["ecs"] = {"version": ECS_VERSION}
    doc["tags"] = uniq(["botes", first(r.get("index"))])      # and the Splunk index: botsv1 for BOTS v1
    return doc


def _ecs_event(key: str, r: dict, keep_original: bool) -> dict:
    """An ECS document as it came, with what BOTES adds: botes.dataset, the related.* fields it can tell
    (added to any the document has), and the tag botes. keep_original False (a slim replay) leaves out
    event.original."""
    doc = _expand({k: v for k, v in r.items() if k != "@timestamp"})
    if not keep_original and isinstance(doc.get("event"), dict):
        doc["event"].pop("original", None)
    put(doc, "botes.dataset", key)
    for field, paths in (("ip", ("source.ip", "destination.ip", "host.ip")), ("user", ("user.name", "user.target.name")),
                         ("hosts", ("host.name", "source.domain", "destination.domain"))):
        found = uniq([*uniq(get(doc, f"related.{field}")), *[v for p in paths for v in uniq(get(doc, p))]])
        if field == "ip":
            found = [v for v in found if isinstance(v, str)]
        put(doc, f"related.{field}", found or None)
    doc.setdefault("ecs", {"version": ECS_VERSION})
    doc["tags"] = uniq([*uniq(doc.get("tags")), "botes"])
    return doc


# ── Index templates ─────────────────────────────────────────────────────────────────────────────

def _kw(caseless: bool = True, text: bool = False) -> dict:
    m: dict = {"type": "keyword", "ignore_above": 1024}
    fields = {}
    if caseless:
        fields["caseless"] = {"type": "keyword", "normalizer": "sim_lowercase", "ignore_above": 1024}
    if text:
        fields["text"] = {"type": "match_only_text"}
    if fields:
        m["fields"] = fields
    return m


def _cmd() -> dict:
    return {"type": "wildcard", "fields": {
        "text": {"type": "match_only_text"},
        "caseless": {"type": "keyword", "normalizer": "sim_lowercase", "ignore_above": 1024}}}


def _proc() -> dict:
    return {"properties": {"executable": _kw(text=True), "name": _kw(text=True), "command_line": _cmd(),
                           "args": {"type": "keyword", "ignore_above": 1024}, "args_count": {"type": "long"},
                           "pid": {"type": "long"}, "entity_id": {"type": "keyword", "ignore_above": 1024},
                           "working_directory": _kw(text=True)}}


def component_template() -> dict:
    """COMPONENT: explicit mappings for the fields rules query, on top of ecs@mappings."""
    proc = _proc()
    proc["properties"]["parent"] = _proc()
    file_props = {"properties": {"path": _kw(text=True), "name": _kw(), "directory": _kw(),
                                 "extension": {"type": "keyword", "ignore_above": 1024}}}
    return {
        "template": {
            "settings": {"index": {
                "analysis": {"normalizer": {"sim_lowercase": {"type": "custom", "filter": ["lowercase"]}}},
                "mapping": {"total_fields": {"limit": 10000}, "ignore_malformed": True},
            }},
            "mappings": {
                "dynamic_templates": [
                    {"sim_event_data": {"path_match": "winlog.event_data.*", "match_mapping_type": "string",
                                          "mapping": {"type": "keyword", "ignore_above": 1024}}},
                    {"sim_suricata_strings": {"path_match": "suricata.eve.*", "match_mapping_type": "string",
                                                "mapping": {"type": "keyword", "ignore_above": 1024}}},
                ],
                "properties": {
                    "@timestamp": {"type": "date"},
                    "original_timestamp": {"type": "date"},
                    "message": {"type": "match_only_text"},
                    "botes": {"properties": {
                        "dataset": {"type": "keyword"}, "sourcetype": {"type": "keyword"}, "scenario": {"type": "keyword"},
                        "replay": {"properties": {"run_id": {"type": "keyword"}, "loop": {"type": "long"}}},
                        "splunk": {"type": "flattened", "ignore_above": 4096, "depth_limit": 5},
                    }},
                    "event": {"properties": {
                        "ingested": {"type": "date"}, "code": {"type": "keyword"},
                        "original": {"type": "keyword", "index": False, "doc_values": False},
                        "severity": {"type": "long"}, "duration": {"type": "long"},
                    }},
                    "process": proc,
                    "file": file_props,
                    "dll": file_props,
                    "registry": {"properties": {"path": _kw(), "key": _kw(), "value": _kw(), "hive": _kw(),
                                                "data": {"properties": {"strings": {"type": "wildcard"},
                                                                        "type": {"type": "keyword"}}}}},
                    "user": {"properties": {"name": _kw(text=True), "domain": _kw(), "id": _kw(caseless=False),
                                            "target": {"properties": {"name": _kw(text=True), "domain": _kw(),
                                                                      "id": _kw(caseless=False)}}}},
                    "host": {"properties": {"id": {"type": "keyword"}, "name": _kw(), "hostname": _kw(),
                                            "domain": _kw(), "ip": {"type": "ip"}}},
                    "winlog": {"properties": {
                        "event_id": {"type": "keyword"}, "record_id": {"type": "keyword"},
                        "channel": {"type": "keyword"}, "provider_name": {"type": "keyword"},
                        "computer_name": {"type": "keyword"}, "task": {"type": "keyword"},
                        "opcode": {"type": "keyword"}, "keywords": {"type": "keyword"},
                        "logon": {"properties": {"type": {"type": "keyword"}, "id": {"type": "keyword"}}},
                        "event_data": {"type": "object"},
                    }},
                    "http": {"properties": {"request": {"properties": {
                        "body": {"properties": {"content": {"type": "wildcard",
                                                            "fields": {"text": {"type": "match_only_text"}}}}}}}}},
                    "url": {"properties": {"original": {"type": "wildcard",
                                                        "fields": {"text": {"type": "match_only_text"}}},
                                           "full": {"type": "wildcard"}, "path": {"type": "wildcard"},
                                           "query": {"type": "keyword", "ignore_above": 2048},
                                           "domain": {"type": "keyword"}}},
                    "dns": {"properties": {"question": {"properties": {"name": {"type": "keyword"}}},
                                           "resolved_ip": {"type": "ip"}}},
                    "source": {"properties": {"ip": {"type": "ip"}, "port": {"type": "long"}}},
                    "destination": {"properties": {"ip": {"type": "ip"}, "port": {"type": "long"}}},
                    "suricata": {"properties": {"eve": {"type": "object"}}},
                },
            },
        },
        "_meta": {"managed_by": "tide", "description": "TIDE simulations: ECS mappings for replayed events"},
    }


COMPONENT = "tide-sim@mappings"       # the component template component_template() is installed as


def index_template(pattern: str, data_stream: bool, priority: int = 250, retention: str | None = None) -> dict:
    """The simulations' index template. With a retention (such as "7d") its data streams delete what is
    older: a data stream lifecycle, which logs@settings' ILM policy (rollover only, never delete) would
    otherwise outrank."""
    composed = ["logs@mappings", "logs@settings", "ecs@mappings", COMPONENT] if data_stream \
        else ["ecs@mappings", COMPONENT]
    settings: dict = {"index": {"auto_expand_replicas": "0-1"}}
    body = {
        "index_patterns": [pattern],
        "priority": priority,
        "composed_of": composed,
        "template": {"settings": settings},
        "_meta": {"managed_by": "tide", "description": "TIDE simulations: replayed scenario events"},
    }
    if data_stream:
        body["data_stream"] = {}
        if retention:
            body["template"]["lifecycle"] = {"data_retention": retention}
            settings["index"]["lifecycle"] = {"prefer_ilm": False}
    return body
