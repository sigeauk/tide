"""ATT&CK's enterprise tactics: the one list TIDE's heatmaps, reports, baselines and rule forms use.

It matches the ATT&CK bundled in the image; test/test_attack_tactics.py checks that, so an ATT&CK
update that adds, renames or reorders a tactic fails there instead of drifting into "Other".
"""
import re
from typing import Dict, List, Optional

# (id, shortname, name), in ATT&CK's kill-chain order.
TACTICS = [
    ("TA0043", "reconnaissance", "Reconnaissance"),
    ("TA0042", "resource-development", "Resource Development"),
    ("TA0001", "initial-access", "Initial Access"),
    ("TA0002", "execution", "Execution"),
    ("TA0003", "persistence", "Persistence"),
    ("TA0004", "privilege-escalation", "Privilege Escalation"),
    ("TA0005", "stealth", "Stealth"),
    ("TA0112", "defense-impairment", "Defense Impairment"),
    ("TA0006", "credential-access", "Credential Access"),
    ("TA0007", "discovery", "Discovery"),
    ("TA0008", "lateral-movement", "Lateral Movement"),
    ("TA0009", "collection", "Collection"),
    ("TA0011", "command-and-control", "Command and Control"),
    ("TA0010", "exfiltration", "Exfiltration"),
    ("TA0040", "impact", "Impact"),
]

# Names from earlier ATT&CK versions that rules, Sigma tags, CTI and saved baselines still carry,
# with the tactic id they had. Defense Evasion (TA0005) was renamed Stealth when Defense Impairment
# was split out of it.
LEGACY = {"Defense Evasion": "TA0005"}

NAMES: List[str] = [name for _, _, name in TACTICS]
ID_BY_NAME: Dict[str, str] = {name: tid for tid, _, name in TACTICS} | LEGACY
NAME_BY_ID: Dict[str, str] = {tid: name for tid, _, name in TACTICS}

# Kill-chain order with each legacy name just before the tactic that replaced it, so an older
# "Defense Evasion" sorts and groups next to Stealth instead of after everything else.
ORDER: List[str] = []
for _name in NAMES:
    ORDER += [old for old, tid in LEGACY.items() if NAME_BY_ID[tid] == _name] + [_name]

# Short column labels where space is tight (the heatmap and report matrices).
SHORT = {"Resource Development": "Resource Dev"}


def _key(text: str) -> str:
    return re.sub(r"[\s_-]+", " ", (text or "").strip().lower())


_LOOKUP: Dict[str, str] = {}
for _tid, _short, _name in TACTICS:
    for _k in (_tid, _short, _name, SHORT.get(_name, _name)):
        _LOOKUP[_key(_k)] = _name
for _old in LEGACY:
    _LOOKUP[_key(_old)] = _old
_LOOKUP.update({"c2": "Command and Control", "command & control": "Command and Control",
                "privesc": "Privilege Escalation", "recon": "Reconnaissance", "exfil": "Exfiltration"})


def tactic_name(raw: Optional[str]) -> Optional[str]:
    """The tactic ``raw`` names, as its ATT&CK name, from an id (TA0005), shortname (stealth,
    defense_evasion), name in any case, or a common abbreviation. A legacy name stays as it is
    ("Defense Evasion"). None if it isn't one."""
    return _LOOKUP.get(_key(raw or ""))
