"""
Threat Report Generator for TIDE.

Generates PDF and Markdown reports for MITRE ATT&CK heatmap coverage.
Designed for fully airgapped environments — no external network calls.

PDF generation uses WeasyPrint (HTML-to-PDF via Pango/Cairo).
All CSS/fonts are inlined in the report template.

Strategy:
  1. build_report_data()  — compile every data point needed from DuckDB in one pass
  2. generate_markdown()  — produce a structured .md string (no extra deps)
  3. generate_pdf_bytes() — render the Jinja2 HTML template → WeasyPrint → bytes
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# ── Tactic ordering & slug-to-title map (mirrors heatmap.py) ───────────────

TACTIC_ORDER = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
    "Reconnaissance", "Resource Dev", "Other",
]

_SLUG_TO_TITLE: Dict[str, str] = {
    "initial-access":        "Initial Access",
    "execution":             "Execution",
    "persistence":           "Persistence",
    "privilege-escalation":  "Privilege Escalation",
    "defense-evasion":       "Defense Evasion",
    "credential-access":     "Credential Access",
    "discovery":             "Discovery",
    "lateral-movement":      "Lateral Movement",
    "collection":            "Collection",
    "command-and-control":   "Command and Control",
    "exfiltration":          "Exfiltration",
    "impact":                "Impact",
    "reconnaissance":        "Reconnaissance",
    "resource-development":  "Resource Dev",
}


def _tactic_display(raw: str) -> str:
    return _SLUG_TO_TITLE.get((raw or "").lower(), "Other")


def _technique_source(technique_id: str) -> str:
    """
    Infer MITRE matrix from technique ID.
    ICS techniques use the T0xxx namespace.
    Everything else defaults to Enterprise (Mobile overlaps Enterprise IDs
    and requires a separate lookup that isn't stored in the current schema).
    """
    tid = technique_id.upper().strip()
    # ICS uses T0001–T0999
    if len(tid) >= 3 and tid[0] == "T" and tid[1] == "0" and tid[2:3].isdigit():
        return "ICS"
    return "Enterprise"


# ── Core data builder ───────────────────────────────────────────────────────

def build_report_data(
    db,
    actors: List[str],
    show_defense: bool = False,
) -> Optional[Dict[str, Any]]:
    """
    Compile every data point needed to render a threat report.

    Parameters
    ----------
    db          : DatabaseService singleton
    actors      : list of selected actor names
    show_defense: whether to include Defense-in-Depth TTPs

    Returns None if no matching actors are found.
    """
    all_actors   = db.get_threat_actors()
    covered_ttps = db.get_all_covered_ttps()          # set of technique IDs
    ttp_rule_counts = db.get_ttp_rule_counts()         # {id: count}
    ttp_map      = db.get_technique_map()              # {id: tactic_slug}
    ttp_names    = db.get_technique_names()            # {id: name}

    selected_actors = [a for a in all_actors if a.name in actors]
    if not selected_actors:
        return None

    # ── Build per-TTP actor mapping ──────────────────────────────────────
    relevant_ttps: Set[str] = set()
    actor_ttp_map: Dict[str, List[str]] = {}

    for actor in selected_actors:
        for ttp in actor.ttps:
            tid = str(ttp).strip().upper()
            relevant_ttps.add(tid)
            actor_ttp_map.setdefault(tid, []).append(actor.name)

    display_ttps = relevant_ttps.copy()
    if show_defense:
        display_ttps.update(covered_ttps)

    # ── Batch-fetch rule names for all display TTPs ──────────────────────
    rule_names_by_ttp = _batch_rule_names(db, list(display_ttps))

    # ── Map TTPs where the actor's intel source is OpenCTI ──────────────
    opencti_ttps: Set[str] = set()
    for actor in selected_actors:
        src_lower = [s.lower() for s in (actor.source or [])]
        if "opencti" in src_lower:
            for ttp in actor.ttps:
                opencti_ttps.add(str(ttp).strip().upper())

    # ── Build tactic-organised matrix ────────────────────────────────────
    matrix: Dict[str, List[Dict[str, Any]]] = {t: [] for t in TACTIC_ORDER}

    for tid in display_ttps:
        is_relevant = tid in relevant_ttps
        is_covered  = tid in covered_ttps

        if is_relevant and not is_covered:
            status = "gap"
        elif is_relevant and is_covered:
            status = "covered"
        else:
            status = "defense"

        tech_name = ttp_names.get(tid) or ttp_names.get(tid.upper()) or "Unknown"
        raw_tactic = ttp_map.get(tid.upper()) or ttp_map.get(tid) or ""
        tactic = _tactic_display(raw_tactic)
        if tactic not in matrix:
            tactic = "Other"

        # Determine source label(s)
        sources = {_technique_source(tid)}
        if tid in opencti_ttps:
            sources.add("OpenCTI")

        matrix[tactic].append({
            "id":         tid,
            "name":       tech_name,
            "tactic":     tactic,
            "status":     status,
            "actors":     actor_ttp_map.get(tid, []),
            "rule_count": ttp_rule_counts.get(tid, 0),
            "rule_names": rule_names_by_ttp.get(tid, []),
            "source":     ", ".join(sorted(sources)),
        })

    # Sort each tactic column by technique ID
    for tactic in matrix:
        matrix[tactic].sort(key=lambda c: c["id"])

    active_tactics = [t for t in TACTIC_ORDER if matrix.get(t)]

    # ── Metrics ──────────────────────────────────────────────────────────
    gap_count      = sum(1 for t in relevant_ttps if t not in covered_ttps)
    covered_count  = len(relevant_ttps) - gap_count
    coverage_pct   = int(covered_count / len(relevant_ttps) * 100) if relevant_ttps else 0

    # Count unique Elastic rules across all mapped TTPs
    all_rule_names: Set[str] = set()
    for names in rule_names_by_ttp.values():
        all_rule_names.update(names)
    total_elastic_rules = len(all_rule_names)

    return {
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "selected_actors": [a.name for a in selected_actors],
        "actor_details": [
            {
                "name":      a.name,
                "aliases":   a.aliases or "",
                "origin":    a.origin or "Unknown",
                "sources":   a.source or [],
                "ttp_count": a.ttp_count,
            }
            for a in selected_actors
        ],
        "total_ttps":          len(relevant_ttps),
        "covered_count":       covered_count,
        "gap_count":           gap_count,
        "coverage_pct":        coverage_pct,
        "total_elastic_rules": total_elastic_rules,
        "tactics":             active_tactics,
        "matrix":              matrix,
        "show_defense":        show_defense,
    }


def _batch_rule_names(db, technique_ids: List[str]) -> Dict[str, List[str]]:
    """
    Fetch rule names for all supplied technique IDs in a single DuckDB query.
    Returns {technique_id: [rule_name, ...]}
    """
    if not technique_ids:
        return {}

    result: Dict[str, List[str]] = {}
    try:
        placeholders = ", ".join(["?" for _ in technique_ids])
        query = f"""
            SELECT UPPER(unnested_id) AS tid, name AS rule_name
            FROM (
                SELECT unnest(mitre_ids) AS unnested_id, name
                FROM detection_rules
                WHERE enabled = 1
            )
            WHERE UPPER(unnested_id) IN ({placeholders})
            ORDER BY tid, rule_name
        """
        with db.get_connection() as conn:
            rows = conn.execute(query, technique_ids).fetchall()

        for tid, rule_name in rows:
            if tid and rule_name:
                result.setdefault(tid, [])
                if rule_name not in result[tid]:
                    result[tid].append(rule_name)
    except Exception as exc:
        logger.error(f"Batch rule-name fetch failed: {exc}")

    return result


# ── Markdown generator ──────────────────────────────────────────────────────

def generate_markdown(data: Dict[str, Any]) -> str:
    """
    Produce a structured Markdown threat report from the compiled report data.
    """
    actors_str = ", ".join(data["selected_actors"])
    lines: List[str] = [
        "# TIDE — Threat Coverage Report",
        "",
        f"**Generated:** {data['generated_at']}",
        f"**Adversaries:** {actors_str}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Selected Actors | {len(data['selected_actors'])} |",
        f"| Total Adversary TTPs | {data['total_ttps']} |",
        f"| Detection Coverage | {data['coverage_pct']}% |",
        f"| Covered TTPs | {data['covered_count']} |",
        f"| Critical Gaps | {data['gap_count']} |",
        f"| Mapped Elastic Rules | {data['total_elastic_rules']} |",
        "",
    ]

    # ── Selected Adversaries ──────────────────────────────────────────────
    lines += ["## Selected Adversaries", ""]
    for actor in data["actor_details"]:
        src = ", ".join(actor["sources"]) if actor["sources"] else "MITRE"
        lines.append(
            f"- **{actor['name']}** — Origin: `{actor['origin']}` | "
            f"TTPs: {actor['ttp_count']} | Sources: {src}"
        )
        if actor["aliases"]:
            lines.append(f"  - *Aliases: {actor['aliases']}*")
    lines.append("")

    # ── Coverage matrix (text art legend) ────────────────────────────────
    lines += [
        "## MITRE ATT&CK Coverage Overview",
        "",
        "> Legend: 🔴 **GAP** – no detection rule | "
        "🟢 **COVERED** – detection exists | "
        "🔵 **DEFENSE** – defence in depth",
        "",
    ]

    for tactic in data["tactics"]:
        cells = data["matrix"].get(tactic, [])
        if not cells:
            continue
        gap_cells   = [c for c in cells if c["status"] == "gap"]
        cov_cells   = [c for c in cells if c["status"] == "covered"]
        def_cells   = [c for c in cells if c["status"] == "defense"]

        lines.append(f"**{tactic}** — "
                     f"🔴 {len(gap_cells)} gap | "
                     f"🟢 {len(cov_cells)} covered | "
                     f"🔵 {len(def_cells)} defense")
    lines.append("")

    # ── Detailed per-tactic tables ────────────────────────────────────────
    lines += ["## Detailed Coverage by Tactic", ""]

    for tactic in data["tactics"]:
        cells = data["matrix"].get(tactic, [])
        if not cells:
            continue

        lines.append(f"### {tactic}")
        lines.append("")
        lines.append("| ID | Technique | Status | Source | Elastic Rules |")
        lines.append("|----|-----------|--------|--------|---------------|")

        for cell in cells:
            icon = {"gap": "🔴 GAP", "covered": "🟢 COVERED", "defense": "🔵 DEFENSE"}.get(
                cell["status"], cell["status"].upper()
            )
            rules_str = "; ".join(cell["rule_names"]) if cell["rule_names"] else "—"
            rules_str = rules_str.replace("|", "\\|")  # escape MD table pipe
            lines.append(
                f"| `{cell['id']}` | {cell['name']} | {icon} | "
                f"{cell['source']} | {rules_str} |"
            )

        lines.append("")

    lines += [
        "---",
        "",
        "*Report generated by [TIDE](https://github.com/sigeauk/tide) — "
        "Threat Intelligence Detection Engineering*",
    ]
    return "\n".join(lines)


# ── PDF generator ───────────────────────────────────────────────────────────

def generate_pdf_bytes(data: Dict[str, Any], templates_dir: str) -> bytes:
    """
    Render the self-contained HTML report template and convert to PDF via
    WeasyPrint.  All CSS is inlined in the template — no network calls.

    Parameters
    ----------
    data          : dict from build_report_data()
    templates_dir : absolute path to app/templates (for Jinja2 loader)

    Returns raw PDF bytes.
    """
    try:
        from weasyprint import HTML  # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError(
            "WeasyPrint is not installed. Ensure 'weasyprint>=62.0' is in "
            "requirements.txt and the Dockerfile includes the required system "
            "libraries (libpango, libcairo, libgdk-pixbuf2.0, fonts-liberation)."
        ) from exc

    from jinja2 import Environment, FileSystemLoader  # noqa: PLC0415

    env = Environment(
        loader=FileSystemLoader(templates_dir),
        autoescape=True,
    )
    template = env.get_template("report/threat_report.html")
    html_str = template.render(**data)

    # WeasyPrint renders from string — base_url not needed as all resources
    # are inlined (CSS + fonts).  This is intentionally airgap-safe.
    pdf = HTML(string=html_str).write_pdf()
    return pdf
