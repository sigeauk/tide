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
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ── Classification options (edit here to add/remove levels) ────────────────

CLASSIFICATION_OPTIONS: List[str] = [
    "Official",
    "Confidential",
    "Secret",
    "Top Secret",
]

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


_SOURCE_DISPLAY: Dict[str, str] = {
    "enterprise": "Enterprise",
    "mitre:enterprise": "Enterprise",
    "mitre-enterprise": "Enterprise",
    "enterprise attack": "Enterprise",
    "mobile": "Mobile",
    "mitre:mobile": "Mobile",
    "ics": "ICS",
    "mitre:ics": "ICS",
    "opencti": "OpenCTI",
    "open-cti": "OpenCTI",
    "octi": "OpenCTI",
}


def _normalise_source(raw: str) -> str:
    """Return a human-friendly display name for an actor intel source."""
    return _SOURCE_DISPLAY.get(raw.lower().strip(), raw.title())


# ── Core data builder ───────────────────────────────────────────────────────

def build_report_data(
    db,
    actors: List[str],
    show_defense: bool = False,
    audience_level: str = "executive",
    classification: str = "Official",
) -> Optional[Dict[str, Any]]:
    """
    Compile every data point needed to render a threat report.

    Parameters
    ----------
    db             : DatabaseService singleton
    actors         : list of selected actor names
    show_defense   : whether to include Defense-in-Depth TTPs
    audience_level : 'executive' or 'technical'
    classification : classification marking string (from CLASSIFICATION_OPTIONS)

    Returns None if no matching actors are found.
    """
    # Normalise inputs
    audience_level = audience_level.lower().strip()
    if audience_level not in ("executive", "technical"):
        audience_level = "executive"
    if classification not in CLASSIFICATION_OPTIONS:
        classification = CLASSIFICATION_OPTIONS[0]

    all_actors      = db.get_threat_actors()
    covered_ttps    = db.get_all_covered_ttps()          # set of technique IDs
    ttp_rule_counts = db.get_ttp_rule_counts()           # {id: count}
    ttp_map         = db.get_technique_map()             # {id: tactic_slug}
    ttp_names       = db.get_technique_names()           # {id: name}

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

        tech_name  = ttp_names.get(tid) or ttp_names.get(tid.upper()) or "Unknown"
        raw_tactic = ttp_map.get(tid.upper()) or ttp_map.get(tid) or ""
        tactic     = _tactic_display(raw_tactic)
        if tactic not in matrix:
            tactic = "Other"

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
            "sigma_rules": [],  # populated below for technical audience
        })

    # Sort each tactic column by technique ID
    for tactic in matrix:
        matrix[tactic].sort(key=lambda c: c["id"])

    active_tactics = [t for t in TACTIC_ORDER if matrix.get(t)]

    # ── Metrics ──────────────────────────────────────────────────────────
    gap_count     = sum(1 for t in relevant_ttps if t not in covered_ttps)
    covered_count = len(relevant_ttps) - gap_count
    coverage_pct  = int(covered_count / len(relevant_ttps) * 100) if relevant_ttps else 0

    all_rule_names: Set[str] = set()
    for names in rule_names_by_ttp.values():
        all_rule_names.update(names)
    total_elastic_rules = len(all_rule_names)

    # ── Top Adversary Overlap table (GAP techniques shared by 3+ actors) ─
    overlap_table = _build_overlap_table(
        actor_ttp_map, covered_ttps, ttp_names, ttp_map, min_actors=3
    )

    # ── Sigma opportunity lookup (both audiences — count for quick-win tile) ──
    gap_tids = [tid for tid in relevant_ttps if tid not in covered_ttps]
    sigma_by_ttp = _lookup_sigma_opportunities(gap_tids)

    if audience_level == "technical":
        # Attach sigma_rules to each matrix cell (full engineer breakdown)
        for tactic in matrix:
            for cell in matrix[tactic]:
                if cell["status"] == "gap":
                    cell["sigma_rules"] = sigma_by_ttp.get(cell["id"], [])

    # Total distinct sigma opportunities across all gap techniques
    sigma_opportunity_count = sum(len(v) for v in sigma_by_ttp.values())

    # ── Tactic coverage scores (CISO high-level overview) ─────────────────
    tactic_coverage_scores: List[Dict[str, Any]] = []
    for tac in active_tactics:
        tac_cells    = matrix[tac]
        tac_relevant = [c for c in tac_cells if c["status"] in ("gap", "covered")]
        tac_covered  = [c for c in tac_cells if c["status"] == "covered"]
        tac_gap      = len(tac_relevant) - len(tac_covered)
        tactic_coverage_scores.append({
            "tactic":  tac,
            "covered": len(tac_covered),
            "total":   len(tac_relevant),
            "gap":     tac_gap,
        })

    return {
        "generated_at":              datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "selected_actors":           [a.name for a in selected_actors],
        "actor_details": [
            {
                "name":        a.name,
                "description": a.description or "",
                "aliases":     a.aliases or "",
                "origin":      a.origin or "Unknown",
                "sources":     [_normalise_source(s) for s in (a.source or [])],
                "ttp_count":   a.ttp_count,
            }
            for a in selected_actors
        ],
        "total_ttps":                len(relevant_ttps),
        "covered_count":             covered_count,
        "gap_count":                 gap_count,
        "coverage_pct":              coverage_pct,
        "total_elastic_rules":       total_elastic_rules,
        "sigma_opportunity_count":   sigma_opportunity_count,
        "tactic_coverage_scores":    tactic_coverage_scores,
        "tactics":                   active_tactics,
        "matrix":                    matrix,
        "show_defense":              show_defense,
        "level":                     audience_level,
        "classification":            classification,
        "overlap_table":             overlap_table,
    }


# ── Helper: Top Adversary Overlap ────────────────────────────────────────────

def _build_overlap_table(
    actor_ttp_map: Dict[str, List[str]],
    covered_ttps: Set[str],
    ttp_names: Dict[str, str],
    ttp_map: Dict[str, str],
    min_actors: int = 3,
) -> List[Dict[str, Any]]:
    """
    Return GAP techniques shared by at least `min_actors` selected actors,
    sorted descending by actor count.  These are "High ROI Priority" gaps:
    a single detection would address coverage for multiple adversaries.
    """
    rows = []
    for tid, actor_list in actor_ttp_map.items():
        if tid in covered_ttps:
            continue  # already covered — not a gap
        if len(actor_list) < min_actors:
            continue

        name      = ttp_names.get(tid) or ttp_names.get(tid.upper()) or "Unknown"
        raw_tac   = ttp_map.get(tid.upper()) or ttp_map.get(tid) or ""
        tactic    = _tactic_display(raw_tac)

        rows.append({
            "id":          tid,
            "name":        name,
            "tactic":      tactic,
            "actors":      sorted(actor_list),
            "actor_count": len(actor_list),
        })

    rows.sort(key=lambda r: r["actor_count"], reverse=True)
    return rows


# ── Helper: Sigma Opportunity lookup ─────────────────────────────────────────

def _lookup_sigma_opportunities(gap_tids: List[str]) -> Dict[str, List[Dict[str, str]]]:
    """
    For each GAP technique ID look up matching Sigma rules in the local
    SigmaHQ repository (fully airgapped — no network calls).

    Returns {technique_id: [{"title": ..., "id": ..., "filename": ...}, ...]}
    """
    if not gap_tids:
        return {}

    result: Dict[str, List[Dict[str, str]]] = {}

    try:
        from app.sigma_helper import search_rules  # noqa: PLC0415

        for tid in gap_tids:
            matches = search_rules(technique_filter=tid, limit=5)
            rules_for_tid: List[Dict[str, str]] = []
            for rule in matches:
                file_path = rule.get("_file_path", "")
                filename  = file_path.split("/")[-1].split("\\")[-1] if file_path else ""
                rules_for_tid.append({
                    "title":    rule.get("title", "Unknown"),
                    "id":       str(rule.get("id", "")),
                    "filename": filename,
                })
            if rules_for_tid:
                result[tid] = rules_for_tid
    except Exception as exc:
        logger.warning(f"Sigma opportunity lookup failed: {exc}")

    return result


# ── Batch rule name fetch ─────────────────────────────────────────────────────

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


# ── Markdown generator ────────────────────────────────────────────────────────

def generate_markdown(data: Dict[str, Any]) -> str:
    """
    Produce a structured Markdown threat report from the compiled report data.
    Audience-aware: technical reports include per-tactic detail tables and
    Sigma opportunity listings; executive reports omit them.
    """
    level      = data.get("level", "executive")
    classif    = data.get("classification", "Official")
    actors_str = ", ".join(data["selected_actors"])

    lines: List[str] = [
        f"<!-- {classif} -->",
        "",
        "# TIDE — Threat Coverage Report",
        "",
        f"**Classification:** {classif}",
        f"**Generated:** {data['generated_at']}",
        f"**Adversaries:** {actors_str}",
        f"**Audience:** {'Technical / Engineer' if level == 'technical' else 'Executive / CISO'}",
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
        f"| Sigma Quick Wins Available | {data.get('sigma_opportunity_count', 0)} |",
        "",
    ]

    # ── Selected Adversaries ──────────────────────────────────────────────
    lines += ["## Selected Adversaries", ""]
    lines += ["| Actor | Description | TTPs | Intel Sources | Aliases |"]
    lines += ["|-------|-------------|-----:|---------------|---------|"]
    for actor in data["actor_details"]:
        src = ", ".join(actor["sources"]) if actor["sources"] else "MITRE"
        desc = (actor.get("description") or "").replace("\n", " ").replace("|", "\\|")
        aliases = (actor["aliases"] or "—").replace("|", "\\|")
        lines.append(
            f"| **{actor['name']}** | {desc} | {actor['ttp_count']} | {src} | {aliases} |"
        )
    lines.append("")
    # ── Coverage matrix overview ──────────────────────────────────────────
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
        gap_cells = [c for c in cells if c["status"] == "gap"]
        cov_cells = [c for c in cells if c["status"] == "covered"]
        def_cells = [c for c in cells if c["status"] == "defense"]
        lines.append(
            f"**{tactic}** — "
            f"🔴 {len(gap_cells)} gap | "
            f"🟢 {len(cov_cells)} covered | "
            f"🔵 {len(def_cells)} defense"
        )
    lines.append("")

    # ── Top Adversary Overlap (both audiences) ────────────────────────────
    overlap = data.get("overlap_table", [])
    if overlap:
        lines += [
            "## High ROI Priority — Top Adversary Overlap",
            "",
            "> GAP techniques shared by 3 or more selected actors.",
            "> A single detection rule would address coverage for multiple adversaries.",
            "",
            "| ID | Technique | Tactic | Shared By | Actor Count |",
            "|----|-----------|--------|-----------|-------------|",
        ]
        for row in overlap:
            actors_str_o = ", ".join(row["actors"])
            actors_str_o = actors_str_o.replace("|", "\\|")
            lines.append(
                f"| `{row['id']}` | {row['name']} | {row['tactic']} | "
                f"{actors_str_o} | **{row['actor_count']}** |"
            )
        lines.append("")

    # ── Detailed per-tactic tables (technical only) ───────────────────────
    if level == "technical":
        lines += ["## Detailed Coverage by Tactic", ""]

        for tactic in data["tactics"]:
            cells = data["matrix"].get(tactic, [])
            if not cells:
                continue

            lines.append(f"### {tactic}")
            lines.append("")

            if any(c.get("sigma_rules") for c in cells):
                lines.append("| ID | Technique | Status | Source | Elastic Rules | Sigma Opportunities |")
                lines.append("|----|-----------|--------|--------|---------------|---------------------|")
                for cell in cells:
                    icon = {
                        "gap":     "🔴 GAP",
                        "covered": "🟢 COVERED",
                        "defense": "🔵 DEFENSE",
                    }.get(cell["status"], cell["status"].upper())
                    rules_str = "; ".join(cell["rule_names"]) if cell["rule_names"] else "—"
                    rules_str = rules_str.replace("|", "\\|")
                    sigma_str = "; ".join(
                        f"{r['title']}" for r in cell.get("sigma_rules", [])
                    ) if cell.get("sigma_rules") else "—"
                    sigma_str = sigma_str.replace("|", "\\|")
                    lines.append(
                        f"| `{cell['id']}` | {cell['name']} | {icon} | "
                        f"{cell['source']} | {rules_str} | {sigma_str} |"
                    )
            else:
                lines.append("| ID | Technique | Status | Source | Elastic Rules |")
                lines.append("|----|-----------|--------|--------|---------------|")
                for cell in cells:
                    icon = {
                        "gap":     "🔴 GAP",
                        "covered": "🟢 COVERED",
                        "defense": "🔵 DEFENSE",
                    }.get(cell["status"], cell["status"].upper())
                    rules_str = "; ".join(cell["rule_names"]) if cell["rule_names"] else "—"
                    rules_str = rules_str.replace("|", "\\|")
                    lines.append(
                        f"| `{cell['id']}` | {cell['name']} | {icon} | "
                        f"{cell['source']} | {rules_str} |"
                    )

            lines.append("")

    lines += [
        "---",
        "",
        f"*{classif} — Report generated by TIDE — "
        "Threat Intelligence Detection Engineering*",
    ]
    return "\n".join(lines)


# ── PDF generator ─────────────────────────────────────────────────────────────

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
