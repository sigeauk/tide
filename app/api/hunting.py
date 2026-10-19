"""
API routes for the Hunting page: Elastic's hunting queries and SigmaHQ's threat-hunting rules, both
built into TIDE (app/services/hunting.py), listed together and read here, run against one of the
tenant's SIEMs and saved to its Kibana as Discover searches (app/services/hunt_runner.py). Nothing is
deployed as a rule.
"""

import logging

from html import escape

from fastapi import APIRouter, Form, Request, Query
from fastapi.responses import HTMLResponse

from app.api.deps import CurrentUser, DbDep, ActiveClient, RequireUser
from app.services import elastic_rules as er
from app.services import hunt_runner
from app.services import hunting

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/hunting", tags=["hunting"])

_NOT_FOUND = '<div class="empty-state empty-state--fill"><p>This hunt is not in the hunting queries built into TIDE.</p></div>'


def list_context(db, client_id: str, q: str = "", technique: str = "", platform: str = "", source: str = "",
                 selected: str = "", limit: int = 100, offset: int = 0) -> dict:
    """What ``partials/hunting_list.html`` needs; shared with the page route. From ``offset`` on,
    only the next rows (the list scrolled to its end)."""
    with db.get_shared_connection() as conn:
        hunts, matching, total = hunting.search(conn, q=q, technique=technique, platform=platform,
                                                source=source, limit=limit, offset=offset)
    shown = offset + len(hunts)
    return {"hunts": hunts, "matching": matching, "total_count": total, "selected_id": selected,
            "offset": offset, "next_offset": shown if shown < matching else 0,
            "source_labels": dict(hunting.SOURCES),
            "covered_ttps": db.get_all_covered_ttps(client_id=client_id),
            "ttp_rule_counts": db.get_ttp_rule_counts(client_id=client_id)}


@router.get("", response_class=HTMLResponse)
def search_hunts(
    request: Request,
    user: CurrentUser,
    db: DbDep,
    client_id: ActiveClient,
    q: str = Query(""),
    technique: str = Query(""),
    platform: str = Query(""),
    source: str = Query(""),
    selected: str = Query(""),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """The Hunting page's list, filtered; from ``offset`` on, the next rows as it is scrolled."""
    return request.app.state.templates.TemplateResponse(
        request, "partials/hunting_list.html",
        list_context(db, client_id, q, technique, platform, source, selected, limit, offset),
    )


@router.get("/{source}/{hunt_id}", response_class=HTMLResponse)
def hunt_detail(request: Request, source: str, hunt_id: str, user: CurrentUser, db: DbDep, client_id: ActiveClient,
                pipeline: str = Query(""), index: str = Query("")):
    """One hunt: an Elastic hunting query (its ES|QL queries and notes), or a SigmaHQ threat-hunting
    rule (rendered like the Sigma page's rules), converted to ES|QL with the page's Sigma pipeline
    (``""``: the usual one for its platform) and index pattern."""
    from app import sigma_helper
    from app.api.rules import _render_guide_markdown

    with db.get_shared_connection() as conn:
        if source == "elastic":
            hunt = er.get_hunt(conn, hunt_id) if hunting.indexes_ready(conn)[0] else None
        elif source == "sigma":
            hunt = hunting.get_sigma(conn, hunt_id)
        else:
            hunt = None
    if not hunt:
        return HTMLResponse(_NOT_FOUND, status_code=404)
    coverage = {"covered_ttps": db.get_all_covered_ttps(client_id=client_id),
                "ttp_rule_counts": db.get_ttp_rule_counts(client_id=client_id)}
    dests = hunt_runner.destinations_for(db, client_id)
    run = {"destinations": dests, "can_save": not user or user.can_write("page:hunting")}
    index = hunt_runner.clean_index(index or (dests[0]["index"] if dests else ""))
    templates = request.app.state.templates
    if source == "elastic":
        kinds = [hunt_runner.query_kind(q) for q in hunt["queries"] or []]
        return templates.TemplateResponse(request, "partials/elastic_hunt_detail.html", {
            "hunt": hunt, "source": er.source_text(hunt["file_path"]),
            "description_html": _render_guide_markdown(hunt["description"]),
            "notes_html": [_render_guide_markdown(n) for n in hunt["notes"] or []],
            "kinds": kinds, "run": run,
            **coverage,
        })
    view = sigma_helper.rule_view(hunt["rule"])
    pipeline = pipeline or hunt_runner.default_pipeline(hunt.get("platform") or (view.get("logsource") or {}).get("product", ""))
    ok, query = hunt_runner.sigma_esql(hunt["raw_yaml"], pipeline, index)
    return templates.TemplateResponse(request, "partials/sigma_rule_detail.html", {
        "v": view, "hunting": True, "can_convert": False, "source": hunt["raw_yaml"], "file_path": hunt["file_path"],
        "description_html": _render_guide_markdown(view["description"]) if view["description"] else "",
        "hunt_id": hunt_id, "query": query if ok else "", "query_error": "" if ok else query,
        "run": run,
        **coverage,
    })


@router.post("/{source}/{hunt_id}/run", response_class=HTMLResponse)
def run_hunt(
    request: Request,
    source: str,
    hunt_id: str,
    user: RequireUser,
    db: DbDep,
    client_id: ActiveClient,
    query_no: int = Query(0, ge=0),
    destination: str = Form(""),
    lookback: str = Form(""),
    pipeline: str = Form(""),
    index: str = Form(""),
):
    """Run one of a hunt's queries on one of the tenant's SIEMs and show the first rows: an Elastic
    hunting query as written, or a Sigma threat-hunting rule converted to ES|QL with ``pipeline``
    over ``index``. Only bundled queries run; the browser picks which, never the query text."""
    error = lambda text: HTMLResponse(f'<div class="alert alert-error">{escape(text)}</div>')   # noqa: E731
    siem, _space = hunt_runner.destination(db, client_id, destination)
    if not siem:
        return error("Choose one of this client's destinations to run it on.")
    hunt, query, kind, ran_query, problem = _hunt_query(db, source, hunt_id, query_no, pipeline, index)
    if problem:
        return error(problem)
    result = hunt_runner.run(siem, query, kind, lookback, index)
    logger.info("Hunting query %s/%s #%d run on SIEM %s by %s: %s", source, hunt_id, query_no, siem["id"],
                getattr(user, "username", ""), "ok" if result["ok"] else result["error"][:200])
    return request.app.state.templates.TemplateResponse(request, "partials/hunt_run_result.html", {
        "result": result, "siem_label": siem.get("label") or siem["id"], "ran_query": ran_query, "n": query_no,
        "when": dict(hunt_runner.LOOKBACKS).get(lookback if lookback in dict(hunt_runner.LOOKBACKS) else "", ""),
    })


@router.post("/{source}/{hunt_id}/save", response_class=HTMLResponse)
def save_hunt(
    request: Request,
    source: str,
    hunt_id: str,
    user: RequireUser,
    db: DbDep,
    client_id: ActiveClient,
    query_no: int = Query(0, ge=0),
    destination: str = Form(""),
    lookback: str = Form(""),
    pipeline: str = Form(""),
    index: str = Form(""),
):
    """Save to Kibana: one of a hunt's ES|QL queries (a Sigma rule converted to ES|QL as for Run) as a
    Discover saved search in the chosen destination's space, with the chosen time range. Saving the
    same query to the same space again replaces it. Needs edit access to the Hunting page."""
    def reply(text: str, tone: str, link: str = "") -> HTMLResponse:
        more = (f' <a href="{escape(link)}" target="_blank" rel="noopener noreferrer">Open it in Discover</a>'
                if link else "")
        return HTMLResponse(f'<p class="hunt-save-result__line hunt-save-result__line--{tone}">{escape(text)}{more}</p>')

    if user and not user.can_write("page:hunting"):
        return reply("Saving to Kibana needs edit access to the Hunting page.", "error")
    siem, space = hunt_runner.destination(db, client_id, destination)
    if not siem:
        return reply("Choose one of this client's destinations to save it to.", "error")
    hunt, query, kind, _ran, problem = _hunt_query(db, source, hunt_id, query_no, pipeline, index)
    if problem:
        return reply(problem, "error")
    if kind != "esql":
        return reply("Only ES|QL queries can be saved as Discover searches.", "error")
    count = len(hunt.get("queries") or []) if source == "elastic" else 1
    title = (hunt.get("name") or hunt_id) + (f" ({query_no + 1} of {count})" if count > 1 else "")
    description = (str(hunt.get("description") or (hunt.get("rule") or {}).get("description") or "")
                   + f"\n\nSaved from TIDE's Hunting page ({'Elastic' if source == 'elastic' else 'Sigma'} hunt {hunt_id}).")
    result = hunt_runner.save_search(siem, space, hunt_runner.saved_search_id(source, hunt_id, query_no),
                                     title, description, query, lookback)
    dest_name = next((d["label"] for d in hunt_runner.destinations_for(db, client_id) if d["value"] == destination), space)
    logger.info("Hunting query %s/%s #%d saved to %s/%s by %s: %s", source, hunt_id, query_no, siem["id"], space,
                getattr(user, "username", ""), "ok" if result["ok"] else result["error"][:200])
    if not result["ok"]:
        return reply(result["error"], "error")
    return reply(f'{"Saved again, replacing the earlier copy," if result["replaced"] else "Saved"} in {dest_name} as '
                 f'"{title}".', "ok", result["url"])


def _hunt_query(db, source: str, hunt_id: str, query_no: int, pipeline: str, index: str):
    """``(hunt, query, kind, converted, problem)`` for Run and Save: an Elastic hunt's query
    ``query_no`` as written, or a Sigma rule converted to ES|QL (``converted`` is then that query).
    ``problem`` says why there is none."""
    with db.get_shared_connection() as conn:
        if source == "elastic":
            hunt = er.get_hunt(conn, hunt_id) if hunting.indexes_ready(conn)[0] else None
        elif source == "sigma":
            hunt = hunting.get_sigma(conn, hunt_id)
        else:
            hunt = None
    if not hunt:
        return None, "", "", "", "This hunt is not in the hunting queries built into TIDE."
    if source == "elastic":
        queries = hunt["queries"] or []
        if query_no >= len(queries):
            return hunt, "", "", "", "This hunt has no such query."
        return hunt, queries[query_no], hunt_runner.query_kind(queries[query_no]), "", ""
    ok, query = hunt_runner.sigma_esql(hunt["raw_yaml"], pipeline or hunt_runner.default_pipeline(hunt.get("platform", "")), index)
    if not ok:
        return hunt, "", "", "", f"It does not convert to ES|QL with that pipeline: {query}"
    return hunt, query, "esql", query, ""
