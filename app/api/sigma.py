"""
API routes for Sigma Converter.
Provides endpoints for rule browsing, conversion, validation, and SIEM deployment.
"""

import json
import os
from html import escape
from urllib.parse import quote

import yaml
from fastapi import APIRouter, Request, Query, Form, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from typing import Optional

from app.api.deps import CurrentUser, SettingsDep, DbDep, ActiveClient
from app import sigma_helper as sigma

import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/sigma", tags=["sigma"])

# A backend's query language, for colouring the converted query (highlight_query).
_QUERY_LANGUAGE = {"elasticsearch": "lucene", "eql": "eql", "esql": "esql", "splunk": "lucene",
                   "microsoft365defender": "kuery"}


def rules_list_context(query: str = "", technique: str = "", category: str = "", level: str = "",
                       status: str = "", limit: int = 100, offset: int = 0) -> dict:
    """The rule browser's rows (``partials/sigma_rules_list.html``), ``limit`` of them from
    ``offset`` on, and how many match; shared with the page route."""
    matches = sigma.search_rules(query=query, technique_filter=technique, category_filter=category,
                                 level_filter=level, status_filter=status, limit=0)
    rows = matches[offset:offset + limit]
    shown = offset + len(rows)
    return {"rules": rows, "matching": len(matches), "total_count": len(sigma.load_all_rules()),
            "offset": offset, "next_offset": shown if shown < len(matches) else 0}


@router.get("/rules", response_class=HTMLResponse)
def search_rules(
    request: Request,
    user: CurrentUser,
    db: DbDep,
    client_id: ActiveClient,
    query: str = Query("", alias="q"),
    technique: str = Query(""),
    category: str = Query(""),
    level: str = Query(""),
    status: str = Query(""),
    selected: str = Query(""),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """The rule browser's list, filtered; from ``offset`` on, the next rows as it is scrolled."""
    return request.app.state.templates.TemplateResponse(
        request,
        "partials/sigma_rules_list.html",
        {
            **rules_list_context(query, technique, category, level, status, limit, offset),
            "covered_ttps": db.get_all_covered_ttps(client_id=client_id),
            "ttp_rule_counts": db.get_ttp_rule_counts(client_id=client_id),
            "selected_rule_id": selected,
        }
    )


@router.get("/rule/{rule_id}", response_class=HTMLResponse)
def get_rule_yaml(
    request: Request,
    user: CurrentUser,
    rule_id: str,
):
    """
    Get a specific rule's YAML content.
    """
    rule = sigma.get_rule_by_id(rule_id)
    if rule:
        yaml_content = rule.get('_raw_yaml', '')
        return HTMLResponse(content=yaml_content, media_type="text/plain")
    return HTMLResponse(content="# Rule not found", status_code=404)


def _rule_detail(request: Request, db, client_id: str, yaml_content: str, backend: str, pipeline: str,
                 index_pattern: str, pipeline_file: str, template_file: str, sigma_id: str = "",
                 file_path: str = "") -> HTMLResponse:
    """The Sigma page's detail pane (partials/sigma_rule_detail.html) for one rule's YAML: laid out for
    reading, its query converted with the page's settings, and its Source. ``sigma_id`` names a
    SigmaHQ rule; a rule of your own has none and carries its YAML in the pane, for Convert."""
    from app.api.rules import _render_guide_markdown
    from app.services import rule_origins

    def empty(text: str) -> HTMLResponse:
        return HTMLResponse(f'<div class="empty-state empty-state--fill"><p>{text}</p></div>')

    if not yaml_content.strip():
        return empty("Select a rule to see what it detects.")
    try:
        rule = next(iter(yaml.safe_load_all(yaml_content)), None)
    except yaml.YAMLError as exc:
        return empty(f"The YAML could not be read: {escape(str(exc))[:300]}")
    if not isinstance(rule, dict):
        return empty("The YAML is not a Sigma rule.")
    view = sigma.rule_view(rule)
    ok, converted = sigma.convert_sigma_rule(
        yaml_content=yaml_content, backend=backend, pipeline=pipeline, output_format="default",
        index_pattern=index_pattern, pipeline_file=pipeline_file, template_file=template_file,
    )
    return request.app.state.templates.TemplateResponse(
        request, "partials/sigma_rule_detail.html",
        {
            "v": view, "can_convert": True, "hunting": False, "source": yaml_content, "file_path": file_path,
            "sigma_id": sigma_id, "own_yaml": "" if sigma_id else yaml_content,
            "deployed": rule_origins.deployed_for_client(db, client_id, "sigma", sigma_id) if sigma_id else [],
            "query": converted if ok else "", "query_error": "" if ok else converted,
            "query_language": _QUERY_LANGUAGE.get(backend, "lucene"),
            "query_target": sigma.get_available_backends().get(backend, backend),
            "description_html": _render_guide_markdown(view["description"]) if view["description"] else "",
            "covered_ttps": db.get_all_covered_ttps(client_id=client_id),
            "ttp_rule_counts": db.get_ttp_rule_counts(client_id=client_id),
        },
    )


@router.get("/rules/{rule_id}/view", response_class=HTMLResponse)
def view_rule(
    request: Request,
    rule_id: str,
    user: CurrentUser,
    db: DbDep,
    client_id: ActiveClient,
    backend: str = Query("elasticsearch"),
    pipeline: str = Query("none"),
    index_pattern: str = Query(""),
    pipeline_file: str = Query(""),
    template_file: str = Query(""),
):
    """One SigmaHQ rule in the Sigma page's detail pane, converted with the page's settings."""
    rule = sigma.get_rule_by_id(rule_id)
    if not rule:
        return HTMLResponse('<div class="empty-state empty-state--fill"><p>This rule is not in the Sigma rules built into TIDE.</p></div>',
                            status_code=404)
    path = str(rule.get("_file_path") or "")
    rel = path[path.find("/rules") + 1:] if "/rules" in path else os.path.basename(path)
    return _rule_detail(request, db, client_id, str(rule.get("_raw_yaml") or ""), backend, pipeline,
                        index_pattern, pipeline_file, template_file, sigma_id=rule_id, file_path=rel)


@router.post("/render", response_class=HTMLResponse)
def render_rule(
    request: Request,
    user: CurrentUser,
    db: DbDep,
    client_id: ActiveClient,
    yaml_content: str = Form(""),
    backend: str = Form("elasticsearch"),
    pipeline: str = Form("none"),
    index_pattern: str = Form(""),
    pipeline_file: str = Form(""),
    template_file: str = Form(""),
):
    """A Sigma rule of your own (Add your own Sigma rule), shown like SigmaHQ's in the detail pane."""
    return _rule_detail(request, db, client_id, yaml_content, backend, pipeline, index_pattern,
                        pipeline_file, template_file)


def rule_form_prefill(sigma_rule: dict, query: str, backend: str, index_pattern: str, username: str) -> dict:
    """The Create Rule form's pre-fill for a converted Sigma rule: its title, description,
    query, level, authors (the rule's, then the converting user), tags and ATT&CK ids. Created
    disabled. Shared by the Sigma library and a technique window's Convert."""
    raw_author = sigma_rule.get("author") or ""
    parts = raw_author if isinstance(raw_author, list) else str(raw_author).split(",")
    authors: list[str] = []
    for author in [str(a).strip() for a in parts] + [username.strip()]:
        if author and author.lower() not in {a.lower() for a in authors}:
            authors.append(author)
    return {
        "sigma_id": str(sigma_rule.get("id") or "").strip(),
        "name": str(sigma_rule.get("title") or "").strip(),
        "description": str(sigma_rule.get("description") or "").strip(),
        "query": query,
        "language": "kuery" if backend == "elasticsearch" else backend,
        "severity": str(sigma_rule.get("level") or "medium").strip().lower(),
        "author": ", ".join(authors),
        "tags": sigma_rule.get("tags") or [],
        "mitre_ids": sigma.extract_mitre_techniques(sigma_rule),
        "note": str(sigma_rule.get("description") or "").strip(),
        "risk_score": sigma_rule.get("risk_score"),
        "index": [part.strip() for part in (index_pattern or "").split(",") if part.strip()],
        "timestamp_override": "event.ingested",
        "highlighted_fields": [],
        "enabled": False,
        "type": "query",
        "from": "now-6m",
        "interval": "5m",
    }


@router.post("/convert", response_class=HTMLResponse)
def convert_rule(
    request: Request,
    user: CurrentUser,
    yaml_content: str = Form(""),
    sigma_id: str = Form(""),
    backend: str = Form("elasticsearch"),
    pipeline: str = Form("none"),
    output_format: str = Form("default"),
    index_pattern: str = Form(""),
    custom_pipeline_yaml: str = Form(""),
    pipeline_file: str = Form(""),
    template_file: str = Form(""),
):
    """
    Convert a Sigma rule to target query language: its YAML (a rule of your own), or a SigmaHQ rule
    by ``sigma_id``. Returns HTML partial with the result.
    """
    if not yaml_content.strip() and sigma_id:
        found = sigma.get_rule_by_id(sigma_id)
        yaml_content = str((found or {}).get("_raw_yaml") or "")
    if not yaml_content.strip():
        return HTMLResponse(
            '<div class="alert alert-warning">Please enter a Sigma rule YAML</div>'
        )
    
    success, result = sigma.convert_sigma_rule(
        yaml_content=yaml_content,
        backend=backend,
        pipeline=pipeline,
        output_format=output_format,
        index_pattern=index_pattern,
        custom_pipeline_yaml=custom_pipeline_yaml,
        pipeline_file=pipeline_file,
        template_file=template_file,
    )
    
    # Also get raw query for SIEM deployment
    raw_query = ""
    if success:
        raw_success, raw_result = sigma.convert_sigma_rule(
            yaml_content=yaml_content,
            backend=backend,
            pipeline=pipeline,
            output_format='default',
            index_pattern=index_pattern,
            custom_pipeline_yaml=custom_pipeline_yaml,
            pipeline_file=pipeline_file,
            template_file=template_file,
        )
        raw_query = raw_result if raw_success else ""

    prefill_payload = ""
    try:
        prefill_payload = quote(json.dumps(rule_form_prefill(
            yaml.safe_load(yaml_content) or {}, raw_query or result, backend, index_pattern,
            str(getattr(user, "username", "") or ""),
        )))
    except Exception:
        prefill_payload = ""
    
    # Determine code language for highlighting
    if backend == 'eql':
        code_lang = 'javascript'
    elif backend == 'esql':
        code_lang = 'sql'
    elif backend == 'elasticsearch' and output_format in ['kibana_ndjson', 'dsl_lucene']:
        code_lang = 'json'
    else:
        code_lang = 'text'
    
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "partials/sigma_convert_result.html",
        {
            "success": success,
            "result": result,
            "raw_query": raw_query,
            "backend": backend,
            "code_lang": code_lang,
            "prefill_payload": prefill_payload,
        }
    )


@router.post("/validate", response_class=HTMLResponse)
def validate_rule(
    request: Request,
    user: CurrentUser,
    yaml_content: str = Form(...),
):
    """
    Validate a Sigma rule YAML.
    """
    if not yaml_content.strip():
        return HTMLResponse(
            '<div class="alert alert-warning">Please enter a Sigma rule YAML</div>'
        )
    
    success, result = sigma.validate_sigma_rule(yaml_content)
    
    if success:
        return HTMLResponse(f'<div class="alert alert-success">{result}</div>')
    else:
        return HTMLResponse(f'<div alert-danger">{result}</div>')


@router.post("/deploy", response_class=HTMLResponse)
def deploy_to_siem(
    request: Request,
    user: CurrentUser,
    db: DbDep,
    client_id: ActiveClient,
    yaml_content: str = Form(...),
    raw_query: str = Form(...),
    space: str = Form("staging"),
    enabled: bool = Form(False),
    index_pattern: str = Form(""),
    pipeline_file: str = Form(""),
    template_file: str = Form(""),
    siem_id: str = Form(""),
    resolution: str = Form(""),
):
    """
    Deploy a converted Sigma rule to Elastic SIEM.
    Validates that the target SIEM belongs to the active client and fails closed
    when SIEM identity is not supplied.
    """
    if not yaml_content.strip() or not raw_query.strip():
        return HTMLResponse(
            '<div class="alert alert-warning">Convert a rule first before deploying</div>'
        )

    # Validate the target space belongs to this client AND resolve the SIEM
    # connection details from siem_inventory / client_siem_map. The legacy
    # ELASTIC_URL/ELASTIC_API_KEY env fallback was removed in 4.0.10 — the
    # rule MUST be deployed to the SIEM the active tenant has assigned for
    # this space. Prefer explicit siem_id when supplied (4.0.13+).
    if not siem_id:
        return HTMLResponse(
            '<div class="alert alert-danger">Deployment blocked: SIEM identifier missing. Refresh the page and select a target SIEM.</div>',
            status_code=400,
        )

    # ``get_client_siems`` returns one row per ``client_siem_map`` entry, so
    # the same SIEM mapped to two spaces (e.g. SIEMY → ``staging`` AND
    # ``production``) appears twice. Match on the composite ``(siem_id,
    # space)`` so we pick the row whose space the operator actually selected
    # in the deploy dropdown — the previous siem_id-only match always
    # returned the first row and then 400'd on
    # ``SIEM/space mismatch detected`` for every space other than that row's.
    target_siem = None
    requested_space = (space or "default")
    client_siems = db.get_client_siems(client_id)
    for s in client_siems:
        if s.get("id") == siem_id and (s.get("space") or "default") == requested_space:
            target_siem = s
            break
    if not target_siem:
        # Fallback: SIEM is linked but not for this space. Surface that
        # specifically so the operator knows whether to fix the mapping or
        # the dropdown choice.
        siem_linked = any(s.get("id") == siem_id for s in client_siems)
        if siem_linked:
            return HTMLResponse(
                '<div class="alert alert-danger">Deployment blocked: '
                f"target SIEM is linked to your client but not for space "
                f"'{requested_space}'. Link the (SIEM, space) pair in "
                'Management or pick a different target.</div>',
                status_code=400,
            )
        return HTMLResponse(
            '<div class="alert alert-danger">Deployment blocked: target SIEM is not linked to your client.</div>',
            status_code=400,
        )
    target_space = requested_space
    if not target_siem.get("kibana_url") or not target_siem.get("api_token_enc"):
        return HTMLResponse(
            '<div class="alert alert-danger">Deployment blocked: '
            f"the SIEM assigned for space '{space}' has no kibana_url / api_token configured."
            '</div>'
        )

    # The space may already hold a rule with this Sigma rule's id (an earlier deploy, or another
    # rule). It is never overwritten unasked: identical (index patterns and enabled state aside)
    # needs nothing; otherwise the user chooses to update it or to deploy a separate copy under a
    # new rule id (``resolution``).
    rule_id_override = ""
    if resolution != "update":
        from app.elastic_helper import find_rule_in_space
        from app.services.rule_diff import conflict_differences
        payload, error = sigma.deploy_payload(yaml_content, enabled, index_pattern or None, pipeline_file,
                                              template_file, user.username)
        if payload is None:
            return HTMLResponse(f'<div class="alert alert-danger">{escape(error)}</div>')
        state, live = find_rule_in_space(payload.get("rule_id", ""), target_space, target_siem["kibana_url"],
                                         target_siem["api_token_enc"])
        if state == "unknown":
            return HTMLResponse('<div class="alert alert-danger">Could not check whether this space already has '
                                'the rule: its SIEM did not answer. Nothing was deployed.</div>')
        if state == "found" and resolution != "new_id":
            diffs = conflict_differences(live, payload)
            prebuilt = bool(live.get("immutable") or (live.get("rule_source") or {}).get("type") == "external")
            return request.app.state.templates.TemplateResponse(
                request, "partials/sigma_deploy_conflict.html",
                {"existing": live, "diffs": diffs, "prebuilt": prebuilt,
                 "destination": target_siem.get("name") or target_space},
            )
        if state == "found":
            import uuid
            rule_id_override = str(uuid.uuid4())

    success, message, new_rule_id = sigma.send_rule_to_siem(
        yaml_content=yaml_content,
        space=target_space,
        kibana_url=target_siem["kibana_url"],
        api_key=target_siem["api_token_enc"],
        enabled=enabled,
        index_pattern=index_pattern or None,
        pipeline_file=pipeline_file,
        template_file=template_file,
        username=user.username,
        rule_id_override=rule_id_override,
    )

    if success:
        # Pull just the deployed rule into this tenant's DB, rather than a full client sync —
        # nothing else in the space changed. See sync_single_rule / CHANGELOG 5.1.2.
        if new_rule_id:
            try:
                from app.api.rules import sync_single_rule
                sync_single_rule(db, client_id, new_rule_id, siem_id, target_space, user.id, user.username)
            except Exception:
                logger.exception("Post-deploy targeted sync failed for %s", new_rule_id)
            try:
                sigma_id = str((yaml.safe_load(yaml_content) or {}).get("id") or "")
            except yaml.YAMLError:
                sigma_id = ""
            from app.services import rule_origins
            rule_origins.record_for_client(
                db, client_id, (new_rule_id, siem_id, target_space), "sigma", sigma_id, "deployed", user.username,
                convert_options={"pipeline_file": pipeline_file, "template_file": template_file,
                                 "index_pattern": index_pattern})
        return HTMLResponse(f'<div class="alert alert-success">{message}</div>')
    else:
        return HTMLResponse(f'<div class="alert alert-danger">{message}</div>')


@router.get("/backends", response_class=HTMLResponse)
def get_backends(request: Request, user: CurrentUser):
    """Get available backends as HTML options."""
    backends = sigma.get_available_backends()
    html = ""
    for key, label in backends.items():
        html += f'<option value="{key}">{label}</option>'
    return HTMLResponse(html)


@router.get("/formats/{backend}", response_class=HTMLResponse)
def get_formats(request: Request, user: CurrentUser, backend: str):
    """Get available output formats for a backend as HTML options."""
    formats = sigma.get_output_formats(backend)
    html = ""
    for key, label in formats.items():
        html += f'<option value="{key}">{label}</option>'
    return HTMLResponse(html)


@router.get("/pipelines", response_class=HTMLResponse)
def get_pipelines(request: Request, user: CurrentUser):
    """Get available pipelines as HTML options."""
    pipelines = sigma.get_available_pipelines()
    html = ""
    for key, label in pipelines.items():
        html += f'<option value="{key}">{label}</option>'
    return HTMLResponse(html)


@router.get("/categories", response_class=HTMLResponse)
def get_categories(request: Request, user: CurrentUser):
    """Get rule categories as HTML options."""
    categories = sigma.get_rule_categories()
    html = '<option value="">All Categories</option>'
    for cat in categories:
        html += f'<option value="{cat}">{cat.title()}</option>'
    return HTMLResponse(html)


@router.get("/spaces", response_class=HTMLResponse)
def get_spaces(request: Request, user: CurrentUser, db: DbDep, client_id: ActiveClient):
    """Get deploy target SIEMs as HTML options, scoped to active client."""
    client_siems = db.get_client_siems(client_id)
    html = ""
    for s in client_siems:
        if s.get("space"):
            label = s.get("name") or s["label"]
            html += f'<option value="{s["space"]}" data-siem-id="{s["id"]}">{label}</option>'
    if not html:
        html = '<option value="" disabled selected>No SIEMs linked</option>'
    return HTMLResponse(html)


@router.get("/indices", response_class=HTMLResponse)
def get_indices(request: Request, user: CurrentUser):
    """Get Elasticsearch index patterns as HTML options."""
    indices = sigma.get_elastic_indices()
    html = '<option value="">No Index Filter</option>'
    for idx in indices:
        html += f'<option value="{idx}">{idx}</option>'
    return HTMLResponse(html)


@router.post("/upload-pipeline")
async def upload_pipeline(
    request: Request,
    user: CurrentUser,
    pipeline_file: UploadFile = File(...),
) -> JSONResponse:
    """
    Upload a custom Sigma ProcessingPipeline YAML file (mapping.yml).
    Validates the pipeline is parseable and returns the YAML content
    for the client to store and submit with future /convert calls.
    """
    content_bytes = await pipeline_file.read()
    yaml_content = content_bytes.decode("utf-8")

    # Validate before returning to client
    try:
        from sigma.processing.pipeline import ProcessingPipeline
        pl = ProcessingPipeline.from_yaml(yaml_content)
        item_count = len(pl.items) if hasattr(pl, "items") else "?"
        return JSONResponse({
            "status": "ok",
            "filename": pipeline_file.filename,
            "item_count": item_count,
            "content": yaml_content,
        })
    except Exception as e:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid Sigma pipeline YAML: {str(e)}"
        )


# â”€â”€â”€ Saved Pipeline CRUD â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.get("/saved-pipelines")
def list_saved_pipelines(request: Request, user: CurrentUser) -> JSONResponse:
    """Return list of saved pipeline file metadata."""
    return JSONResponse(
        sigma.list_saved_pipelines(),
        headers={"Cache-Control": "no-store, no-cache, must-revalidate"},
    )


@router.get("/saved-pipelines/{filename}")
def get_saved_pipeline(
    request: Request,
    user: CurrentUser,
    filename: str,
) -> JSONResponse:
    """Return the YAML content of a saved pipeline by filename."""
    content = sigma.read_pipeline_file(filename)
    if content is None:
        raise HTTPException(status_code=404, detail=f"Pipeline not found: {filename}")
    return JSONResponse(
        {"filename": filename, "content": content},
        headers={"Cache-Control": "no-store, no-cache, must-revalidate"},
    )


@router.post("/saved-pipelines")
async def save_pipeline(
    request: Request,
    user: CurrentUser,
    name: str = Form(...),
    content: str = Form(...),
) -> JSONResponse:
    """
    Validate and save a pipeline YAML to disk.
    `name` is the desired filename stem (without extension).
    """
    if not name.strip():
        raise HTTPException(status_code=422, detail="Pipeline name is required")
    # Sanitise: keep only safe filename characters
    import re as _re
    safe_name = _re.sub(r'[^\w\-]', '_', name.strip().lower()) + '.yml'
    ok, msg = sigma.write_pipeline_file(safe_name, content)
    if not ok:
        raise HTTPException(status_code=422, detail=msg)
    return JSONResponse({"status": "ok", "filename": msg})


@router.delete("/saved-pipelines/{filename}")
def delete_saved_pipeline(
    request: Request,
    user: CurrentUser,
    db: DbDep,
    filename: str,
) -> JSONResponse:
    """Delete a saved pipeline YAML by filename and clear tenant assignments."""
    ok, msg = sigma.delete_pipeline_file(filename)
    if not ok:
        raise HTTPException(status_code=404, detail=msg)
    try:
        db.delete_sigma_asset_assignments("pipeline", msg)
    except Exception as exc:
        logger.warning(f"could not clear pipeline assignments for {msg}: {exc}")
    return JSONResponse({"status": "ok", "deleted": msg})


# â”€â”€â”€ Saved Template CRUD â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.get("/saved-templates")
def list_saved_templates(request: Request, user: CurrentUser) -> JSONResponse:
    """Return list of saved template file metadata."""
    return JSONResponse(
        sigma.list_saved_templates(),
        headers={"Cache-Control": "no-store, no-cache, must-revalidate"},
    )


@router.get("/saved-templates/{filename}")
def get_saved_template(
    request: Request,
    user: CurrentUser,
    filename: str,
) -> JSONResponse:
    """Return the YAML content of a saved template by filename."""
    content = sigma.read_template_file(filename)
    if content is None:
        raise HTTPException(status_code=404, detail=f"Template not found: {filename}")
    return JSONResponse(
        {"filename": filename, "content": content},
        headers={"Cache-Control": "no-store, no-cache, must-revalidate"},
    )


@router.post("/saved-templates")
async def save_template(
    request: Request,
    user: CurrentUser,
    name: str = Form(...),
    content: str = Form(...),
) -> JSONResponse:
    """Validate and save a template YAML to disk."""
    if not name.strip():
        raise HTTPException(status_code=422, detail="Template name is required")
    import re as _re
    safe_name = _re.sub(r'[^\w\-]', '_', name.strip().lower()) + '.yml'
    ok, msg = sigma.write_template_file(safe_name, content)
    if not ok:
        raise HTTPException(status_code=422, detail=msg)
    return JSONResponse({"status": "ok", "filename": msg})


@router.delete("/saved-templates/{filename}")
def delete_saved_template(
    request: Request,
    user: CurrentUser,
    db: DbDep,
    filename: str,
) -> JSONResponse:
    """Delete a saved template YAML by filename and clear tenant assignments."""
    ok, msg = sigma.delete_template_file(filename)
    if not ok:
        raise HTTPException(status_code=404, detail=msg)
    try:
        db.delete_sigma_asset_assignments("template", msg)
    except Exception as exc:
        logger.warning(f"could not clear template assignments for {msg}: {exc}")
    return JSONResponse({"status": "ok", "deleted": msg})



# --- Sigma asset tenant assignments (Migration 33) ---------------------------

_VALID_ASSET_TYPES = {"pipeline", "template"}


@router.get("/assignments/{asset_type}")
def list_sigma_assignments(
    request: Request,
    user: CurrentUser,
    db: DbDep,
    asset_type: str,
) -> JSONResponse:
    """Return {filename: [{id, name}, ...]} for every assignment of this asset type.

    Used by the Management hub Sigma Assets editor to render the chips next to each file.
    """
    if asset_type not in _VALID_ASSET_TYPES:
        raise HTTPException(status_code=400, detail="asset_type must be 'pipeline' or 'template'")
    return JSONResponse(db.list_sigma_asset_assignments(asset_type))


@router.get("/assignments/{asset_type}/{filename}")
def get_sigma_assignment(
    request: Request,
    user: CurrentUser,
    db: DbDep,
    asset_type: str,
    filename: str,
) -> JSONResponse:
    """Return [{id, name}, ...] of clients assigned to a single file."""
    if asset_type not in _VALID_ASSET_TYPES:
        raise HTTPException(status_code=400, detail="asset_type must be 'pipeline' or 'template'")
    return JSONResponse({"filename": filename, "clients": db.get_sigma_asset_clients(asset_type, filename)})


@router.put("/assignments/{asset_type}/{filename}")
async def set_sigma_assignment(
    request: Request,
    user: CurrentUser,
    db: DbDep,
    asset_type: str,
    filename: str,
) -> JSONResponse:
    """Replace the tenant assignment set for a sigma asset.

    Body: {"client_ids": ["uuid", ...]} - must be non-empty (force-assign-on-save).
    """
    if asset_type not in _VALID_ASSET_TYPES:
        raise HTTPException(status_code=400, detail="asset_type must be 'pipeline' or 'template'")
    body = await request.json()
    client_ids = body.get("client_ids") or []
    if not isinstance(client_ids, list) or not client_ids:
        raise HTTPException(status_code=422, detail="client_ids must be a non-empty list")
    cleaned = [str(c).strip() for c in client_ids if str(c).strip()]
    if not cleaned:
        raise HTTPException(status_code=422, detail="client_ids must contain at least one valid id")
    count = db.set_sigma_asset_assignments(asset_type, filename, cleaned)
    return JSONResponse({"status": "ok", "filename": filename, "client_count": count})
