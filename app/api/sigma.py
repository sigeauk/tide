"""
API routes for Sigma Converter.
Provides endpoints for rule browsing, conversion, validation, and SIEM deployment.
"""

from fastapi import APIRouter, Request, Query, Form, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from typing import Optional

from app.api.deps import CurrentUser, SettingsDep, DbDep, ActiveClient
from app import sigma_helper as sigma

import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/sigma", tags=["sigma"])


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
    limit: int = Query(100, le=500),
):
    """
    Search Sigma rules and return HTML partial.
    """
    results = sigma.search_rules(
        query=query,
        technique_filter=technique,
        category_filter=category,
        level_filter=level,
        limit=limit
    )
    
    # Coverage data for MITRE pills
    covered_ttps = db.get_all_covered_ttps(client_id=client_id)
    ttp_rule_counts = db.get_ttp_rule_counts(client_id=client_id)
    
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "partials/sigma_rules_list.html",
        {
            "rules": results,
            "total_count": len(sigma.load_all_rules()),
            "filtered_count": len(results),
            "covered_ttps": covered_ttps,
            "ttp_rule_counts": ttp_rule_counts,
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


@router.post("/convert", response_class=HTMLResponse)
def convert_rule(
    request: Request,
    user: CurrentUser,
    yaml_content: str = Form(...),
    backend: str = Form("elasticsearch"),
    pipeline: str = Form("none"),
    output_format: str = Form("default"),
    index_pattern: str = Form(""),
    custom_pipeline_yaml: str = Form(""),
    pipeline_file: str = Form(""),
    template_file: str = Form(""),
):
    """
    Convert a Sigma rule to target query language.
    Returns HTML partial with the result.
    """
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
):
    """
    Deploy a converted Sigma rule to Elastic SIEM.
    Validates that the target space belongs to the active client's linked SIEMs.
    """
    if not yaml_content.strip() or not raw_query.strip():
        return HTMLResponse(
            '<div class="alert alert-warning">Convert a rule first before deploying</div>'
        )

    # Validate the target space belongs to this client
    allowed_spaces = db.get_client_siem_spaces(client_id)
    if space not in allowed_spaces:
        return HTMLResponse(
            '<div class="alert alert-danger">Deployment blocked: target SIEM is not linked to your client.</div>'
        )

    success, message = sigma.send_rule_to_siem(
        yaml_content=yaml_content,
        space=space,
        enabled=enabled,
        index_pattern=index_pattern or None,
        pipeline_file=pipeline_file,
        template_file=template_file,
        username=user.username,
    )

    if success:
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
            label = f'{s["label"]} ({s["environment_role"].title()})'
            selected = ' selected' if s["environment_role"] == "production" else ""
            html += f'<option value="{s["space"]}"{selected}>{label}</option>'
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


# ─── Saved Pipeline CRUD ─────────────────────────────────────────────────────

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
    filename: str,
) -> JSONResponse:
    """Delete a saved pipeline YAML by filename."""
    ok, msg = sigma.delete_pipeline_file(filename)
    if not ok:
        raise HTTPException(status_code=404, detail=msg)
    return JSONResponse({"status": "ok", "deleted": msg})


# ─── Saved Template CRUD ────────────────────────────────────────────────────

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
    filename: str,
) -> JSONResponse:
    """Delete a saved template YAML by filename."""
    ok, msg = sigma.delete_template_file(filename)
    if not ok:
        raise HTTPException(status_code=404, detail=msg)
    return JSONResponse({"status": "ok", "deleted": msg})
