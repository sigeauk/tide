"""
API routes for Sigma Converter.
Provides endpoints for rule browsing, conversion, validation, and SIEM deployment.
"""

from fastapi import APIRouter, Request, Query, Form
from fastapi.responses import HTMLResponse
from typing import List, Optional

from app.api.deps import CurrentUser, SettingsDep
from app import sigma_helper as sigma

import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/sigma", tags=["sigma"])


@router.get("/rules", response_class=HTMLResponse)
def search_rules(
    request: Request,
    user: CurrentUser,
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
    
    templates = request.app.state.templates
    return templates.TemplateResponse(
        "partials/sigma_rules_list.html",
        {
            "request": request,
            "rules": results,
            "total_count": len(sigma.load_all_rules()),
            "filtered_count": len(results),
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
        output_format=output_format
    )
    
    # Also get raw query for SIEM deployment
    raw_query = ""
    if success:
        raw_success, raw_result = sigma.convert_sigma_rule(
            yaml_content=yaml_content,
            backend=backend,
            pipeline=pipeline,
            output_format='default'
        )
        raw_query = raw_result if raw_success else result
    
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
        "partials/sigma_convert_result.html",
        {
            "request": request,
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
    yaml_content: str = Form(...),
    raw_query: str = Form(...),
    space: str = Form("staging"),
    enabled: bool = Form(False),
):
    """
    Deploy a converted Sigma rule to Elastic SIEM.
    """
    if not yaml_content.strip() or not raw_query.strip():
        return HTMLResponse(
            '<div class="alert alert-warning">Convert a rule first before deploying</div>'
        )
    
    success, message = sigma.send_rule_to_siem(
        yaml_content=yaml_content,
        query=raw_query,
        space=space,
        enabled=enabled
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
def get_spaces(request: Request, user: CurrentUser):
    """Get Kibana spaces as HTML options."""
    spaces = sigma.get_kibana_spaces()
    html = ""
    for space in spaces:
        html += f'<option value="{space}">{space.title()}</option>'
    return HTMLResponse(html)
