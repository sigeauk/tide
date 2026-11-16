"""The Detection Backlog's list (app/services/backlog.py), refreshed by its filter bar; the page itself
is app/main.py's ``/backlog``, from the same ``page_context``."""

import logging
from typing import Any, Dict

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from app.api.deps import ActiveClient, DbDep, RequireUser
from app.services import backlog

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/backlog", tags=["backlog"])

_FILTERS = ("search", "system", "status", "sort")


def page_context(db, client_id: str, params, user=None) -> Dict[str, Any]:
    """The filters, their choices, the rows they show and the whole backlog's figures. ``can``: the
    pages this user may open from a row (the ATT&CK technique, the rule libraries, a CVE)."""
    data = backlog.backlog(db, client_id)
    filters = backlog.filters_from(params, data["systems"])

    def may(resource: str) -> bool:
        return user is None or user.can_read(resource)

    return {
        "filters": filters, "rows": backlog.view(data, filters), "totals": data["totals"],
        "has_systems": bool(data["systems"]), "baseline_techniques": data["baseline_techniques"],
        "narrowed": bool(filters["search"] or filters["system"] or filters["status"]),
        "system_options": [(s.id, s.name) for s in data["systems"]],
        "status_options": list(backlog.STATUSES),
        "status_titles": {"amber": "Every technique with a known gap, Partial coverage included",
                          "partial": "Known gaps with coverage beside them",
                          "not_effective": "Covered, or partly, only by rules a Rule Monitoring finding stops working"},
        "sort_options": list(backlog.SORTS), "sort_titles": backlog.SORT_TITLES,
        "can": {"mitre": may("page:mitre_technique"), "sigma": may("page:sigma"), "elastic": may("page:elastic"),
                "cves": may("page:cve_overview")},
        "filter_include": ", ".join(f"#backlog-filters [name='{n}']" for n in _FILTERS),
    }


@router.get("/list", response_class=HTMLResponse)
def backlog_list(request: Request, db: DbDep, user: RequireUser, client_id: ActiveClient):
    """The rows for the filter bar's choices."""
    return request.app.state.templates.TemplateResponse(
        request, "partials/backlog_list.html", page_context(db, client_id, request.query_params, user))
