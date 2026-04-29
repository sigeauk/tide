"""
External Data Sharing API — Sidecar query service for TIDE.

Exposes a secure POST /api/external/query endpoint that allows authenticated
external applications to run read-only SQL against TIDE tenant databases.

Authentication: API key via X-TIDE-API-KEY header.
Authorisation:  Only SELECT statements are permitted; queries run directly
                against the tenant database identified by client_id.
                The API key owner must have access to the requested tenant.
"""

import re
import logging

import duckdb
from fastapi import APIRouter, Header, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional, List

from app.api.deps import DbDep
from app.config import get_settings
from app.services.tenant_manager import resolve_tenant_db_path

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/external", tags=["external"])

# Compiled once — matches any dangerous keyword at a word boundary
_FORBIDDEN_RE = re.compile(
    r"\b(DROP|DELETE|INSERT|UPDATE|ALTER|CREATE|REPLACE|TRUNCATE|ATTACH|DETACH|"
    r"COPY|EXPORT|IMPORT|INSTALL|LOAD|CALL|PRAGMA|GRANT|REVOKE|SET)\b",
    re.IGNORECASE,
)


class QueryRequest(BaseModel):
    """Incoming query payload."""
    sql: str = Field(..., min_length=1, max_length=4000, description="SQL SELECT statement")
    client_id: Optional[str] = Field(
        None,
        description="Target tenant (client) ID. Required when the API key owner has access to multiple tenants. "
                    "Use GET /api/external/clients to discover available tenants.",
    )


class QueryResponse(BaseModel):
    """Successful query response."""
    columns: list[str]
    rows: list[dict]
    row_count: int


class ClientInfo(BaseModel):
    id: str
    name: str
    slug: str


class ClientsResponse(BaseModel):
    """Response listing accessible tenants for an API key."""
    clients: List[ClientInfo]


def _validate_sql(sql: str) -> None:
    """Reject anything that is not a read-only SELECT."""
    stripped = sql.strip().rstrip(";").strip()

    # Must start with SELECT or WITH (CTE)
    if not re.match(r"^(SELECT|WITH)\b", stripped, re.IGNORECASE):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only SELECT statements are allowed.",
        )

    # Reject forbidden keywords anywhere in the statement
    match = _FORBIDDEN_RE.search(stripped)
    if match:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Forbidden SQL keyword: {match.group(0).upper()}",
        )


@router.get("/clients", response_model=ClientsResponse)
def list_external_clients(
    db: DbDep,
    x_tide_api_key: str = Header(..., alias="X-TIDE-API-KEY"),
):
    """
    List tenants (clients) accessible to this API key.

    Returns the client IDs, names, and slugs that the API key owner
    is assigned to.  Use the ``id`` value as ``client_id`` in query requests.
    """
    key_info = db.validate_api_key_full(x_tide_api_key)
    if not key_info:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
        )
    return ClientsResponse(
        clients=[ClientInfo(**c) for c in key_info["clients"]]
    )


@router.post("/query", response_model=QueryResponse)
def external_query(
    body: QueryRequest,
    db: DbDep,
    x_tide_api_key: str = Header(..., alias="X-TIDE-API-KEY"),
):
    """
    Execute a read-only SQL query against a TIDE tenant database.

    Requires a valid API key in the X-TIDE-API-KEY header.
    Only SELECT (and WITH/CTE) statements are permitted.

    The ``client_id`` field selects which tenant database to query.
    If the API key owner has access to exactly one tenant, ``client_id``
    may be omitted and will default to that tenant.
    Use ``GET /api/external/clients`` to discover available tenants.
    """
    # ── Auth ──
    key_info = db.validate_api_key_full(x_tide_api_key)
    if not key_info:
        logger.warning("External query rejected — invalid API key")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
        )

    allowed_client_ids = key_info["client_ids"]
    if not allowed_client_ids:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API key owner has no tenant access. Assign the user to at least one client.",
        )

    # ── Resolve target tenant ──
    target_client_id = body.client_id
    if not target_client_id:
        if len(allowed_client_ids) == 1:
            target_client_id = allowed_client_ids[0]
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="client_id is required when the API key owner has access to multiple tenants. "
                       "Use GET /api/external/clients to list available tenants.",
            )

    if target_client_id not in allowed_client_ids:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API key does not have access to the requested tenant.",
        )

    # ── Resolve tenant DB path ──
    settings = get_settings()
    tenant_db_path = resolve_tenant_db_path(target_client_id, settings.data_dir)
    if not tenant_db_path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant database not found for the requested client.",
        )

    # ── SQL validation ──
    _validate_sql(body.sql)

    # ── Execute against tenant DB (read-only) ──
    try:
        # 4.1.0 P3 — pool may hold a writable handle to this tenant DB; opening
        # read-only would trip DuckDB's "different configuration" error.
        conn = duckdb.connect(tenant_db_path, read_only=False)
        try:
            result = conn.execute(body.sql)
            columns = [desc[0] for desc in result.description]
            raw_rows = result.fetchall()
            rows = [dict(zip(columns, row)) for row in raw_rows]
        finally:
            conn.close()
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"External query error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Query error: {exc}",
        )

    logger.info(f"External query OK — {len(rows)} rows for client {target_client_id[:8]}…")
    return QueryResponse(columns=columns, rows=rows, row_count=len(rows))
