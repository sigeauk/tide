"""
External Data Sharing API — Sidecar query service for TIDE.

Exposes a secure POST /api/external/query endpoint that allows authenticated
external applications to run read-only SQL against the TIDE DuckDB database.

Authentication: API key via X-TIDE-API-KEY header.
Authorisation:  Only SELECT statements are permitted; results are scoped to
                the client that owns the API key via temporary filtered views.
"""

import re
import logging

from fastapi import APIRouter, Header, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.api.deps import DbDep

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/external", tags=["external"])

# Compiled once — matches any dangerous keyword at a word boundary
_FORBIDDEN_RE = re.compile(
    r"\b(DROP|DELETE|INSERT|UPDATE|ALTER|CREATE|REPLACE|TRUNCATE|ATTACH|DETACH|"
    r"COPY|EXPORT|IMPORT|INSTALL|LOAD|CALL|PRAGMA|GRANT|REVOKE|SET)\b",
    re.IGNORECASE,
)

# Tables with a client_id column that must be tenant-scoped
_TENANT_SCOPED_TABLES = [
    "systems", "hosts", "software_inventory", "detection_rules",
    "playbooks", "system_baselines", "system_baseline_snapshots",
    "vuln_detections", "applied_detections", "cve_technique_overrides",
    "classifications", "blind_spots", "api_keys",
]

# Reject explicit main.* references that would bypass temp-view scoping
_SCHEMA_BYPASS_RE = re.compile(
    r"\bmain\s*\.\s*(" + "|".join(_TENANT_SCOPED_TABLES) + r")\b",
    re.IGNORECASE,
)


class QueryRequest(BaseModel):
    """Incoming query payload."""
    sql: str = Field(..., min_length=1, max_length=4000, description="SQL SELECT statement")


class QueryResponse(BaseModel):
    """Successful query response."""
    columns: list[str]
    rows: list[dict]
    row_count: int


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

    # Reject qualified schema references that bypass tenant-scoped views
    bypass = _SCHEMA_BYPASS_RE.search(stripped)
    if bypass:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Qualified schema references not allowed: main.{bypass.group(1)}",
        )


@router.post("/query", response_model=QueryResponse)
def external_query(
    body: QueryRequest,
    db: DbDep,
    x_tide_api_key: str = Header(..., alias="X-TIDE-API-KEY"),
):
    """
    Execute a read-only SQL query against the TIDE database.

    Requires a valid API key in the X-TIDE-API-KEY header.
    Only SELECT (and WITH/CTE) statements are permitted.
    All tenant-scoped tables are automatically filtered to the API key's
    owning client via temporary views — callers see only their own data.
    """
    # ── Auth ──
    client_id = db.validate_api_key(x_tide_api_key)
    if not client_id:
        logger.warning("External query rejected — invalid API key")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
        )

    # ── SQL validation ──
    _validate_sql(body.sql)

    # ── Execute with tenant-scoped views ──
    try:
        with db.get_connection() as conn:
            # Shadow every tenant-scoped table with a filtered temp view.
            # DuckDB resolves temp views before main schema tables, so the
            # caller's SQL transparently sees only their client's rows.
            for table in _TENANT_SCOPED_TABLES:
                conn.execute(
                    f"CREATE OR REPLACE TEMP VIEW {table} AS "
                    f"SELECT * FROM main.{table} WHERE client_id = ?",
                    [client_id],
                )

            result = conn.execute(body.sql)
            columns = [desc[0] for desc in result.description]
            raw_rows = result.fetchall()
            rows = [dict(zip(columns, row)) for row in raw_rows]
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"External query error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Query error: {exc}",
        )

    logger.info(f"External query OK — {len(rows)} rows for client {client_id[:8]}…")
    return QueryResponse(columns=columns, rows=rows, row_count=len(rows))
