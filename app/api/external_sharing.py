"""
External Data Sharing API — Sidecar query service for TIDE.

Exposes a secure POST /api/external/query endpoint that allows authenticated
external applications to run read-only SQL against the TIDE DuckDB database.

Authentication: API key via X-TIDE-API-KEY header.
Authorisation:  Only SELECT statements are permitted.
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
    """
    # ── Auth ──
    if not db.validate_api_key(x_tide_api_key):
        logger.warning("External query rejected — invalid API key")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
        )

    # ── SQL validation ──
    _validate_sql(body.sql)

    # ── Execute via the app's connection pool (handles DuckDB locking) ──
    try:
        with db.get_connection() as conn:
            result = conn.execute(body.sql)
            columns = [desc[0] for desc in result.description]
            raw_rows = result.fetchall()
            rows = [dict(zip(columns, row)) for row in raw_rows]
    except Exception as exc:
        logger.error(f"External query error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Query error: {exc}",
        )

    logger.info(f"External query OK — {len(rows)} rows returned")
    return QueryResponse(columns=columns, rows=rows, row_count=len(rows))
