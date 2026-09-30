"""
External Data Sharing API — Sidecar query service for TIDE.

Exposes a secure POST /api/external/query endpoint that allows authenticated
external applications to run read-only SQL against TIDE tenant databases.

Authentication: API key via X-TIDE-API-KEY header.
Authorisation:  Only SELECT statements are permitted; queries run directly
                against the tenant database identified by client_id.
                The API key owner must have access to the requested tenant.
"""

import json
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

# Compiled once — matches any dangerous keyword at a word boundary. Includes
# DuckDB's built-in file/network table functions (no INSTALL/LOAD needed to
# call these, so blocking the extension load alone isn't enough) so a SELECT
# can't be used to read arbitrary host files or reach outside the tenant DB.
_FORBIDDEN_RE = re.compile(
    r"\b(DROP|DELETE|INSERT|UPDATE|ALTER|CREATE|REPLACE|TRUNCATE|ATTACH|DETACH|"
    r"COPY|EXPORT|IMPORT|INSTALL|LOAD|CALL|PRAGMA|GRANT|REVOKE|SET|"
    r"READ_CSV(?:_AUTO)?|READ_PARQUET|READ_JSON(?:_AUTO)?|READ_NDJSON(?:_AUTO)?|"
    r"READ_TEXT|READ_BLOB|READ_XLSX|GLOB|SNIFF_CSV|"
    r"SQLITE_SCAN|POSTGRES_SCAN|ICEBERG_SCAN|DELTA_SCAN)\b",
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


# Table functions a query may use: they only generate rows, they read nothing.
_ROW_FUNCTIONS = {"range", "generate_series", "unnest"}
_PLAIN_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _check_references(conn, sql: str) -> None:
    """Parse the query with DuckDB itself and let it read only this tenant's own tables and views
    (and its CTEs). The keyword list alone cannot stop a SELECT reading a file: a path used as a
    table name ('/x.csv', read by DuckDB's replacement scan), an alias of a blocked reader
    (parquet_scan) or query('...') built from pieces all get past it."""
    def reject(detail: str):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)

    tree = json.loads(conn.execute("SELECT json_serialize_sql(?)", [sql]).fetchone()[0])
    if tree.get("error") or len(tree.get("statements") or []) != 1:
        reject("Only a single SELECT statement is allowed.")

    database = conn.execute("SELECT current_database()").fetchone()[0].lower()
    own = {name.lower() for (name,) in conn.execute(
        "SELECT table_name FROM duckdb_tables() WHERE database_name = current_database() "
        "UNION SELECT view_name FROM duckdb_views() WHERE database_name = current_database() AND NOT internal"
    ).fetchall()}

    ctes, tables, functions = set(), [], []

    def walk(node):
        if isinstance(node, dict):
            for entry in (node.get("cte_map") or {}).get("map") or []:
                ctes.add(str(entry.get("key") or ""))
            if node.get("type") == "BASE_TABLE":
                tables.append((node.get("catalog_name") or "", node.get("schema_name") or "", node.get("table_name") or ""))
            elif node.get("type") == "TABLE_FUNCTION":
                functions.append(((node.get("function") or {}).get("function_name") or "").lower())
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(tree["statements"][0])
    # A CTE name is a plain identifier: a path can't pass as one ('/x.csv' in one scope, read as a
    # file in another), since a file DuckDB would scan always has an extension.
    for name in ctes:
        if not _PLAIN_NAME.match(name):
            reject(f"CTE names must be plain identifiers: {name}")
    cte_names = {n.lower() for n in ctes}
    for catalog, schema, name in tables:
        if catalog.lower() not in ("", database) or schema.lower() not in ("", "main") \
                or name.lower() not in own | cte_names:
            reject(f"Unknown table: {name}")
    for name in functions:
        if name not in _ROW_FUNCTIONS:
            reject(f"Table function not allowed: {name}")


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
            _check_references(conn, body.sql.strip().rstrip(";").strip())
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
