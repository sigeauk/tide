"""Parser-based guard for read-only SQL written by a user (the external query API and the
Management query page).

A keyword list alone cannot stop a SELECT reading a file: a path used as a table name ('/x.csv',
read by DuckDB's replacement scan), an alias of a blocked reader (parquet_scan) or query('...')
built from pieces all get past it. So the query is parsed by DuckDB itself and may read only the
connected database's own tables and views (and its CTEs).
"""
import json
import re

# Table functions a query may use: they only generate rows, they read nothing.
ROW_FUNCTIONS = {"range", "generate_series", "unnest"}
PLAIN_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class SqlRejected(ValueError):
    """The statement reads something other than the database's own tables."""


def own_tables(conn) -> set:
    """Lower-cased names of the connected database's own tables and views."""
    return {name.lower() for (name,) in conn.execute(
        "SELECT table_name FROM duckdb_tables() WHERE database_name = current_database() "
        "UNION SELECT view_name FROM duckdb_views() WHERE database_name = current_database() AND NOT internal"
    ).fetchall()}


def check_references(conn, sql: str, catalog_views: bool = False) -> None:
    """Raise SqlRejected unless ``sql`` is one SELECT reading only the database's own tables.
    ``catalog_views`` also allows the information_schema / pg_catalog views, which describe the
    database and read no files."""
    tree = json.loads(conn.execute("SELECT json_serialize_sql(?)", [sql]).fetchone()[0])
    if tree.get("error") or len(tree.get("statements") or []) != 1:
        raise SqlRejected("Only a single SELECT statement is allowed.")

    database = conn.execute("SELECT current_database()").fetchone()[0].lower()
    own = own_tables(conn)
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
        if not PLAIN_NAME.match(name):
            raise SqlRejected(f"CTE names must be plain identifiers: {name}")
    cte_names = {n.lower() for n in ctes}
    for catalog, schema, name in tables:
        if catalog_views and catalog.lower() in ("", database) and schema.lower() in ("information_schema", "pg_catalog"):
            continue
        if catalog.lower() not in ("", database) or schema.lower() not in ("", "main") \
                or name.lower() not in own | cte_names:
            raise SqlRejected(f"Unknown table: {name}")
    for name in functions:
        if name not in ROW_FUNCTIONS:
            raise SqlRejected(f"Table function not allowed: {name}")
