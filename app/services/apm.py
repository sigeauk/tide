"""Elastic APM helpers for TIDE."""

from __future__ import annotations

from contextlib import contextmanager, nullcontext
import logging

try:
    import elasticapm
except Exception:  # pragma: no cover
    elasticapm = None

logger = logging.getLogger(__name__)


def _summarize_sql(statement: str) -> str:
    text = " ".join(str(statement or "").split())
    if not text:
        return "DuckDB query"
    operation = text.split(" ", 1)[0].upper()
    if operation == "WITH":
        operation = "SELECT"
    return f"DuckDB {operation}"


@contextmanager
def capture_duckdb_span(statement: str):
    """Capture a DuckDB query span when APM is enabled."""
    if elasticapm is None:
        yield
        return
    try:
        span = elasticapm.capture_span(
            _summarize_sql(statement),
            span_type="db",
            span_subtype="duckdb",
            span_action="query",
        )
    except Exception:  # pragma: no cover
        logger.debug("Elastic APM span creation failed for DuckDB statement", exc_info=True)
        span = nullcontext()
    with span:
        yield


def set_transaction_labels(**labels):
    """Attach transaction labels when APM is available."""
    if elasticapm is None:
        return
    clean_labels = {key: value for key, value in labels.items() if value is not None}
    if not clean_labels:
        return
    try:
        elasticapm.label(**clean_labels)
    except Exception:  # pragma: no cover
        logger.debug("Elastic APM label update failed", exc_info=True)