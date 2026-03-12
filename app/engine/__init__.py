"""
engine/ — Hierarchical CPE-to-CVE Dynamic Engine

Replaces the monolithic version_gate.py with a modular architecture:

  cpe_validator.py   Strict CPE 2.3 identity matching + version arithmetic
  sync_manager.py    KEV / OpenCTI / NVD delta tracking and cache management
  platform_graph.py  Hierarchical Platform → Device → Component model

Public re-exports are provided here for backward compatibility so that
existing ``from app.version_gate import …`` can be replaced with a single
``from app.engine import …`` statement.
"""

from app.engine.cpe_validator import (       # noqa: F401
    Cpe,
    should_include_match,
)
from app.engine.sync_manager import (        # noqa: F401
    clear_opencti_vuln_cache,
    fetch_cve_opencti,
    fetch_opencti_vuln_index,
    get_nvd_cpe_ranges,
    _octi_bulk_cache,
)
from app.engine.platform_graph import (      # noqa: F401
    Platform,
    Device,
    Component,
)
