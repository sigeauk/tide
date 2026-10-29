"""
engine/ — Hierarchical CPE-to-CVE Dynamic Engine

Replaces the monolithic version_gate.py with a modular architecture:

  cpe_validator.py   Strict CPE 2.3 identity matching + version arithmetic
  sync_manager.py    KEV / NVD delta tracking and cache management
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
    get_nvd_cpe_ranges,
)
from app.engine.platform_graph import (      # noqa: F401
    Platform,
    Device,
    Component,
)
