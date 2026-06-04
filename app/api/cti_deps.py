"""CTI-side FastAPI dependencies (step D of PLAN_CTI).

This module is intentionally narrow: it only provides the TLP scoping
machinery that the ``/cti/...`` read surface (step E) will lean on.

Concepts
--------
* **TLP ceiling** — the most *restrictive* TLP marking the operator is
  authorised to handle. Rows whose ``tlp`` is *more restrictive than*
  the ceiling are filtered out at query time. This matches the
  semantics already in :mod:`app.services.cti_egress._common`: an
  ``amber`` ceiling sees ``amber`` + the less-restrictive markings
  (``green``, ``clear``), but not ``red``.
* **Source** — the Keycloak ``tide_tlp_max`` claim, surfaced on
  :attr:`app.models.auth.User.tlp_max` by the auth pipeline. Local-only
  users (no SSO claim) default to ``"amber"``.
* **Ranking** — mirrors :mod:`app.services.cti_egress._common` so
  ingest, egress, and read paths agree on what "more restrictive"
  means:

    ``clear`` / ``white`` (4) > ``green`` (3) > ``amber`` (2) > ``red`` (1)

  Unlabelled rows (``NULL`` ``tlp``) are treated as ``amber`` — same
  convention as the egress path, so unlabelled indicators never leak
  to a ``red``-only operator and never get dropped on the floor by a
  ``clear``-only operator either.

The dependency exposes:

* :data:`TlpScopeDep` \u2014 ``Annotated[TlpScope, Depends(require_tlp_scope)]``
  for use in route signatures.
* :func:`tlp_filter_clause` \u2014 emits a parametrised SQL fragment
  (``"i.tlp IN (?, ?, ...)"``) plus the bind list, so the read endpoints
  in step E can splice the filter into their own ``WHERE`` clauses
  without re-implementing the ranking.

Superadmins are *not* exempted: TLP is a need-to-know marker, not an
authorisation level. A superadmin without a ``tide_tlp_max`` claim still
gets the default ``amber`` ceiling.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Iterable, Optional

from fastapi import Depends

from app.api.deps import RequireUser
from app.models.auth import User


# Numeric ranking shared with cti_egress. Higher = more permissive.
_TLP_RANK = {
    "clear": 4,
    "white": 4,  # legacy alias for clear
    "green": 3,
    "amber": 2,
    "red": 1,
}

# Default ceiling when the claim is missing or malformed. Matches the
# default applied to ``cti_egress_targets.tlp_ceiling`` so an operator
# with no SSO claim sees exactly what the default egress target would
# push out \u2014 no surprises either way.
DEFAULT_TLP_CEILING = "amber"


def _coerce_ceiling(value: Optional[str]) -> str:
    v = (value or "").strip().lower()
    return v if v in _TLP_RANK else DEFAULT_TLP_CEILING


@dataclass(frozen=True)
class TlpScope:
    """Resolved TLP ceiling for the current request."""

    ceiling: str

    @property
    def rank(self) -> int:
        return _TLP_RANK[self.ceiling]

    def visible_markings(self) -> list[str]:
        """Return every TLP marking the operator is allowed to see.

        A marking is visible iff its rank is *greater than or equal to*
        the ceiling rank (less or equally restrictive). Includes both
        ``clear`` and ``white`` whenever ``clear`` is visible, since
        legacy ingest paths may have written either spelling.
        """
        ceiling_rank = self.rank
        out = [name for name, rank in _TLP_RANK.items()
               if rank >= ceiling_rank]
        # Stable, predictable order: most permissive first.
        out.sort(key=lambda n: (-_TLP_RANK[n], n))
        return out

    def allows(self, marking: Optional[str]) -> bool:
        """``True`` if a row with ``marking`` passes this ceiling.

        Unknown / missing markings are treated as ``amber`` — same
        default as :func:`app.services.cti_egress._common._tlp_rank` so
        unlabelled indicators behave identically on read and write.
        """
        raw = (marking or "").strip().lower()
        rank = _TLP_RANK.get(raw, _TLP_RANK["amber"])
        return rank >= self.rank


async def require_tlp_scope(
    user: RequireUser,
) -> TlpScope:
    """Resolve the active user's TLP ceiling.

    Pulls from :attr:`User.tlp_max` (sourced from the Keycloak
    ``tide_tlp_max`` claim) and falls back to :data:`DEFAULT_TLP_CEILING`
    when the claim is absent.
    """
    return TlpScope(ceiling=_coerce_ceiling(user.tlp_max))


TlpScopeDep = Annotated[TlpScope, Depends(require_tlp_scope)]


def tlp_filter_clause(
    scope: TlpScope,
    *,
    column: str = "tlp",
) -> tuple[str, list[str]]:
    """Build a SQL fragment + bind list for filtering by TLP ceiling.

    Returns ``(clause, params)`` where ``clause`` looks like
    ``"(tlp IN (?, ?, ?) OR (tlp IS NULL AND ?))"`` — NULL rows pass
    whenever the unlabelled-default (``amber``) is itself visible under
    the ceiling, matching :meth:`TlpScope.allows`.

    The ``column`` argument lets callers prefix with a table alias
    (e.g. ``"i.tlp"``).
    """
    visible = scope.visible_markings()
    placeholders = ", ".join("?" for _ in visible)
    null_visible = scope.allows(None)
    clause = (
        f"({column} IN ({placeholders}) OR "
        f"({column} IS NULL AND ?))"
    )
    params: list = [*visible, bool(null_visible)]
    return clause, params


def filter_rows_by_tlp(
    rows: Iterable[dict],
    scope: TlpScope,
    *,
    key: str = "tlp",
) -> list[dict]:
    """In-Python fallback: drop rows whose ``key`` exceeds the ceiling.

    Used by the read surface when a query already returned a row list
    (e.g. cross-link panels populated from a join) and we just need to
    redact rather than re-query.
    """
    return [r for r in rows if scope.allows(r.get(key))]


__all__ = [
    "DEFAULT_TLP_CEILING",
    "TlpScope",
    "TlpScopeDep",
    "require_tlp_scope",
    "tlp_filter_clause",
    "filter_rows_by_tlp",
]
