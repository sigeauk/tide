"""
4.1.0 P4 — Asset bundling for TIDE.

Concatenates the CSS files under ``app/static/css/`` (excluding ``dist/``
and ``vendor/``) into a single content-hashed bundle in ``app/static/css/dist/``
and emits ``app/static/manifest.json`` mapping logical asset names to
their hashed paths.

Why content-hashed filenames:
    * Lets nginx serve ``/static/css/dist/*`` with
      ``Cache-Control: public, immutable, max-age=31536000`` instead of the
      current 7-day window — the URL itself encodes the content version,
      so cache poisoning by a stale CDN is impossible.
    * Decouples cache busting from the release version, so dev edits to
      ``style.css`` inside a release pick up immediately (the new hash
      becomes a new URL).
    * Removes the ``cache_bust | default(range(1, 99999) | random)``
      fallback in ``base.html`` which silently re-downloaded the CSS on
      every render whenever ``cache_bust`` was missing.

Run at container build time (Dockerfile) and on demand in dev:

    docker exec tide-app python -m app.scripts.build_assets

Idempotent — same input bytes produce the same output filename.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Iterable, List

# Paths — module-level constants so the script stays trivially readable.
APP_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = APP_DIR / "static"
CSS_DIR = STATIC_DIR / "css"
JS_DIR = STATIC_DIR / "js"
DIST_DIR = CSS_DIR / "dist"
JS_DIST_DIR = JS_DIR / "dist"
MANIFEST_PATH = STATIC_DIR / "manifest.json"

# Bundles to build — keep tiny on purpose. New bundles get a new entry here
# rather than auto-discovery so the build output stays predictable. The
# order in *sources* matters (concatenation is positional).
BUNDLES: dict = {
    "styles.css": {
        "kind": "css",
        "sources": [
            CSS_DIR / "style.css",
            CSS_DIR / "heatmap.css",
        ],
    },
    "app.js": {
        "kind": "js",
        "sources": [
            JS_DIR / "app.js",
        ],
    },
}


def _hash(content: bytes) -> str:
    """Return the first 12 hex chars of sha256 — collision-resistant enough
    for a per-release asset namespace (~10^14 distinct outputs)."""
    return hashlib.sha256(content).hexdigest()[:12]


def _read_concat(sources: Iterable[Path]) -> bytes:
    """Concatenate *sources* in order with a single ``\\n`` separator. Missing
    files raise immediately — silent skips would let a typo in BUNDLES ship
    a half-built bundle."""
    chunks: List[bytes] = []
    for src in sources:
        if not src.exists():
            raise FileNotFoundError(f"build_assets: source missing — {src}")
        chunks.append(src.read_bytes())
    return b"\n".join(chunks)


def _clean_dist(dist: Path, kind: str) -> None:
    """Remove old hashed bundles of *kind* so old releases don't accumulate
    in the image. Leaves the directory itself in place."""
    dist.mkdir(parents=True, exist_ok=True)
    suffix = f".{kind}"
    for path in dist.iterdir():
        if path.is_file() and path.suffix == suffix:
            path.unlink()


def build() -> dict:
    """Build every bundle in BUNDLES and write the manifest. Returns the
    manifest dict so callers (Dockerfile, tests) can assert its shape."""
    manifest: dict = {}

    # Group bundles by output dir so we can clean once per kind.
    css_bundles = {n: b for n, b in BUNDLES.items() if b["kind"] == "css"}
    js_bundles = {n: b for n, b in BUNDLES.items() if b["kind"] == "js"}

    if css_bundles:
        _clean_dist(DIST_DIR, "css")
    if js_bundles:
        _clean_dist(JS_DIST_DIR, "js")

    for logical_name, bundle in BUNDLES.items():
        kind = bundle["kind"]
        content = _read_concat(bundle["sources"])
        digest = _hash(content)

        if kind == "css":
            out_dir = DIST_DIR
            url_prefix = "/static/css/dist"
        else:
            out_dir = JS_DIST_DIR
            url_prefix = "/static/js/dist"

        stem, ext = os.path.splitext(logical_name)
        out_name = f"{stem}-{digest}{ext}"
        (out_dir / out_name).write_bytes(content)

        manifest[logical_name] = f"{url_prefix}/{out_name}"
        print(f"  built {logical_name} → {manifest[logical_name]} ({len(content)} bytes)")

    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    print(f"  manifest → {MANIFEST_PATH}")
    return manifest


if __name__ == "__main__":
    print("Building TIDE asset bundles…")
    build()
    print("Done.")
