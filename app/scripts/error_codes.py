"""TIDE's error codes (app/services/errors.py), for when its pages aren't there to say what one means.

    docker exec tide-app python -m app.scripts.error_codes            # every code
    docker exec tide-app python -m app.scripts.error_codes D500       # what one means, and what to do
    docker exec tide-app python -m app.scripts.error_codes --markdown # write docs/ERRORS.md from them

The guide's Error codes page (docs/ERRORS.md) is written from the same codes, so the two always agree.
"""
from __future__ import annotations

import sys
from pathlib import Path

from app.services.errors import CODES, PREFIXES

GUIDE = Path(__file__).resolve().parents[2] / "docs" / "ERRORS.md"
COMMAND = "docker exec tide-app python -m app.scripts.error_codes"


def markdown() -> str:
    """docs/ERRORS.md: every code, by where it went wrong."""
    out = [
        "# Error codes",
        "",
        "<!-- Written from TIDE's error codes (app/services/errors.py) by "
        "python -m app.scripts.error_codes --markdown: change them there, not here. -->",
        "",
        "When something goes wrong, TIDE's message ends with a short error code, such as D500, and TIDE's log "
        "records the same code. Quote the code when you ask for help: this page says what each one means and "
        "what to do. A failure TIDE didn't expect also gives a reference, which finds it in TIDE's log "
        "(see [Logs](OPERATIONS.md#logs)).",
        "",
        "## Reading a code",
        "",
        "The letter says where it went wrong:",
        "",
        "| Letter | Stands for | Covers |",
        "|---|---|---|",
        *[f"| {letter} | {name} | {about} |" for letter, name, about in PREFIXES],
        "",
        "The first digit says whose side: 4 means something to put right (the request, a setting, a "
        "permission), 5 means something failed or wasn't available. Where the web has a number for the same "
        "thing, the code uses it (404 is \"not found\" there too). For a SIEM, GitLab, OpenCTI or Keycloak, "
        "it is what that system answered: S401 means the SIEM answered 401, it didn't accept TIDE's key.",
        "",
        "## Looking a code up in the container",
        "",
        "When TIDE's pages aren't there to read this one, look a code up from the command line:",
        "",
        "```bash",
        f"{COMMAND} D500",
        "```",
        "",
        "Without a code it lists them all. In the log (`docker compose logs tide-app`, or `data/log/tide.log`) "
        "each error has its code in its `code` field.",
    ]
    for letter, name, _ in PREFIXES:
        codes = [c for c in CODES.values() if c.code[0] == letter]
        if not codes:
            continue
        out += ["", f"## {letter}: {name}"]
        for c in codes:
            out += ["", f"### {c.code}", "", c.title, "", f"*What to do:* {c.fix}"]
    return "\n".join(out) + "\n"


def describe(code: str) -> str:
    c = CODES[code]
    return f"{c.code}  {c.title}\n\nWhat to do: {c.fix}\n"


def main(argv) -> int:
    if argv[:1] == ["--markdown"]:
        GUIDE.write_text(markdown(), encoding="utf-8")
        print(f"Wrote {GUIDE} ({len(CODES)} codes)")
        return 0
    if argv:
        code = argv[0].strip().upper()
        if code not in CODES:
            print(f"There is no error code {code} in this version of TIDE. Run it without a code for the list.")
            return 1
        print(describe(code))
        return 0
    for c in CODES.values():
        print(f"{c.code}  {c.title}")
    print(f"\n{COMMAND} <code> says what to do about one.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
