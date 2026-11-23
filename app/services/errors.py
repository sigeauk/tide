"""TIDE's error codes (#117): one registry, so a failure carries the same code on screen, in the log
and in the guide (docs/ERRORS.md, written from here by ``python -m app.scripts.error_codes``).

A code is a letter for where it went wrong and three digits:

    T  TIDE itself           D  TIDE's databases (DuckDB)      S  a SIEM (Elastic, Wazuh)
    A  access: sign-in, roles, API keys, Keycloak              I  GitLab and OpenCTI

The first digit says whose side: 4, something a person puts right (the request, a setting, a
permission); 5, something failed or isn't available. A number HTTP defines means what it means in
HTTP (A401: not signed in). A failure with no HTTP equivalent takes a number HTTP leaves free,
460-499 or 560-599. A code keeps its meaning once released, and a retired code is never used again.

Everywhere else names a code by its constant here (``errors.D503``), never by its text.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from html import escape
from typing import Any, Dict, Optional

import duckdb
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import Response


@dataclass(frozen=True)
class Code:
    code: str               # "D503"
    status: Optional[int]   # what a request failing with it answers; None for startup and background work
    title: str              # what happened, one sentence
    fix: str                # what to do
    upstream: bool = False  # about another system's answer (a SIEM, GitLab, OpenCTI, Keycloak): its number
                            # is that answer's (S401: the SIEM said 401), and TIDE answers 502

    def __str__(self) -> str:
        return self.code


# Where a code says it went wrong: (letter, name, what it covers), in the guide's order.
PREFIXES = [
    ("T", "TIDE", "TIDE itself: pages, forms, its settings and files, its background services."),
    ("D", "Databases", "TIDE's databases: its own, each client's, and the bundled reference database."),
    ("S", "SIEMs", "A SIEM TIDE reads: Elastic (Kibana, Elasticsearch) or Wazuh."),
    ("A", "Access", "Who you are and what you may do: signing in, sessions, roles, API keys, Keycloak."),
    ("I", "Integrations", "GitLab and OpenCTI."),
]

# ── T: TIDE ─────────────────────────────────────────────────────────────
T400 = Code("T400", 400, "The request wasn't one TIDE can act on.",
            "Refresh the page and try again.")
T404 = Code("T404", 404, "That item doesn't exist, or no longer does.",
            "It may have been deleted or moved: refresh the list and look for it again.")
T409 = Code("T409", 409, "That already exists, or changed while you were working on it.",
            "Refresh, look at what is there now, and choose again.")
T422 = Code("T422", 422, "A field is missing or not valid.",
            "Check the fields the form marks, then try again.")
T500 = Code("T500", 500, "TIDE hit an unexpected error.",
            "Try again. If it happens again, report the code, the reference and the time: the reference "
            "finds the error in TIDE's log.")
# T503 and T504 are nginx's (nginx/nginx.conf, @tide_down and @tide_slow), when TIDE itself doesn't answer:
# its page there has the same words, held to these by test/cicd_nginx_headers.py.
T503 = Code("T503", 503, "TIDE is starting or restarting.",
            "Wait a minute: the page reloads by itself. If TIDE doesn't come back, its log says why "
            "(docker compose logs tide-app).")
T504 = Code("T504", 504, "TIDE didn't answer in time.",
            "Try again. If every page hangs, restart TIDE (docker compose restart tide-app).")
T460 = Code("T460", None, "SESSION_SECRET isn't set, or is still the example value, so TIDE won't start.",
            "Set SESSION_SECRET in .env to a long random string (make one with openssl rand -base64 48), then "
            "start TIDE again (docker compose up -d).")
T461 = Code("T461", None, "Stored keys and passwords can't be read: data/credentials.key isn't the key they were "
            "saved with.",
            "Put back the data/credentials.key that was backed up with this data, then restart TIDE. Without it, "
            "enter each SIEM's and integration's key or password again in Settings → Management.")
T560 = Code("T560", None, "A background service isn't running, so rule-log exports, scheduled backups and the "
            "maintenance window won't happen on their own.",
            "Restart TIDE (docker compose restart tide-app). If it says so again, report the log from startup: "
            "the error before this one says why.")

# ── D: databases ────────────────────────────────────────────────────────
D404 = Code("D404", 404, "A client's database file is missing from the data folder.",
            "Settings → Diagnostics → Run all checks names the file. Restore it from a backup, or remove the "
            "client if it is no longer used.")
D409 = Code("D409", 409, "Two changes to the same data met at once, and one was stopped.",
            "Try again. If it keeps happening, wait for any sync that is running to finish.")
D500 = Code("D500", 500, "A database query failed.",
            "Try again. If it happens again, report the code, the reference and the time: the reference "
            "finds the error in TIDE's log.")
D503 = Code("D503", 503, "A database file is locked by another program.",
            "Something else has TIDE's database open: a second TIDE on the same data folder, or a DuckDB tool on "
            "the host. Stop it, then try again. If nothing else is running, restart TIDE (docker compose "
            "restart tide-app).")
D507 = Code("D507", 507, "The disk TIDE keeps its data on is full.",
            "Free space on the data volume (the guide's Operations page, Reclaiming disk space), then try again.")
D560 = Code("D560", 503, "A database stopped after a DuckDB fatal error, so TIDE restarted to open it afresh.",
            "Usually nothing: wait a minute, then try again, as the restart repairs it. Settings → Diagnostics "
            "shows the error.")
D561 = Code("D561", 503, "A database stopped again soon after TIDE restarted for it, so TIDE didn't restart again.",
            "Restart TIDE (docker compose restart tide-app). If it happens again, back up the data folder and "
            "report it. Settings → Diagnostics shows the error.")
D562 = Code("D562", 500, "A database doesn't match this version of TIDE: a table or column it needs is missing.",
            "Restart TIDE (docker compose restart tide-app) so its upgrades run. If it happens again, run "
            "Settings → Diagnostics → Run all checks and report the result with the code and reference.")
D563 = Code("D563", None, "A database upgrade failed while TIDE was starting.",
            "Report the log from startup (docker compose logs tide-app). Don't delete the database: to go back, "
            "restore the backup taken before the upgrade (the guide's Operations page, Restore a backup).")
D565 = Code("D565", None, "The bundled reference database (MITRE ATT&CK, NIST 800-53, the Sigma and Elastic rule "
            "libraries) couldn't be opened.",
            "Restart TIDE. If it happens again, recreate its container (docker compose up -d --force-recreate "
            "tide-app), which puts the file back from the image.")
D566 = Code("D566", 503, "A database ran out of memory.",
            "Give TIDE's container more memory, or do the work for fewer clients or rules at a time, then try "
            "again.")

# ── S: SIEMs ────────────────────────────────────────────────────────────
_SIEM_DIALOG = "the SIEM's dialog (Settings → Management → Integrations)"
S401 = Code("S401", 502, "The SIEM didn't accept TIDE's API key, user or password.",
            f"Check it with Test connection in {_SIEM_DIALOG}, and enter it again if it has changed or expired.",
            upstream=True)
S403 = Code("S403", 502, "The SIEM accepted TIDE's key, but the key isn't allowed to do this.",
            "Give the key the privileges the guide lists (Setting up clients → The Elastic API key; for Wazuh, "
            "Configuration → Wazuh), then Test connection.", upstream=True)
S404 = Code("S404", 502, "The SIEM has no such space (for Wazuh, no such agent group).",
            "Check the destination's space on the client's page, or link the destination again.", upstream=True)
S495 = Code("S495", 502, "TIDE didn't trust the SIEM's certificate.",
            f"Install the CA certificate that signed it, or untick Verify TLS certificate in {_SIEM_DIALOG}. "
            "Configuration → When a certificate is refused says how.", upstream=True)
S502 = Code("S502", 502, "The SIEM answered with an error, or with something TIDE can't read.",
            "Check the SIEM is working, then try again. If it keeps happening, report the code and the message.",
            upstream=True)
S503 = Code("S503", 502, "The SIEM couldn't be reached: the connection was refused or timed out, or its address "
            "doesn't resolve.",
            f"Check the SIEM's address in {_SIEM_DIALOG} and that TIDE's network can reach it, then Test "
            "connection.", upstream=True)
S504 = Code("S504", 502, "The SIEM accepted the connection but didn't answer in time.",
            "It is up but slow: try again later. If it is always slow, check how busy the SIEM is.", upstream=True)

# ── A: access ───────────────────────────────────────────────────────────
A401 = Code("A401", 401, "You aren't signed in, or your session has ended; or an API key is missing or not valid.",
            "Sign in again. For the External Query API, check the X-TIDE-API-KEY header, or create a new key.")
A403 = Code("A403", 403, "You aren't allowed to do that: your role doesn't allow it, or you have no access to "
            "this client.",
            "Ask an admin of the client for the role or the access you need.")
_KEYCLOAK_DIALOG = "the Keycloak integration (Settings → Management → Integrations)"
A460 = Code("A460", 502, "Keycloak didn't accept TIDE's settings: its realm, client id or client secret.",
            f"Correct them in {_KEYCLOAK_DIALOG}, then Test connection. Configuration → Single sign-on with "
            "Keycloak says what they should be.", upstream=True)
A495 = Code("A495", 502, "TIDE didn't trust Keycloak's certificate.",
            f"Install the CA certificate that signed it, or untick Verify TLS certificate in {_KEYCLOAK_DIALOG}.",
            upstream=True)
A502 = Code("A502", 502, "Keycloak answered with an error, or with something TIDE can't read.",
            "Check Keycloak is working, then sign in again. If it keeps happening, report the code and the time.",
            upstream=True)
A503 = Code("A503", 502, "Keycloak couldn't be reached: the connection was refused or timed out, or its address "
            "doesn't resolve.",
            f"Check Keycloak is running, and its address in {_KEYCLOAK_DIALOG}. Signing in with a TIDE password "
            "still works.", upstream=True)
A504 = Code("A504", 502, "Keycloak accepted the connection but didn't answer in time.",
            "It is up but slow: sign in again in a minute.", upstream=True)

# ── I: integrations ─────────────────────────────────────────────────────
I401 = Code("I401", 502, "GitLab or OpenCTI didn't accept TIDE's token.",
            "Make a new token, put it in the GitLab project's or the OpenCTI connector's dialog, and test it.",
            upstream=True)
I403 = Code("I403", 502, "GitLab or OpenCTI accepted the token, but it isn't allowed to do this.",
            "Give the token the role the guide lists (Setting up clients → Link GitLab projects), then test it.",
            upstream=True)
I404 = Code("I404", 502, "The GitLab project isn't there, or the token can't see it.",
            "Check the project's path on the client's page, or link the project again.", upstream=True)
I495 = Code("I495", 502, "TIDE didn't trust GitLab's or OpenCTI's certificate.",
            "Install the CA certificate that signed it, or untick Verify TLS certificate in its dialog. "
            "Configuration → When a certificate is refused says how.", upstream=True)
I502 = Code("I502", 502, "GitLab or OpenCTI answered with an error, or with something TIDE can't read.",
            "Check it is working, then try again. If it keeps happening, report the code and the message.",
            upstream=True)
I503 = Code("I503", 502, "GitLab or OpenCTI couldn't be reached: the connection was refused or timed out, or its "
            "address doesn't resolve.",
            "Check its address in its dialog and that TIDE's network can reach it, then test it.", upstream=True)
I504 = Code("I504", 502, "GitLab or OpenCTI accepted the connection but didn't answer in time.",
            "It is up but slow: try again later.", upstream=True)

_ORDER = {letter: i for i, (letter, _, _) in enumerate(PREFIXES)}
CODES: Dict[str, Code] = {c.code: c for c in sorted((v for v in list(globals().values()) if isinstance(v, Code)),
                                                    key=lambda c: (_ORDER[c.code[0]], c.code))}

_BY_STATUS = {400: T400, 401: A401, 403: A403, 404: T404, 409: T409, 422: T422}


def for_status(status: int) -> Code:
    """The code for an HTTP refusal TIDE raised with only a status."""
    return _BY_STATUS.get(status) or (T500 if status >= 500 else T400)


class TideError(Exception):
    """A failure with its code. ``message`` says what went wrong for the person; without one, the code's
    title does."""

    def __init__(self, code: Code, message: Optional[str] = None):
        super().__init__(message or code.title)
        self.code = code
        self.message = message or code.title


_LOCK = re.compile(r"\block")        # "Could not set lock", "locked"; never "block"
_MISSING_COLUMN = ("does not have a column", "Referenced column")


def _database_code(exc: duckdb.Error) -> Code:
    """A DuckDB error's code: by its class, and by its message only to tell apart failures of one class
    that have different fixes."""
    text = str(exc)
    if isinstance(exc, duckdb.IOException):
        return D503 if _LOCK.search(text) else D507 if "No space left" in text else D500
    if isinstance(exc, duckdb.TransactionException) and "Conflict" in text:
        return D409
    if isinstance(exc, duckdb.OutOfMemoryException):
        return D566
    if isinstance(exc, duckdb.CatalogException) and "does not exist" in text:
        return D562
    if isinstance(exc, duckdb.BinderException) and any(m in text for m in _MISSING_COLUMN):
        return D562
    return D500


def classify(exc: Optional[BaseException]) -> Code:
    """The code for ``exc``: by its class, then by what caused it (``raise … from``, or an exception
    raised while handling another), else T500."""
    from app.services import db_fatal
    from app.services.credentials import CredentialUnreadable
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        if isinstance(exc, TideError):
            return exc.code
        if isinstance(exc, FailureError):
            return exc.code
        if isinstance(exc, HTTPException):
            return for_status(exc.status_code)
        if isinstance(exc, RequestValidationError):
            return T422
        if isinstance(exc, CredentialUnreadable):
            return T461
        if db_fatal.is_fatal(exc):
            return D560
        if isinstance(exc, duckdb.Error):
            return _database_code(exc)
        exc = exc.__cause__ or exc.__context__
    return T500


_CODE_IN_TEXT = re.compile(r"\b([TDSAI][45]\d\d)\b")


def first_code(text: str) -> Optional[Code]:
    """The first error code a message TIDE wrote names ("Not reached: Prod (refused, S503)" → S503)."""
    return next((CODES[m] for m in _CODE_IN_TEXT.findall(text or "") if m in CODES), None)


def without_code(text: str, code: Optional[Code]) -> str:
    """``with_code``'s text without its code at the end, for a sentence that names the code itself."""
    text = str(text or "")
    for end in (f" ({code}).", f" ({code})"):
        if code and text.endswith(end):
            return text[:-len(end)] + ("." if end.endswith(".") else "")
    return text


def with_code(text: str, code: Code) -> str:
    """``text`` ending with its code: "Connection refused (S503)", "… on the client's page (I401)."."""
    text = " ".join(str(text or code.title).split())
    return f"{text[:-1]} ({code})." if text.endswith(".") else f"{text} ({code})"


class Failure(str):
    """Why a request to another system failed, as TIDE words it, ending with its code: a string wherever
    a reason is kept or shown ("Connection refused (S503)"), with ``code`` and ``why`` (the words alone)."""

    code: Code
    why: str

    def __new__(cls, code: Code, why: str) -> "Failure":
        text = super().__new__(cls, with_code(why, code))
        text.code, text.why = code, why
        return text


class FailureError(Exception):
    """Another system refused or didn't answer (GitLabError, WazuhError, OpenCTIError): ``code``, and
    ``why`` in TIDE's words; its text ends with the code."""

    def __init__(self, failure: Failure):
        self.code, self.why = failure.code, failure.why
        super().__init__(str(failure))


_ORIGINS = {
    # letter: (certificate refused, not reached, too slow, answered with an error, {its status: code})
    "S": (S495, S503, S504, S502, {401: S401, 403: S403, 404: S404}),
    "A": (A495, A503, A504, A502, {401: A460, 404: A460}),
    "I": (I495, I503, I504, I502, {401: I401, 403: I403, 404: I404}),
}
_NO_NAME = ("Name or service not known", "nodename nor servname", "Temporary failure in name resolution",
            "No address associated with hostname", "getaddrinfo failed", "NameResolutionError")


def answer_code(origin: str, status: int) -> Code:
    """The code for another system's answer with HTTP ``status`` (``origin``: "S" a SIEM, "A" Keycloak,
    "I" GitLab or OpenCTI): 401, 403 and 404 as themselves (Keycloak's 401 and 404 are TIDE's settings
    for it, A460), anything else S502 / A502 / I502."""
    *_, answered, by_status = _ORIGINS[origin]
    return by_status.get(status) or answered


def connection_failure(origin: str, what: str, exc: BaseException, read_timeout=None) -> Failure:
    """Why a request to ``what`` ("Kibana", "The Wazuh manager", "GitLab") raised instead of answering:
    a certificate TIDE didn't trust; no connection (refused, timed out, or a name that doesn't resolve);
    or an answer that didn't come in time (``read_timeout`` seconds, when known). For requests and httpx."""
    import httpx
    import requests
    from app.services import tls
    certificate, down, slow, answered, _ = _ORIGINS[origin]
    cert = tls.describe_error(exc)
    if cert:
        return Failure(certificate, cert)
    if isinstance(exc, (requests.exceptions.ConnectTimeout, httpx.ConnectTimeout)):
        return Failure(down, "Connection timed out")
    if isinstance(exc, (requests.exceptions.ReadTimeout, httpx.TimeoutException)):
        # Also raised when TLS never starts (after the connect timeout): no number of seconds without one.
        return Failure(slow, f"{what} accepted the connection but did not answer "
                             + (f"within {read_timeout}s" if read_timeout else "in time"))
    if isinstance(exc, (requests.exceptions.ConnectionError, httpx.ConnectError)):
        if any(n in _chain_text(exc) for n in _NO_NAME):
            return Failure(down, "The host name doesn't resolve")
        return Failure(down, "Connection refused")
    return Failure(answered, f"{what} couldn't be read ({type(exc).__name__})")


def _chain_text(exc: Optional[BaseException]) -> str:
    """The text of ``exc`` and of everything that caused it."""
    out, seen = [], set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        out.append(f"{type(exc).__name__}: {exc}")
        exc = exc.__cause__ or exc.__context__
    return " | ".join(out)


def reason(exc: BaseException, code: Code) -> str:
    """What a person is told went wrong. TIDE's own words (a TideError's, a refusal's detail) as they
    are; anything else gets the code's title, as an exception's own text can hold SQL, file paths or
    another system's answer: that goes to the log only."""
    if isinstance(exc, TideError):
        return exc.message
    if isinstance(exc, HTTPException) and isinstance(exc.detail, str) and exc.detail.strip():
        return exc.detail
    if isinstance(exc, FailureError):
        return exc.why
    return code.title


# Names a reason may start with, which keep their capital after "Could not complete that:".
_NAMES = {"Elastic", "Elasticsearch", "Kibana", "Wazuh", "GitLab", "OpenCTI", "Keycloak", "Sigma", "DuckDB",
          "Nessus", "Splunk", "Sentinel", "MITRE", "Settings", "Diagnostics", "Management"}


def _why(text: str) -> str:
    """A reason as the part of a sentence after "Could not complete that:": its first word lower-cased
    when it is an ordinary word ("Rule not found" → "rule not found"; "SIEM …", "Kibana …" as they are)."""
    text = " ".join(str(text or "").split()).rstrip(" .")
    first = text.split(" ", 1)[0]
    if first and (first[1:].islower() or len(first) == 1) and first[0].isupper() and first not in _NAMES \
            and not text.startswith("Could not "):
        text = text[0].lower() + text[1:]
    return text


def invalid_fields(problems) -> str:
    """A request's validation problems (FastAPI's list) as a reason: what is missing or not valid."""
    fields = sorted({str(p["loc"][-1]) for p in problems if p.get("loc")})
    if not fields:
        return T422.title
    return f"{', '.join(fields)} {'is' if len(fields) == 1 else 'are'} missing or not valid"


def sentence(why: str, code: Code, reference: Optional[str] = None) -> str:
    """The failure as TIDE words one, ending with its code: "Could not complete that: <why> (T404)."
    With a reference (a request id), it says that too, to find the error in the log."""
    why = _why(why) or _why(code.title)
    tag = code.code + (f", reference {reference}" if reference else "")
    return f"{why} ({tag})." if why.startswith("Could not ") else f"Could not complete that: {why} ({tag})."


def _failure_of(exc: BaseException, origin: Optional[str], what: str) -> Optional[Failure]:
    """With the system a request went to (``origin`` "S", "A" or "I", ``what`` "Kibana"), a request
    that raised as ``connection_failure`` words it; else None."""
    import httpx
    import requests
    if origin and isinstance(exc, (requests.RequestException, httpx.HTTPError)):
        return connection_failure(origin, what or "It", exc)
    return None


def could_not(doing: str, exc: BaseException, origin: Optional[str] = None, what: str = "") -> str:
    """A failure TIDE didn't expect while ``doing`` ("test the connection"), as the sentence a person
    reads: "Could not <doing>: <why> (CODE, reference …).", in the code's words or TIDE's own, never the
    exception's text, which goes to the log with its traceback (a refusal with a 4xx code isn't logged).
    When the work was a request to another system (``origin``, ``what``: "S", "Kibana"), one that
    raised says why, as connection_failure does ("Connection refused (S503)"). The reference, which finds
    the log line, comes with a 5xx code of TIDE's own: another system's code says what to do already."""
    from app.services.log_context import error_log, get_context
    failure = _failure_of(exc, origin, what)
    code = failure.code if failure else classify(exc)
    failed = (code.status or 500) >= 500
    if failed or not isinstance(exc, TideError):
        first = (str(exc).strip().splitlines() or [""])[0][:200]
        error_log(f"Could not {doing} ({code}): {type(exc).__name__}" + (f": {first}" if first else ""),
                  exc=exc, code=code)
    ref = get_context().get("request_id")
    why = failure.why if failure else reason(exc, code)
    return sentence(f"Could not {doing}: {_why(why)}", code,
                    ref if failed and not code.upstream and ref not in (None, "-") else None)


def could_not_alert(doing: str, exc: BaseException, origin: Optional[str] = None, what: str = "") -> str:
    """``could_not`` as a failure in the page (alert alert-danger), which app.js reads for the toast."""
    failure = _failure_of(exc, origin, what)
    return snippet(could_not(doing, exc, origin, what), failure.code if failure else classify(exc))


def request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "-")


def error_headers(code: Code, request: Request) -> Dict[str, str]:
    return {"X-TIDE-Error-Code": code.code, "X-TIDE-Error-Id": request_id(request)}


def wants_json(request: Request) -> bool:
    """Whether to answer a failure in JSON: the External Query API, a caller that asks for it, and a
    tool calling TIDE's API (curl, a script), which sends no Fetch Metadata where a browser always
    does. A browser's own requests get HTML, which every page script can show."""
    path = request.url.path
    if path.startswith("/api/external") or "application/json" in request.headers.get("accept", ""):
        return True
    return path.startswith("/api/") and "sec-fetch-mode" not in request.headers and not request.headers.get("HX-Request")


def is_page(request: Request) -> bool:
    """Whether the failed request was a browser opening a page (so it gets a page of its own)."""
    path = request.url.path
    return (request.method == "GET" and not path.startswith(("/api/", "/static/"))
            and not request.headers.get("HX-Request") and "text/html" in request.headers.get("accept", ""))


def snippet(message: str, code: Code) -> str:
    """A failure in the page (alert alert-danger). app.js reads it for the toast."""
    return f'<div class="alert alert-danger" role="alert" data-tide-error="{code.code}">{escape(message)}</div>'


def bare_page(request: Request, code: Code, why: str, status: int) -> HTMLResponse:
    """A failure as a page of its own when TIDE's page can't be drawn."""
    ref = request_id(request)
    title = " ".join(str(why or code.title).split()).rstrip(" .")
    resp = HTMLResponse(
        f"<h1>{escape(title)}</h1><p>{escape(code.fix)}</p>"
        f"<p>Error {code.code}" + (f", reference <code>{escape(ref)}</code>" if ref != "-" else "") + "</p>",
        status_code=status)
    resp.headers.update(error_headers(code, request))
    return resp


def _message(request: Request, code: Code, why: str, status: int) -> str:
    ref = request_id(request)
    return sentence(why, code, ref if status >= 500 and not code.upstream and ref != "-" else None)


def json_response(request: Request, code: Code, why: str, status: Optional[int] = None, *, detail: Any = None,
                  **fields: Any) -> JSONResponse:
    """A failure in JSON: ``detail`` (``why``, or the refusal's own detail as it always was), ``code``,
    ``message`` (the sentence to show a person) and ``request_id``, plus any ``fields``."""
    status = status or code.status or 500
    resp = JSONResponse({"detail": why if detail is None else detail, **fields, "code": code.code,
                         "message": _message(request, code, why, status), "request_id": request_id(request)},
                        status_code=status)
    resp.headers.update(error_headers(code, request))
    return resp


def response(request: Request, code: Code, why: str, status: Optional[int] = None, *, detail: Any = None,
             headers: Optional[Dict[str, str]] = None, page=None) -> Response:
    """A failed request's answer: JSON (``wants_json``), a page (``is_page``: ``page(request, code, why,
    status)``, else ``bare_page``), or the failure as a line for the page (``snippet``), with the code
    and request id in X-TIDE-Error-Code and X-TIDE-Error-Id. A 5xx's message says the reference.
    ``detail`` is the JSON's ``detail`` when it isn't ``why`` (a refusal's own detail, kept as it was)."""
    status = status or code.status or 500
    if wants_json(request):
        resp: Response = json_response(request, code, why, status, detail=detail)
    elif is_page(request):
        resp = (page or bare_page)(request, code, why, status)
    else:
        resp = HTMLResponse(snippet(_message(request, code, why, status), code), status_code=status)
    resp.headers.update({**(headers or {}), **error_headers(code, request)})
    return resp
