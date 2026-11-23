"""What the words in a search box mean, the same in every search in TIDE (the searches that run in
the browser read them the same way: ``TIDE.searchMatcher`` in app.js).

- ``Suspicious PowerShell``: things holding every word, in any case, anywhere the search looks.
- ``"Suspicious PowerShell"``: quotes keep words together, and keep NOT, AND and OR plain words.
- ``NOT Suspicious`` or ``!Suspicious``: things without the word.
- ``Suspicious AND PowerShell``: the same as a space. ``PowerShell OR cmd``: either.
- Brackets group: ``Suspicious (PowerShell OR cmd)``. NOT binds tightest, then AND, then OR.

NOT, AND and OR are operators only in capitals, so a name with "and" or "not" in it is still found
by typing it. A search never fails: an operator with nothing to work on, or a bracket left open (as
while still typing), is left out.
"""
from typing import Any, Iterable, List, Optional, Tuple

_OPERATORS = ("AND", "OR", "NOT")


def _tokens(text: str) -> List[Tuple[str, str]]:
    """``(kind, value)``: a ``word`` (lower case), an ``op`` (AND, OR, NOT) or a bracket. A ``(``
    opens a group only at the start of a word, and a ``)`` closes one only while one is open, so
    ``func()`` or ``Utilities (LSASS`` stay searchable as typed."""
    out: List[Tuple[str, str]] = []
    i, n, depth = 0, len(text), 0
    while i < n:
        ch = text[i]
        if ch.isspace():
            i += 1
        elif ch == '"':
            end = text.find('"', i + 1)
            end = n if end < 0 else end
            if text[i + 1:end].strip():
                out.append(("word", text[i + 1:end].lower()))
            i = end + 1
        elif ch == "!":
            out.append(("op", "NOT"))
            i += 1
        elif ch == "(":
            out.append(("(", ""))
            depth += 1
            i += 1
        elif ch == ")" and depth:
            out.append((")", ""))
            depth -= 1
            i += 1
        else:
            j = i
            while j < n and not text[j].isspace() and text[j] != '"' and not (text[j] == ")" and depth):
                j += 1
            word = text[i:j]
            out.append(("op", word) if word in _OPERATORS else ("word", word.lower()))
            i = j
    return out


class _Parser:
    """Turns tokens into a tree: ``("word", w)``, ``("not", node)``, ``("and", [nodes])`` or
    ``("or", [nodes])``; None when nothing is left to search for."""

    def __init__(self, tokens: List[Tuple[str, str]]):
        self.tokens, self.at = tokens, 0

    def peek(self) -> Optional[Tuple[str, str]]:
        return self.tokens[self.at] if self.at < len(self.tokens) else None

    def tree(self):
        parts = []
        while self.peek():
            parts.append(self.any_of())
            if self.peek():   # a ")" with no group open: skip it
                self.at += 1
        return _joined("and", parts)

    def any_of(self):
        parts = [self.all_of()]
        while self.peek() == ("op", "OR"):
            self.at += 1
            parts.append(self.all_of())
        return _joined("or", parts)

    def all_of(self):
        parts = []
        while (tok := self.peek()) and tok[0] != ")" and tok != ("op", "OR"):
            if tok == ("op", "AND"):
                self.at += 1
            else:
                parts.append(self.one())
        return _joined("and", parts)

    def one(self):
        kind, value = self.tokens[self.at]
        self.at += 1
        if kind == "op":   # NOT: AND and OR never get here
            following = self.peek()
            if not following or following[0] == ")" or following in (("op", "AND"), ("op", "OR")):
                return None
            inner = self.one()
            return ("not", inner) if inner else None
        if kind == "(":
            inner = self.any_of()
            if self.peek() and self.peek()[0] == ")":
                self.at += 1
            return inner
        return ("word", value)


def _joined(kind: str, parts: list):
    parts = [p for p in parts if p]
    return None if not parts else parts[0] if len(parts) == 1 else (kind, parts)


def _test(node, hay: str) -> bool:
    kind, value = node
    if kind == "word":
        return value in hay
    if kind == "not":
        return not _test(value, hay)
    return (all if kind == "and" else any)(_test(n, hay) for n in value)


def _sql(node, hay: str, params: List[Any]) -> str:
    kind, value = node
    if kind == "word":
        params.append(value)
        return f"contains({hay}, ?)"
    if kind == "not":
        return f"NOT ({_sql(value, hay, params)})"
    return "(" + (" AND " if kind == "and" else " OR ").join(_sql(n, hay, params) for n in value) + ")"


def _words(node) -> List[str]:
    kind, value = node
    if kind == "word":
        return [value]
    if kind == "not":
        return []
    return [w for n in value for w in _words(n)]


def _flat(fields: Iterable[Any]) -> Iterable[str]:
    for field in fields:
        if isinstance(field, (list, tuple, set)):
            yield from _flat(field)
        elif field is not None:
            yield str(field)


class SearchQuery:
    """A search box's text, read once: ``matches`` tests some text against it, ``sql`` gives the
    same test as a WHERE condition. An empty search (or one of operators alone) matches everything."""

    def __init__(self, text: Optional[str]):
        self.text = (text or "").strip()
        self.tree = _Parser(_tokens(self.text)).tree()

    def __bool__(self) -> bool:
        return self.tree is not None

    @property
    def words(self) -> List[str]:
        """The words searched for (not those after NOT), in lower case: to rank or highlight hits."""
        return _words(self.tree) if self.tree else []

    def matches(self, *fields: Any) -> bool:
        """Whether the text of ``fields`` (strings, or lists of them; None is skipped) matches. Each
        word may be in any of the fields; a phrase must be within one."""
        if self.tree is None:
            return True
        return _test(self.tree, "\n".join(_flat(fields)).lower())

    def sql(self, *columns: str) -> Tuple[str, List[Any]]:
        """``(condition, params)`` for a WHERE clause, true for the rows whose ``columns`` (SQL
        expressions, of any type; NULL counts as empty) match: ``("TRUE", [])`` for an empty search."""
        if self.tree is None:
            return "TRUE", []
        hay = "lower(concat_ws(chr(10), " + ", ".join(f"CAST({c} AS VARCHAR)" for c in columns) + "))"
        params: List[Any] = []
        return f"({_sql(self.tree, hay, params)})", params
