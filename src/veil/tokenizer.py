"""bigip.conf tokenizer — byte-precise, quote-aware, brace-aware.

Produces a stream of :class:`Token` carrying ``(kind, value, offset,
length, line)``. Designed to round-trip: re-emitting each token's
``src[offset:offset+length]`` in order reconstructs the original input
exactly (minus the whitespace and newlines between tokens, which the
caller can recover from offset arithmetic).

Not in scope for v0.1:
- Tcl-aware lexing inside ``ltm rule`` bodies. The body is delivered as
  a sequence of normal tokens; pass-2 substitution treats it as a
  byte stream rather than a Tcl AST.
- TMSH macros, include directives, or non-bigip.conf file shapes.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterator


class TokKind(str, Enum):
    LBRACE = "LBRACE"
    RBRACE = "RBRACE"
    WORD = "WORD"
    QSTRING = "QSTRING"
    COMMENT = "COMMENT"


@dataclass(frozen=True)
class Token:
    kind: TokKind
    value: str
    offset: int
    length: int
    line: int


def tokenize(src: str) -> Iterator[Token]:
    n = len(src)
    i = 0
    line = 1
    while i < n:
        c = src[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        if c.isspace():
            i += 1
            continue
        if c == "#":
            start = i
            start_line = line
            while i < n and src[i] != "\n":
                i += 1
            yield Token(TokKind.COMMENT, src[start:i], start, i - start, start_line)
            continue
        if c == "{":
            yield Token(TokKind.LBRACE, "{", i, 1, line)
            i += 1
            continue
        if c == "}":
            yield Token(TokKind.RBRACE, "}", i, 1, line)
            i += 1
            continue
        if c == '"':
            start = i
            start_line = line
            i += 1
            while i < n:
                ch = src[i]
                if ch == "\\" and i + 1 < n:
                    if src[i + 1] == "\n":
                        line += 1
                    i += 2
                    continue
                if ch == "\n":
                    line += 1
                    i += 1
                    continue
                if ch == '"':
                    i += 1
                    break
                i += 1
            yield Token(TokKind.QSTRING, src[start:i], start, i - start, start_line)
            continue
        start = i
        start_line = line
        while i < n and not src[i].isspace() and src[i] not in '{}"#':
            i += 1
        yield Token(TokKind.WORD, src[start:i], start, i - start, start_line)
