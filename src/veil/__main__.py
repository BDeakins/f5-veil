"""f5-veil package entry point. See :mod:`veil.cli` for the actual CLI."""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
