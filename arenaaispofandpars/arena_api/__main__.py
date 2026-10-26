"""``python -m arena_api`` — the zero-configuration bootstrap CLI.

Thin wrapper around :func:`arena_api.auto.main`, so the documented command does
not trip the ``RuntimeWarning`` that ``python -m arena_api.auto`` produces (the
package imports :mod:`arena_api.auto` itself). ``python -m arena_api.auto``
keeps working for anyone who already typed it.
"""

from __future__ import annotations

from .auto import main

if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
