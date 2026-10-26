"""Third-party code vendored into this distribution.

``recaptcha_toolkit`` lives here rather than at the top level so that installing
``arena-api`` cannot collide with (or be overwritten by) a same-named project on
PyPI. Import it as::

    from arena_api._vendor import recaptcha_toolkit

Nothing in this package imports it at module scope: :mod:`arena_api.auth.captcha`
loads it lazily, so ``import arena_api`` stays dependency-free.
"""

from __future__ import annotations

__all__: list[str] = []
