"""Sign in once in a real browser window and save cookies to state/cookies.json.

Run::

    python examples/login_save_cookies.py
"""

from __future__ import annotations

from arena_api import AutoOptions, interactive_login


def main() -> None:
    outcome = interactive_login(AutoOptions())
    print(f"Saved {len(outcome.login.cookie_names)} cookies -> {outcome.login.storage_path}")
    if outcome.verification is not None:
        print(f"Verification: {outcome.verification.describe()}")


if __name__ == "__main__":
    main()
