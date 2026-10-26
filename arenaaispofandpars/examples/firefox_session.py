"""Inspect a local Firefox profile session and send a Direct Chat request.

Run::

    python examples/firefox_session.py
"""

from __future__ import annotations

import sys

from arena_api import AutoOptions, auto_direct_client
from arena_api.auth import FirefoxSessionManager


def main() -> None:
    manager = FirefoxSessionManager(domains=["arena.ai", ".arena.ai"])
    cookies = manager.load_cookies()
    proxy = manager.proxy_url(scheme="https", host="arena.ai")
    print(f"Profile : {manager.selected_profile}")
    print(f"Cookies : {len(cookies)} names loaded")
    print(f"Proxy   : {proxy or 'direct'}")

    options = AutoOptions(proxy=proxy)
    with auto_direct_client(options, verification_token="auto") as client:
        answer = client.complete("Назови три планеты земной группы.")
        sys.stdout.write(answer + "\n")


if __name__ == "__main__":
    main()
