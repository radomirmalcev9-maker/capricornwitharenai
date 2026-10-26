"""Zero-configuration Direct Chat quickstart on arena.ai.

Run::

    python examples/quickstart.py
    python examples/quickstart.py "Объясни разницу между TCP и UDP."
"""

from __future__ import annotations

import sys

from arena_api import AutoOptions, auto_direct_client


def main() -> None:
    prompt = (
        " ".join(sys.argv[1:]).strip()
        or "Привет! Коротко расскажи, чем примечателен дебют Гроба в шахматах."
    )
    options = AutoOptions()
    with auto_direct_client(options, verification_token="auto") as client:
        for event in client.stream(prompt):
            if event.kind == "text" and event.text:
                sys.stdout.write(event.text)
                sys.stdout.flush()
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
