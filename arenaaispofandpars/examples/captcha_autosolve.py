"""Standalone demo of built-in zero-FFmpeg reCAPTCHA auto-solving on a test page.

Run::

    python examples/captcha_autosolve.py
"""

from __future__ import annotations

import asyncio

from arena_api.auth import (
    AUTOMATION_BLINK_SWITCH,
    AUTOMATION_DEFAULT_ARGS_TO_DROP,
    HIDE_WEBDRIVER_SCRIPT,
    BrowserEnvironment,
    BrowserEnvironmentOptions,
    auto_solve_challenge_on_page,
)

DEMO_URL = "https://www.google.com/recaptcha/api2/demo"


async def _run() -> None:
    opts = BrowserEnvironmentOptions(
        headless=False,
        locale=None,
        timezone_id=None,
        install_determinism_script=False,
        identify_automation=False,
        ignore_default_args=AUTOMATION_DEFAULT_ARGS_TO_DROP,
        launch_args=(AUTOMATION_BLINK_SWITCH,),
        extra_init_scripts=(HIDE_WEBDRIVER_SCRIPT,),
    )
    async with BrowserEnvironment(opts) as env:
        page = await env.new_page()
        await page.goto(DEMO_URL, wait_until="domcontentloaded")
        await page.wait_for_timeout(1500)
        outcome = await auto_solve_challenge_on_page(
            page,
            {"kind": "recaptcha_bframe"},
        )
        print(f"Solved={outcome.solved}, method={outcome.method}, token_len={len(outcome.token or '')}")


if __name__ == "__main__":
    asyncio.run(_run())
