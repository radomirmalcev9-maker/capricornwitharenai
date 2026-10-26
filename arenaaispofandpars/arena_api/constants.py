"""Public protocol defaults.

Arena's frontends are not a stable API. These values describe common Gradio
routes and may need to be overridden for a deployment you are authorized to
use.
"""

from __future__ import annotations

DEFAULT_BASE_URL = "https://arena.ai"
DEFAULT_TIMEOUT = 45.0
DEFAULT_QUEUE_TIMEOUT = 180.0

# Be transparent about this being a library client. Callers may supply their own
# static headers when a deployment requires additional request context.
DEFAULT_HEADERS: dict[str, str] = {
    "accept": "text/event-stream, application/json, text/plain, */*",
    "user-agent": "arena-api/0.2.0",
}

CONFIG_PATH = "/config"
QUEUE_JOIN_PATH = "/queue/join"
QUEUE_DATA_PATH = "/queue/data"

# Unofficial Direct Chat routes observed in the Next.js frontend. They are
# deliberately isolated from the Gradio adapter because the frontend protocol
# can change without notice.
DIRECT_PAGE_PATH = "/text/direct?model_a=max"
DIRECT_STREAM_PATH = "/nextjs-api/stream/create-evaluation"
