"""Cloud Run launch adapter: permit the Pages origin to read GET /health only."""

from starlette.types import ASGIApp, Message, Receive, Scope, Send

PAGES_ORIGIN = b"https://witold-andelie.github.io"


class HealthCors:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        probe = (
            scope["type"] == "http" and scope["path"] == "/health"
            and scope["method"] == "GET"
            and (b"origin", PAGES_ORIGIN) in scope["headers"]
        )

        async def send_headers(message: Message) -> None:
            if probe and message["type"] == "http.response.start":
                message = {**message, "headers": [
                    *message.get("headers", []),
                    (b"access-control-allow-origin", PAGES_ORIGIN),
                    (b"vary", b"Origin"),
                    (b"cache-control", b"no-store"),
                ]}
            await send(message)

        await self.app(scope, receive, send_headers)


def create_app() -> HealthCors:
    from pulseguard.api import create_app as application

    return HealthCors(application())
