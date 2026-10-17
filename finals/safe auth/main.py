
from dataclasses import dataclass
from typing import Callable

import anyio
import anyio.abc
import os
import secrets

import logging
logger = logging.getLogger(__name__)


FLAG = os.environ.get("FLAG", "ECSC{testflag}")
SECRET = secrets.token_hex(32)


type AuthCallback = Callable[[HTTPRequest], bool]
type RequestCallback = Callable[[], HTTPResponse]


HTTPStatusNames = {
    200: "OK",
    403: "Forbidden",
    404: "Not Found",
    500: "Internal Server Error"
}


@dataclass
class HTTPRequest:
    method: str
    path: str
    headers: dict[str, str]


@dataclass
class HTTPResponse:
    status_code: int
    body: str = ""
    
    def encode(self) -> bytes:
        status_name = HTTPStatusNames[self.status_code]

        headers = {
            "Content-Type": "text/plain",
            "Content-Length": len(self.body)
        }

        lines = [f"HTTP/1.1 {self.status_code} {status_name}"]
        for key, value in headers.items():
            lines.append(f"{key}: {value}")

        text = "\r\n".join(lines) + "\r\n\r\n" + self.body
        return text.encode()


class HTTPClient:
    _stream: anyio.abc.SocketStream
    _buffer: bytes

    def __init__(self, stream: anyio.abc.SocketStream):
        self._stream = stream
        self._buffer = b""
    
    async def receive_headers(self) -> HTTPRequest:
        line = await self._receive_line()
        parts = line.split()
        method, path = parts[0], parts[1]

        headers: dict[str, str] = {}
        while True:
            line = await self._receive_line()
            if not line:
                break

            key, value = line.split(":", maxsplit=1)
            headers[key.strip().lower()] = value.strip()
        
        return HTTPRequest(method, path, headers)

    async def receive_body(self, request: HTTPRequest) -> bytes:
        content_length = int(request.headers.get("content-length", 0))
        return await self._receive_raw(content_length)

    async def send_response(self, response: HTTPResponse) -> None:
        await self._stream.send(response.encode())

    async def _receive_line(self) -> str:
        while b"\r\n" not in self._buffer:
            self._buffer += await self._stream.receive()

        line, self._buffer = self._buffer.split(b"\r\n", maxsplit=1)
        return line.decode()

    async def _receive_raw(self, size: int) -> bytes:
        while len(self._buffer) < size:
            self._buffer += await self._stream.receive()

        body = self._buffer[:size]
        self._buffer = self._buffer[size:]
        return body


class Server:
    _auth_ok: bool
    _handlers: dict[tuple[str, str], tuple[AuthCallback, RequestCallback]]

    def __init__(self):
        self._auth_ok = False

        self._handlers = {
            ("GET", "/status"): (self._auth_none, self._handle_status),
            ("GET", "/flag"): (self._auth_admin, self._handle_flag),
        }

    def _cleanup(self) -> None:
        self._auth_ok = False
    
    async def run(self) -> None:
        listener = await anyio.create_tcp_listener(
            local_host = "0.0.0.0", local_port = 80
        )
        async with listener:
            logger.info("Server will now be started")
            await listener.serve(self._accept_client)

    async def _accept_client(self, stream: anyio.abc.SocketStream) -> None:
        async with stream:
            try:
                client = HTTPClient(stream)
                await self._handle_client(client)
            except Exception:
                pass
            self._cleanup()

    async def _handle_client(self, client: HTTPClient) -> None:
        self._cleanup()

        request = await client.receive_headers()
        try:
            response = await self._handle_request(client, request)
        except Exception:
            response = HTTPResponse(500, "Internal Server Error")
        
        await client.send_response(response)

    async def _handle_request(
        self, client: HTTPClient, request: HTTPRequest
    ) -> HTTPResponse:
        request_key = (request.method, request.path)
        if request_key not in self._handlers:
            await client.receive_body(request)
            return HTTPResponse(404, "Not Found")

        authenticator, handler = self._handlers[request_key]
        self._auth_ok = authenticator(request)
        await client.receive_body(request)

        if not self._auth_ok:
            return HTTPResponse(403, "Forbidden")
        
        return handler()

    def _handle_status(self) -> HTTPResponse:
        return HTTPResponse(200, "The server is up!")

    def _handle_flag(self) -> HTTPResponse:
        return HTTPResponse(200, FLAG)

    def _auth_none(self, request: HTTPRequest) -> bool:
        return True

    def _auth_admin(self, request: HTTPRequest) -> bool:
        return request.headers.get("x-admin") == SECRET


async def main() -> None:
    server = Server()
    await server.run()


anyio.run(main)
