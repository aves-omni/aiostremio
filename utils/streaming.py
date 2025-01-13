import asyncio
import io
from collections import deque
from typing import AsyncGenerator, Dict

import aiohttp
from fastapi.responses import StreamingResponse

from utils.config import config
from utils.logger import logger


class StreamManager:
    def __init__(
        self,
        chunk_size: int = config.chunk_size_mb * 1024 * 1024,
        buffer_size: int = config.buffer_size_mb * 1024 * 1024,
    ):
        self.chunk_size = chunk_size
        self.buffer_size = buffer_size
        self.default_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Accept": "*/*",
            "Connection": "keep-alive",
        }

    async def create_streaming_response(
        self, url: str, request_headers: Dict
    ) -> StreamingResponse:
        headers = self.default_headers.copy()
        if "range" in request_headers:
            headers["range"] = request_headers["range"]

        timeout = aiohttp.ClientTimeout(total=180)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, headers=headers) as response:
                content_range = response.headers.get("Content-Range", "")
                content_length = response.headers.get("Content-Length", "")
                
                response_headers = {
                    "Accept-Ranges": "bytes",
                    "Content-Range": content_range if content_range else None,
                    "Content-Length": content_length if content_length else None,
                    "Connection": "keep-alive",
                    "Cache-Control": "no-cache",
                }
                response_headers = {k: v for k, v in response_headers.items() if v is not None}
                media_type = response.headers.get("Content-Type", "video/mp4")

        return StreamingResponse(
            self._stream_content(url, headers),
            media_type=media_type,
            status_code=206 if "range" in request_headers else 200,
            headers=response_headers,
        )

    async def _stream_content(
        self, url: str, headers: Dict
    ) -> AsyncGenerator[bytes, None]:
        timeout = aiohttp.ClientTimeout(total=None, connect=120, sock_read=120)
        buffer = deque()
        current_buffer_size = 0
        buffer_low_threshold = self.buffer_size * 0.2  # 20% of buffer size

        connector = aiohttp.TCPConnector(
            limit=0,
            ttl_dns_cache=300,
            force_close=False,
            enable_cleanup_closed=True,
        )

        async with aiohttp.ClientSession(
            timeout=timeout, connector=connector
        ) as session:
            async with session.get(url, headers=headers) as response:

                async def fill_buffer():
                    nonlocal current_buffer_size
                    while True:
                        try:
                            if current_buffer_size < self.buffer_size:
                                chunk = await response.content.read(self.chunk_size)
                                if not chunk:
                                    break
                                buffer.append(chunk)
                                current_buffer_size += len(chunk)
                            else:
                                await asyncio.sleep(0.1)
                        except (asyncio.TimeoutError, aiohttp.ClientError) as e:
                            logger.error(f"Buffer filling error: {str(e)}")
                            await asyncio.sleep(1)
                            continue

                buffer_task = asyncio.create_task(fill_buffer())

                try:
                    while not buffer:
                        await asyncio.sleep(0.1)

                    while True:
                        if not buffer and current_buffer_size == 0:
                            break

                        if buffer:
                            chunk = buffer.popleft()
                            current_buffer_size -= len(chunk)
                            yield chunk

                        if current_buffer_size < buffer_low_threshold:
                            await asyncio.sleep(0.1)

                finally:
                    buffer_task.cancel()
                    try:
                        await buffer_task
                    except asyncio.CancelledError:
                        pass
