import os
from typing import Dict, List

import httpx
from fastapi import HTTPException

from utils.config import config
from utils.logger import logger

from .base import StreamingService


class TorrentioService(StreamingService):
    def __init__(self):
        self.base_url = "https://torrentio.strem.fun"
        self.debrid_api_key = config.get_addon_debrid_api_key("torrentio")
        self.debrid_service = config.get_addon_debrid_service("torrentio")
        self.options = f"debridoptions=nocatalog|{self.debrid_service}={self.debrid_api_key}"

    @property
    def name(self) -> str:
        return "Torrentio"

    async def _fetch_from_torrentio(self, url: str) -> Dict:
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(url)
                response.raise_for_status()
                data = response.json()
                logger.debug(f"Torrentio response: {data}")
                return data
            except httpx.HTTPError as e:
                logger.error(f"Torrentio request failed: {str(e)}")
                raise HTTPException(status_code=502, detail="Upstream service error")

    async def get_streams(self, meta_id: str) -> List[Dict]:
        url = f"{self.base_url}/{self.options}/stream/{meta_id}"
        logger.debug(f"Torrentio stream url: {url}")
        data = await self._fetch_from_torrentio(url)
        streams = data.get("streams", [])
        for stream in streams:
            stream["service"] = self.name

            stream_name = stream.get("name", "")
            if stream_name.startswith("["):
                prefix = stream_name[1:stream_name.find("]")] if "]" in stream_name else ""
                stream["is_cached"] = "+" in prefix
            else:
                stream["is_cached"] = True

        return streams
