import os
from typing import Dict, List

import httpx
from fastapi import HTTPException

from utils.logger import logger

from .base import StreamingService


class TorboxService(StreamingService):
    def __init__(self):
        self.base_url = "https://stremio.torbox.app"
        self.debrid_api_key = os.getenv("DEBRID_API_KEY")
        self.options = f"{self.debrid_api_key}"

    @property
    def name(self) -> str:
        return "TorBox"

    async def _fetch_from_torbox(self, url: str) -> Dict:
        async with httpx.AsyncClient(timeout=15) as client:
            try:
                response = await client.get(url)
                response.raise_for_status()
                data = response.json()
                logger.debug(f"TorBox response: {data}")
                return data
            except httpx.HTTPError as e:
                logger.error(f"TorBox request failed: {str(e)}")
                raise HTTPException(status_code=502, detail="Upstream service error")

    async def get_streams(self, meta_id: str) -> List[Dict]:
        url = f"{self.base_url}/{self.options}/stream/{meta_id}"
        logger.debug(f"TorBox stream url: {url}")
        data = await self._fetch_from_torbox(url)
        streams = data.get("streams", [])
        for stream in streams:
            stream["service"] = self.name
        return streams
