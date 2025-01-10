import os
from typing import Dict, List

import httpx
from fastapi import HTTPException

from utils.logger import logger

from .base import StreamingService


class WatchHubService(StreamingService):
    def __init__(self):
        self.base_url = "https://watchhub.stkc.win"

    @property
    def name(self) -> str:
        return "WatchHub"

    async def _fetch_from_watchhub(self, url: str) -> Dict:
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(url)
                response.raise_for_status()
                data = response.json()
                logger.debug(f"WatchHub response: {data}")
                return data
            except httpx.HTTPError as e:
                logger.error(f"WatchHub request failed: {str(e)}")
                return {"streams": []}

    async def get_streams(self, meta_id: str) -> List[Dict]:
        url = f"{self.base_url}/stream/{meta_id}"
        logger.debug(f"WatchHub stream url: {url}")
        data = await self._fetch_from_watchhub(url)
        streams = data.get("streams", [])
        for stream in streams:
            stream["service"] = self.name
        return streams
