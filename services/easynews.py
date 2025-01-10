import os
from typing import Dict, List

import httpx
from fastapi import HTTPException

from utils.logger import logger

from .base import StreamingService


class EasynewsService(StreamingService):
    def __init__(self):
        self.base_url = "https://ea627ddf0ee7-easynews.baby-beamup.club"
        self.username = os.getenv("EASYNEWS_USERNAME")
        self.password = os.getenv("EASYNEWS_PASSWORD")
        self.options = f"%7B%22username%22%3A%22{self.username}%22%2C%22password%22%3A%22{self.password}%22%7D"

    @property
    def name(self) -> str:
        return "Easynews"

    async def _fetch_from_easynews(self, url: str) -> Dict:
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(url)
                response.raise_for_status()
                data = response.json()
                logger.debug(f"Easynews response: {data}")
                return data
            except httpx.HTTPError as e:
                logger.error(f"Easynews request failed: {str(e)}")
                raise HTTPException(status_code=502, detail="Upstream service error")

    async def get_streams(self, meta_id: str) -> List[Dict]:
        url = f"{self.base_url}/{self.options}/stream/{meta_id}"
        logger.debug(f"Easynews stream url: {url}")
        data = await self._fetch_from_easynews(url)
        streams = data.get("streams", [])
        for stream in streams:
            stream["service"] = self.name

            # Easynews doesn't have a cache
            stream["is_cached"] = True

        return streams
