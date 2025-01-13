import base64
import os
from typing import Dict, List

import httpx
from fastapi import HTTPException

from utils.config import config
from utils.logger import logger

from .base import StreamingService


class PeerflixService(StreamingService):
    def __init__(self):
        self.base_url = "https://peerflix-addon.onrender.com"
        self.debrid_api_key = config.get_addon_debrid_api_key("peerflix")
        self.debrid_service = config.get_addon_debrid_service("peerflix")
        self.options = f'language=en,es|debridoptions=nocatalog,nodownloadlinks|{self.debrid_service}={self.debrid_api_key}|sort=quality-desc'

    @property
    def name(self) -> str:
        return "Peerflix"

    async def _fetch_from_peerflix(self, url: str) -> Dict:
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(url)
                response.raise_for_status()
                data = response.json()
                logger.debug(f"Peerflix response: {data}")
                return data
            except httpx.HTTPError as e:
                logger.error(f"Peerflix request failed: {str(e)}")
                raise HTTPException(status_code=502, detail="Upstream service error")

    async def get_streams(self, meta_id: str) -> List[Dict]:
        url = f"{self.base_url}/{self.options}/stream/{meta_id}"
        logger.debug(f"Peerflix stream url: {url}")
        data = await self._fetch_from_peerflix(url)
        streams = data.get("streams", [])
        for stream in streams:
            stream["service"] = self.name

            # Peerflix streams are always cached
            stream["is_cached"] = True

        return streams
