import os
from typing import Dict, List

import httpx
from fastapi import HTTPException

from utils.logger import logger

from .base import StreamingService


class MediaFusionService(StreamingService):
    def __init__(self):
        self.base_url = "https://mediafusion.elfhosted.com"
        # Generate a MediaFusion URL, then copy the data between https://mediafusion.elfhosted.com/ and /manifest.json
        self.options = os.getenv("MEDIAFUSION_OPTIONS")

    @property
    def name(self) -> str:
        return "MediaFusion"

    async def _fetch_from_mediafusion(self, url: str) -> Dict:
        async with httpx.AsyncClient(timeout=15) as client:
            try:
                response = await client.get(url)
                response.raise_for_status()
                data = response.json()
                logger.debug(f"MediaFusion response: {data}")
                return data
            except httpx.HTTPError as e:
                logger.error(f"MediaFusion request failed: {str(e)}")
                raise HTTPException(status_code=502, detail="Upstream service error")

    async def get_streams(self, meta_id: str) -> List[Dict]:
        url = f"{self.base_url}/{self.options}/stream/{meta_id}"
        logger.debug(f"MediaFusion stream url: {url}")
        data = await self._fetch_from_mediafusion(url)
        streams = data.get("streams", [])
        for stream in streams:
            stream["service"] = self.name

            if "⚡" in stream["name"]:
                stream["is_cached"] = True

        return streams
