import base64
import os
from typing import Dict, List

import httpx
from fastapi import HTTPException

from utils.config import config
from utils.logger import logger

from .base import StreamingService


class CometService(StreamingService):
    def __init__(self):
        self.base_url = config.get("addon_config", "comet", "base_url")
        self.debrid_api_key = config.get_addon_debrid_api_key("comet")
        self.debrid_service = config.get_addon_debrid_service("comet")
        self.options = f"""{{
            "indexers": ["bitsearch", "eztv", "thepiratebay", "therarbg", "yts"],
            "maxResults": 0,
            "maxResultsPerResolution": 0,
            "maxSize": 0,
            "reverseResultOrder": false,
            "removeTrash": true,
            "resultFormat": ["All"],
            "resolutions": ["All"], 
            "languages": ["All"],
            "debridService": "{self.debrid_service}",
            "debridApiKey": "{self.debrid_api_key}",
            "stremthruUrl": "",
            "debridStreamProxyPassword": ""
        }}"""
        self.options_encoded = base64.b64encode(self.options.encode()).decode("utf-8")

    @property
    def name(self) -> str:
        return "Comet"

    async def _fetch_from_comet(self, url: str) -> Dict:
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(url)
                response.raise_for_status()
                data = response.json()
                logger.debug(f"Comet response: {data}")
                return data
            except httpx.HTTPError as e:
                logger.error(f"Comet request failed: {str(e)}")
                raise HTTPException(status_code=502, detail="Upstream service error")

    async def get_streams(self, meta_id: str) -> List[Dict]:
        url = f"{self.base_url}/{self.options_encoded}/stream/{meta_id}"
        logger.debug(f"Comet stream url: {url}")
        data = await self._fetch_from_comet(url)
        streams = data.get("streams", [])
        for stream in streams:
            stream["service"] = self.name

            stream_name = stream.get("name", "")
            if stream_name.startswith("["):
                prefix = stream_name[1:stream_name.find("]")] if "]" in stream_name else ""
                stream["is_cached"] = "⚡" in prefix
            else:
                stream["is_cached"] = True

        return streams
