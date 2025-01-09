import asyncio
from typing import Dict, List

from services.base import StreamingService
from utils.logger import logger


class ServiceManager:
    def __init__(self, services: List[StreamingService]):
        self.services = services

    async def fetch_all_streams(self, meta_id: str) -> List[Dict]:
        """Fetch streams from all services concurrently and process them."""
        service_streams_list = await asyncio.gather(
            *[
                self._fetch_service_streams(service, meta_id)
                for service in self.services
            ]
        )

        return self._process_streams(service_streams_list)

    async def _fetch_service_streams(
        self, service: StreamingService, meta_id: str
    ) -> List[Dict]:
        """Fetch streams from a single service with error handling."""
        try:
            streams = await service.get_streams(meta_id)
            return streams
        except Exception as e:
            error_message = f"Error fetching streams from {service.name}:\n{str(e)}"
            logger.error(error_message)
            return [
                {
                    "name": "Error",
                    "title": f"""❌ {service.name}: {str(e)}""",
                    "url": "https://example.com/",
                }
            ]

    def _process_streams(self, service_streams_list: List[List[Dict]]) -> List[Dict]:
        """Process and organize streams from all services."""
        all_streams = []
        error_streams = []
        service_streams_map = {}

        for service_streams in service_streams_list:
            for stream in service_streams:
                if stream.get("name") == "Error":
                    error_streams.append(stream)
                else:
                    service_name = stream.get("service")
                    if service_name not in service_streams_map:
                        service_streams_map[service_name] = []
                    service_streams_map[service_name].append(stream)

        final_streams = error_streams.copy()

        if "WatchHub" in service_streams_map:
            all_streams.extend(service_streams_map.pop("WatchHub"))

        while any(service_streams_map.values()):
            for service_name in list(service_streams_map.keys()):
                if service_streams_map[service_name]:
                    all_streams.append(service_streams_map[service_name].pop(0))
                if not service_streams_map[service_name]:
                    del service_streams_map[service_name]

        final_streams.extend(all_streams)
        return final_streams

    def get_enabled_services(self) -> List[str]:
        """Get list of enabled service names."""
        return [service.name for service in self.services]
