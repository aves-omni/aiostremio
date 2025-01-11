import asyncio
import json
import os
from typing import Dict, List

from services.base import StreamingService
from utils.logger import logger


class ServiceManager:
    def __init__(self, services: List[StreamingService]):
        self.all_services = services
        self.users_file = "db/users.json"

    def _get_user_services(self, user: str) -> List[str]:
        """Get list of enabled service names for a user"""
        if not os.path.exists(self.users_file):
            return []
            
        with open(self.users_file, "r") as f:
            users = json.load(f)
            
        if user not in users:
            return []
            
        return users[user].get("enabled_services", [])

    async def fetch_all_streams(self, meta_id: str, user: str = None) -> List[Dict]:
        """Fetch streams from all services concurrently."""
        service_streams_list = await asyncio.gather(
            *[
                self._fetch_service_streams(service, meta_id)
                for service in self.all_services
            ]
        )

        return self._process_streams(service_streams_list)

    async def _fetch_service_streams(
        self, service: StreamingService, meta_id: str
    ) -> List[Dict]:
        """Fetch streams from a single service with error handling."""
        try:
            streams = await service.get_streams(meta_id)
            for stream in streams:
                stream["service"] = service.name
            return streams
        except Exception as e:
            error_message = f"Error fetching streams from {service.name}:\n{str(e)}"
            logger.error(error_message)
            return [
                {
                    "name": "Error",
                    "title": f"""❌ {service.name}: {str(e)}""",
                    "url": "https://example.com/",
                    "service": service.name
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

        # Add WatchHub streams first
        if "WatchHub" in service_streams_map:
            all_streams.extend(service_streams_map.pop("WatchHub"))

        # First interleave cached streams
        while any(service_streams_map.values()):
            found_cached = False
            for service_name in list(service_streams_map.keys()):
                streams = service_streams_map[service_name]
                if streams and streams[0].get("is_cached", False):
                    found_cached = True
                    all_streams.append(streams.pop(0))
                if not streams:
                    del service_streams_map[service_name]
            if not found_cached:
                break

        # Then interleave remaining uncached streams
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
        return [service.name for service in self.all_services]
