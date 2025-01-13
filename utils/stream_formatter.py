from typing import List, Dict, Any
from utils.config import config
from utils.url_processor import URLProcessor
from utils.video_info import VideoInfoParser
import copy

class StreamFormatter:
    def __init__(self, url_processor: URLProcessor):
        self.url_processor = url_processor
        self.video_parser = VideoInfoParser()

    async def process_streams(self, streams: List[Dict[str, Any]], user_path: str, proxy_streams: bool, meta_id: str, username: str = None) -> List[Dict[str, Any]]:
        """Process streams with URL processing and formatting."""
        if not streams:
            return []

        regular_streams = [s for s in streams if s.get("name") != "Error"]
        streams_to_return = {"streams": copy.deepcopy(regular_streams)}
        
        await self.url_processor.process_stream_urls(
            streams_to_return["streams"], 
            user_path, 
            proxy_streams, 
            meta_id=meta_id
        )
        
        self._process_stream_formatting(streams_to_return["streams"], username)
        
        return streams_to_return["streams"]

    def filter_streams_by_services(self, streams: List[Dict[str, Any]], enabled_services: List[str]) -> List[Dict[str, Any]]:
        if not enabled_services:
            return streams
            
        return [s for s in streams if s.get("service") in enabled_services]

    def vidi_format(self, streams: List[Dict[str, Any]], username: str = None) -> None:
        for stream in streams:
            stream_name = stream.get('name', stream['service'])
            stream_name = ' '.join(stream_name.split())
            
            if 'title' in stream and stream['title']:
                stream['title'] = f"{stream_name}\n{stream['title']}"
            elif 'description' in stream and stream['description']:
                stream['description'] = f"{stream_name}\n{stream['description'].lstrip()}"
            else:
                stream['description'] = stream_name

    def simple_format(self, streams: List[Dict[str, Any]], username: str = None) -> None:
        for stream in streams:
            info = self.video_parser.parse(stream)
            formatted_info = info['formatted_description']
            
            stream['name'] = stream.get('service', 'Unknown')

            if 'title' in stream and stream['title']:
                stream['title'] = formatted_info
            elif 'description' in stream and stream['description']:
                stream['description'] = formatted_info
            else:
                stream['description'] = formatted_info

    def one_per_quality(self, streams: List[Dict[str, Any]], username: str = None) -> None:
        """Filter streams to keep only the best quality stream for each resolution.
        The best quality is determined by:
        0. Cache status (cached streams preferred)
        1. HDR presence (DV > HDR10+ > HDR10 > HDR > None)
        2. Codec (AV1 > H265 > VP9 > H264 > VP8 > MPEG-2 > MP4)
        3. Audio quality (Atmos > TrueHD > DTS-HD > DTS > DD+ > DD > AAC > MP3)
        4. File size (larger is assumed better quality)
        """
        if not streams:
            return

        # Group streams by resolution
        resolution_groups = {}
        for stream in streams:
            info = self.video_parser.parse(stream)
            resolution = info['raw_info']['resolution']
            if resolution not in resolution_groups:
                resolution_groups[resolution] = []
            resolution_groups[resolution].append((stream, info['raw_info']))

        # Sort resolutions by quality (8K > 4K > 1080p > 720p > 480p > 360p > Unknown)
        sorted_resolutions = sorted(
            resolution_groups.keys(),
            key=lambda x: self.video_parser.RESOLUTION_PRIORITY.get(x, -1) if x != 'Unknown' else -999,
            reverse=True
        )

        # For each resolution, find the best quality stream
        best_streams = []
        for resolution in sorted_resolutions:
            stream_infos = resolution_groups[resolution]

            sorted_streams = sorted(stream_infos, key=lambda x: (
                # Cache status
                1000 if (x[0].get('cached', False) or x[1]['is_cached']) else 0,
                # HDR
                max([self.video_parser.HDR_PRIORITY.get(hdr, 0) for hdr in x[1]['hdr']]) if x[1]['hdr'] else 0,
                # Codec
                self.video_parser.CODEC_PRIORITY.get(x[1]['codec'].split()[0], 0),
                # Audio
                max([self.video_parser.AUDIO_PRIORITY.get(audio.split()[0], 0) for audio in x[1]['audio']]) if x[1]['audio'] else 0,
                # Size (convert to bytes for comparison)
                float(x[1]['size'].split()[0]) if x[1]['size'] and x[1]['size'].split()[0].replace('.', '').isdigit() else 0
            ), reverse=True)

            if sorted_streams:
                best_streams.append(sorted_streams[0][0])

        streams[:] = best_streams

    def _process_stream_formatting(self, streams: List[Dict[str, Any]], username: str = None) -> None:
        cached_only = config.get_user_cached_only(username) if username else False
        one_per_quality = config.get_user_one_per_quality(username) if username else False
        simple_mode = config.get_user_simple_format(username) if username else False
        vidi_mode = config.get_user_vidi_mode(username) if username else False

        if not streams:
            return

        watchhub_streams = [s for s in streams if s.get("service") == "WatchHub"]
        filtered_streams = [s for s in streams if s.get("service") != "WatchHub"]

        if filtered_streams:
            if cached_only:
                filtered_streams = [s for s in filtered_streams if s.get("is_cached", False)]
            if one_per_quality:
                self.one_per_quality(filtered_streams, username)
            if simple_mode:
                self.simple_format(filtered_streams, username)
            if vidi_mode:
                self.vidi_format(filtered_streams, username)

        streams[:] = watchhub_streams + filtered_streams
