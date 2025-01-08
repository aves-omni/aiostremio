import asyncio
import json
import time
from typing import List, Dict, Optional, Tuple
import aiohttp
import sys
import argparse
from datetime import datetime, timedelta
import os
import logging

from utils.cache import cache
from utils.config import config
from utils.service_manager import ServiceManager
from utils.url_processor import URLProcessor
from services.base import StreamingService
from services.torrentio import TorrentioService

DELAY_BETWEEN_REQUESTS = 2
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)
for logger_name in logging.root.manager.loggerDict:
    if logger_name != __name__:
        logging.getLogger(logger_name).setLevel(logging.WARNING)

DIRECT_USER = None
PROXIED_USER = None

def init_users() -> None:
    global DIRECT_USER, PROXIED_USER
    try:
        with open("db/users.json", "r") as f:
            users = json.load(f)
            
            for username, data in users.items():
                if not data.get("proxy_streams") and DIRECT_USER is None:
                    DIRECT_USER = (username, data["password"])
                elif data.get("proxy_streams") and PROXIED_USER is None:
                    PROXIED_USER = (username, data["password"])
                
                if DIRECT_USER and PROXIED_USER:
                    break
            
            if not DIRECT_USER and not PROXIED_USER:
                logger.warning("No valid users found in database")
            elif not DIRECT_USER:
                logger.info("Only caching proxied links (no direct user found)")
            elif not PROXIED_USER:
                logger.info("Only caching direct links (no proxied user found)")
            else:
                logger.info("Caching both direct and proxied links")
            
            logger.info(f"Using users \"{DIRECT_USER[0] if DIRECT_USER else 'none'}\" for direct and \"{PROXIED_USER[0] if PROXIED_USER else 'none'}\" for proxy caching")
            
    except Exception as e:
        logger.error(f"Error reading users database: {e}")

def get_services() -> List[StreamingService]:
    services = []

    if config.debrid_service is not None:
        from services.comet import CometService
        services.append(CometService())

    if os.getenv("EASYNEWS_USERNAME") and os.getenv("EASYNEWS_PASSWORD"):
        from services.easynews import EasynewsService
        services.append(EasynewsService())

    if os.getenv("MEDIAFUSION_OPTIONS"):
        from services.mediafusion import MediaFusionService
        services.append(MediaFusionService())

    if config.debrid_service is not None and config.debrid_service.lower() == "torbox":
        from services.torbox import TorboxService
        services.append(TorboxService())

    if config.debrid_service is not None:
        from services.torrentio import TorrentioService
        services.append(TorrentioService())

    return services

service_manager = ServiceManager(get_services())
url_processor = URLProcessor(os.getenv("ENCRYPTION_KEY").encode())

async def fetch_json(url: str) -> tuple[Dict, float]:
    start = time.time()
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            data = await response.json()
            return data, time.time() - start

async def get_stream_links(imdb_id: str, type: str, title: str) -> bool:
    try:
        meta_id = f"{type}/{imdb_id}"
        if any(isinstance(service, TorrentioService) for service in service_manager.services):
            meta_id = f"{meta_id}.json"

        direct_success = False
        proxy_success = False

        if DIRECT_USER:
            username, password = DIRECT_USER
            api_url = f"{config.addon_url}/user={username}|password={password}/stream/{meta_id}"
            async with aiohttp.ClientSession() as session:
                async with session.get(api_url) as response:
                    if response.status == 200:
                        response_data = await response.json()
                        if response_data.get("streams", []):
                            direct_success = True

        if PROXIED_USER:
            username, password = PROXIED_USER
            api_url = f"{config.addon_url}/user={username}|password={password}/stream/{meta_id}"
            async with aiohttp.ClientSession() as session:
                async with session.get(api_url) as response:
                    if response.status == 200:
                        response_data = await response.json()
                        if response_data.get("streams", []):
                            proxy_success = True

        status_parts = []
        if direct_success:
            status_parts.append("direct")
        if proxy_success:
            status_parts.append("proxy")
        
        if not status_parts:
            logger.warning(f"No streams cached for {type}: {title} ({imdb_id})")
            return False
        elif len(status_parts) < (bool(DIRECT_USER) + bool(PROXIED_USER)):
            logger.warning(f"Partially cached ({', '.join(status_parts)}) for {type}: {title} ({imdb_id})")
        else:
            logger.info(f"Cached ({', '.join(status_parts)}) for {type}: {title} ({imdb_id})")
        
        return bool(status_parts)
        
    except Exception as e:
        logger.error(f"Error fetching streams for {type} {title} ({imdb_id}): {e}")
        return False

def format_time(seconds: float) -> str:
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)
    return f"{hours}h {minutes}m {secs}s"

async def main():
    print("Fetching top content lists...")
    
    movies_data, _ = await fetch_json("https://cinemeta-catalogs.strem.io/top/catalog/movie/top.json")
    series_data, _ = await fetch_json("https://cinemeta-catalogs.strem.io/top/catalog/series/top.json")

    movies = [(item["imdb_id"], "movie", item["name"]) for item in movies_data["metas"]]
    series = [(item["imdb_id"], "series", item["name"]) for item in series_data["metas"]]
    
    all_content = movies + series
    total_movies = len(movies)
    total_series = len(series)
    
    avg_episodes_per_series = 20
    total_episodes = total_series * avg_episodes_per_series
    
    print(f"\nFound {total_movies} movies and {total_series} series")
    print(f"Estimated total episodes across all series: {total_episodes}")
    print(f"Total items to process: {total_movies + total_series + total_episodes}")
    print(f"Using {DELAY_BETWEEN_REQUESTS} second delay between uncached items\n")

    start_time = time.time()
    movies_processed = 0
    series_processed = 0

    for i, (imdb_id, content_type, title) in enumerate(all_content, 1):
        if content_type == "movie":
            movies_processed += 1
            movies_progress = f"Movies: [{movies_processed}/{total_movies}] ({(movies_processed/total_movies)*100:.1f}%)"

            already_cached = await get_stream_links(imdb_id, content_type, title)
            if not already_cached:
                await asyncio.sleep(DELAY_BETWEEN_REQUESTS)

            print(movies_progress)
        else:
            series_processed += 1
            series_progress = f"Series: [{series_processed}/{total_series}] ({(series_processed/total_series)*100:.1f}%)"
            
            print(f"\nProcessing series: {title}")
            print(series_progress)

            series_data, _ = await fetch_json(f"https://v3-cinemeta.strem.io/meta/series/{imdb_id}.json")
            
            already_cached = await get_stream_links(imdb_id, content_type, title)
            if not already_cached:
                await asyncio.sleep(DELAY_BETWEEN_REQUESTS)
            
            if "meta" in series_data and "videos" in series_data["meta"]:
                total_episodes = len(series_data["meta"]["videos"])
                print(f"Found {total_episodes} episodes")
                
                for ep_num, episode in enumerate(series_data["meta"]["videos"], 1):
                    if "id" in episode:
                        season = episode.get('season', 0)
                        ep = episode.get('episode', 0)
                        episode_name = f"S{season}E{ep} - {episode.get('name', 'Unknown')}"
                        print(f"Caching episode {ep_num}/{total_episodes}: {episode_name}")

                        already_cached = await get_stream_links(f"{imdb_id}:{season}:{ep}", content_type, episode_name)
                        if not already_cached:
                            await asyncio.sleep(DELAY_BETWEEN_REQUESTS)

    elapsed_time = time.time() - start_time
    print(f"\nCompleted in {format_time(elapsed_time)}")

async def cache_single_movie(imdb_id: str) -> None:
    print(f"Caching movie {imdb_id}...")
    movie_data, _ = await fetch_json(f"https://v3-cinemeta.strem.io/meta/movie/{imdb_id}.json")
    if not movie_data or "meta" not in movie_data:
        print(f"Error: Movie {imdb_id} not found")
        return
    
    title = movie_data["meta"]["name"]
    await get_stream_links(imdb_id, "movie", title)

async def cache_series(imdb_id: str) -> None:
    print(f"Caching series {imdb_id}...")
    series_data, _ = await fetch_json(f"https://v3-cinemeta.strem.io/meta/series/{imdb_id}.json")
    if not series_data or "meta" not in series_data:
        print(f"Error: Series {imdb_id} not found")
        return
    
    title = series_data["meta"]["name"]
    print(f"Found series: {title}")
    
    await get_stream_links(imdb_id, "series", title)
    
    if "videos" in series_data["meta"]:
        total_episodes = len(series_data["meta"]["videos"])
        print(f"Found {total_episodes} episodes")
        
        for i, episode in enumerate(series_data["meta"]["videos"], 1):
            if "id" in episode:
                season = episode.get('season', 0)
                ep = episode.get('episode', 0)
                episode_name = f"S{season}E{ep} - {episode.get('name', 'Unknown')}"
                print(f"Caching episode {i}/{total_episodes}: {episode_name}")
                
                already_cached = await get_stream_links(f"{imdb_id}:{season}:{ep}", "series", episode_name)
                if not already_cached:
                    await asyncio.sleep(DELAY_BETWEEN_REQUESTS)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Cache movies and series from Stremio')
    parser.add_argument('--delay', type=float, default=2, help='Delay between requests in seconds')
    parser.add_argument('--movie', type=str, help='Cache a specific movie by IMDB ID')
    parser.add_argument('--series', type=str, help='Cache all episodes of a series by IMDB ID')
    args = parser.parse_args()

    DELAY_BETWEEN_REQUESTS = args.delay
    print(f"Starting cache build process with {DELAY_BETWEEN_REQUESTS}s delay...")
    
    init_users()

    if args.movie:
        asyncio.run(cache_single_movie(args.movie))
    elif args.series:
        asyncio.run(cache_series(args.series))
    else:
        asyncio.run(main()) 
