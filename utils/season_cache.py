import json
import os
import time
import asyncio
import aiohttp
from utils.logger import logger
from utils.config import config

_caching_seasons = set()

async def _fetch_streams(meta_id: str, username: str, password: str, proxy_streams: bool) -> bool:
    api_url = f"{config.addon_url}/user={username}|password={password}/stream/{meta_id}"
    async with aiohttp.ClientSession() as session:
        async with session.get(api_url) as response:
            if response.status == 200:
                response_data = await response.json()
                return bool(response_data.get("streams", []))
    return False

async def cache_season(meta_id: str):
    try:
        # Extract series ID and season from meta_id (tt1234567:1:2 for S1E2)
        parts = meta_id.split(":")
        if len(parts) == 3:
            series_id, season, _ = parts
            
            season_key = f"{series_id}:{season}"
            if season_key in _caching_seasons:
                logger.debug(f"Season {season_key} is already being cached")
                return
            
            _caching_seasons.add(season_key)
            logger.info(f"Starting to cache season {season} for series {series_id}")
            
            try:
                async with aiohttp.ClientSession() as session:
                    cinemeta_url = f"https://v3-cinemeta.strem.io/meta/{series_id.split(':')[0]}.json"
                    async with session.get(cinemeta_url) as response:
                        if response.status == 200:
                            data = await response.json()
                            if "meta" in data and "videos" in data["meta"]:
                                # Filter episodes for the current season
                                season_episodes = [
                                    video for video in data["meta"]["videos"]
                                    if video.get("season") == int(season)
                                ]

                                name = data["meta"]["name"]
                                
                                logger.info(f"Found {len(season_episodes)} episodes in season {season} for {name}")

                                users_file = "db/users.json"
                                if os.path.exists(users_file):
                                    with open(users_file, "r") as f:
                                        users = json.load(f)

                                    cache_user = None
                                    if users:
                                        username, data = next(iter(users.items()))
                                        cache_user = (username, data["password"])
                                
                                start_time = time.time()
                                
                                for episode in season_episodes:
                                    ep_num = episode.get("episode", 0)
                                    if meta_id.endswith('.json'):
                                        ep_meta_id = f"{series_id.split(':')[0]}:{season}:{ep_num}.json"
                                    else:
                                        ep_meta_id = f"{series_id.split(':')[0]}:{season}:{ep_num}"
                                    ep_name = f"S{season}E{ep_num} - {episode.get('name', 'Unknown')}"
                                    
                                    logger.info(f"Caching episode {ep_name} of {name}")
                                    
                                    tasks = []
                                    
                                    if cache_user:
                                        tasks.append(_fetch_streams(ep_meta_id, cache_user[0], cache_user[1], False))  # Direct
                                        tasks.append(_fetch_streams(ep_meta_id, cache_user[0], cache_user[1], True))   # Proxied
                                    
                                    if tasks:
                                        await asyncio.gather(*tasks)
                                        
                                    # Wait before next episode to avoid rate limits
                                    await asyncio.sleep(60)
                                
                                logger.info(f"Completed caching for all episodes in season {season} of {name} in {time.time() - start_time} seconds")
            finally:
                _caching_seasons.remove(season_key)
                
    except Exception as e:
        logger.error(f"Error in season caching: {str(e)}", exc_info=True)
