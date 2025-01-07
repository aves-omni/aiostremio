import asyncio
import json
import time
from typing import List, Dict
import aiohttp
import sys
import argparse
from datetime import datetime, timedelta

DELAY_BETWEEN_REQUESTS = 2

async def fetch_json(url: str) -> tuple[Dict, float]:
    start = time.time()
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            data = await response.json()
            return data, time.time() - start

async def get_stream_links(imdb_id: str, type: str, title: str, domain: str, username: str, password: str) -> bool:
    url = f"https://{domain}/user={username}|password={password}/stream/{type}/{imdb_id}.json"
    try:
        _, response_time = await fetch_json(url)
        if response_time < 3:
            print(f"Already cached {type}: {title} ({imdb_id}) - {response_time:.1f}s")
            return True
        print(f"Cached new {type}: {title} ({imdb_id}) - {response_time:.1f}s")
        return False
    except Exception as e:
        print(f"Error caching {type} {title} ({imdb_id}): {e}")
        return False

def format_time(seconds: float) -> str:
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)
    return f"{hours}h {minutes}m {secs}s"

async def main(username: str, password: str, domain: str):
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

            already_cached = await get_stream_links(imdb_id, content_type, title, domain, username, password)
            if not already_cached:
                await asyncio.sleep(DELAY_BETWEEN_REQUESTS)

            print(movies_progress)
        else:
            series_processed += 1
            series_progress = f"Series: [{series_processed}/{total_series}] ({(series_processed/total_series)*100:.1f}%)"
            
            print(f"\nProcessing series: {title}")
            print(series_progress)

            series_data, _ = await fetch_json(f"https://v3-cinemeta.strem.io/meta/series/{imdb_id}.json")
            
            already_cached = await get_stream_links(imdb_id, content_type, title, domain, username, password)
            if not already_cached:
                await asyncio.sleep(DELAY_BETWEEN_REQUESTS)
            
            if "meta" in series_data and "videos" in series_data["meta"]:
                total_episodes = len(series_data["meta"]["videos"])
                print(f"Found {total_episodes} episodes")
                
                for ep_num, episode in enumerate(series_data["meta"]["videos"], 1):
                    if "id" in episode:
                        episode_id = episode["id"].replace("tt", "")  # Some episodes use tt prefix
                        episode_name = f"S{episode.get('season', '?')}E{episode.get('episode', '?')} - {episode.get('name', 'Unknown')}"
                        print(f"Caching episode {ep_num}/{total_episodes}: {episode_name}")
                        
                        already_cached = await get_stream_links(episode_id, "series", episode_name, domain, username, password)
                        if not already_cached:
                            await asyncio.sleep(DELAY_BETWEEN_REQUESTS)

    elapsed_time = time.time() - start_time
    print(f"\nCompleted in {format_time(elapsed_time)}")

async def cache_single_movie(imdb_id: str, domain: str, username: str, password: str) -> None:
    print(f"Caching movie {imdb_id}...")
    movie_data, _ = await fetch_json(f"https://v3-cinemeta.strem.io/meta/movie/{imdb_id}.json")
    if not movie_data or "meta" not in movie_data:
        print(f"Error: Movie {imdb_id} not found")
        return
    
    title = movie_data["meta"]["name"]
    await get_stream_links(imdb_id, "movie", title, domain, username, password)

async def cache_series(imdb_id: str, domain: str, username: str, password: str) -> None:
    print(f"Caching series {imdb_id}...")
    series_data, _ = await fetch_json(f"https://v3-cinemeta.strem.io/meta/series/{imdb_id}.json")
    if not series_data or "meta" not in series_data:
        print(f"Error: Series {imdb_id} not found")
        return
    
    title = series_data["meta"]["name"]
    print(f"Found series: {title}")
    
    await get_stream_links(imdb_id, "series", title, domain, username, password)
    
    if "videos" in series_data["meta"]:
        total_episodes = len(series_data["meta"]["videos"])
        print(f"Found {total_episodes} episodes")
        
        for i, episode in enumerate(series_data["meta"]["videos"], 1):
            if "id" in episode:
                episode_id = episode["id"].replace("tt", "")
                episode_name = f"S{episode.get('season', '?')}E{episode.get('episode', '?')} - {episode.get('name', 'Unknown')}"
                print(f"Caching episode {i}/{total_episodes}: {episode_name}")
                
                already_cached = await get_stream_links(episode_id, "series", episode_name, domain, username, password)
                if not already_cached:
                    await asyncio.sleep(DELAY_BETWEEN_REQUESTS)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Cache movies and series from Stremio')
    parser.add_argument('--delay', type=float, default=2, help='Delay between requests in seconds')
    parser.add_argument('--movie', type=str, help='Cache a specific movie by IMDB ID')
    parser.add_argument('--series', type=str, help='Cache all episodes of a series by IMDB ID')
    parser.add_argument('--domain', type=str, required=True, help='Domain AIOStremio is hosted on')
    parser.add_argument('--user', type=str, required=True, help='Username for authentication')
    parser.add_argument('--password', type=str, required=True, help='Password for authentication')
    args = parser.parse_args()

    DELAY_BETWEEN_REQUESTS = args.delay
    print(f"Starting cache build process with {DELAY_BETWEEN_REQUESTS}s delay...")

    if args.movie:
        asyncio.run(cache_single_movie(args.movie, args.domain, args.user, args.password))
    elif args.series:
        asyncio.run(cache_series(args.series, args.domain, args.user, args.password))
    else:
        asyncio.run(main(args.user, args.password, args.domain)) 
