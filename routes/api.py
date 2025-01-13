import base64
import json
import os
import time
from collections import defaultdict
import copy
from datetime import datetime
import bcrypt

import aiohttp
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from utils.cache import cached_decorator, cache
from utils.config import config
from utils.logger import logger
from utils.service_manager import ServiceManager
from utils.streaming import StreamManager
from utils.url_processor import URLProcessor
from utils.stream_formatter import StreamFormatter

router = APIRouter()

from main import (
    CACHE_TTL,
    ENCRYPTION_KEY,
    USERS_FILE,
    User,
    admin_auth,
    rate_limiter,
    streaming_services,
    templates,
)

service_manager = ServiceManager(streaming_services)
stream_manager = StreamManager()
url_processor = URLProcessor(ENCRYPTION_KEY)
url_processor.set_services(streaming_services)
stream_formatter = StreamFormatter(url_processor)


def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    return {}


def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)


async def verify_user(user_path: str) -> tuple[str, bool]:
    try:
        username, password = user_path.split("|")
        username = username.split("=")[1]
        safe_hash = password.split("=")[1]
    except:
        raise HTTPException(status_code=400, detail="Invalid credentials format")

    users = load_users()
    if username not in users:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user_data = users[username]
    if user_data["password"] != safe_hash:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    proxy_streams = user_data.get("proxy_streams", True)

    return username, proxy_streams


async def track_media_request(username: str, meta_id: str):
    try:
        if ':' in meta_id:
            parts = meta_id.split(':')
            if len(parts) == 3:
                media_type = "series"
                imdb_id = parts[0].replace('series/', '')
                if not imdb_id.startswith('tt'):
                    return
                    
                season = parts[1]
                episode = parts[2].replace('.json', '')
                
                entry = {
                    'type': media_type,
                    'imdb_id': imdb_id,
                    'season': season,
                    'episode': episode,
                    'timestamp': datetime.now().isoformat(),
                }

                async with aiohttp.ClientSession() as session:
                    url = f"https://v3-cinemeta.strem.io/meta/series/{imdb_id}.json"
                    async with session.get(url) as response:
                        if response.status == 200:
                            data = await response.json()
                            series_title = data.get('meta', {}).get('name', 'Unknown Title')
                            episode_data = None
                            if 'meta' in data and 'videos' in data['meta']:
                                for video in data['meta']['videos']:
                                    if (str(video.get('season')) == season and 
                                        str(video.get('episode')) == episode):
                                        episode_data = video
                                        break
                            
                            if episode_data:
                                title = f"{series_title} - {episode_data.get('name', 'Unknown')}"
                            else:
                                title = f"{series_title} - S{season}E{episode}"
                            entry['title'] = title
            else:
                logger.warning(f"Invalid meta_id format: {meta_id}")
                return
        else:
            parts = meta_id.split('/')
            if len(parts) == 2 and parts[0] == 'movie':
                imdb_id = parts[1].replace('.json', '')
                if imdb_id.startswith('tt'):
                    entry = {
                        'type': 'movie',
                        'imdb_id': imdb_id,
                        'timestamp': datetime.now().isoformat(),
                    }
                    async with aiohttp.ClientSession() as session:
                        url = f"https://v3-cinemeta.strem.io/meta/movie/{imdb_id}.json"
                        async with session.get(url) as response:
                            if response.status == 200:
                                data = await response.json()
                                entry['title'] = data.get('meta', {}).get('name', 'Unknown Title')
                            else:
                                entry['title'] = 'Unknown Title'
                                logger.warning(f"Failed to fetch movie metadata, status: {response.status}")
                else:
                    return
            else:
                return

        history_key = f"media_history:{username}"
        history = await cache.get(history_key) or []
        history.insert(0, entry)
        history = history[:100]
        await cache.set(history_key, history, ttl=30*24*60*60)
        logger.debug(f"Stored history entry for {username}: {entry}")
    except Exception as e:
        logger.error(f"Error tracking media request: {str(e)}", exc_info=True)


@router.get("/")
async def root():
    return RedirectResponse(url="/configure")


@router.get("/manifest.json")
async def manifest():
    return RedirectResponse(url="/configure")


@router.get("/configure", response_class=HTMLResponse)
async def configure_page(request: Request):
    return templates.TemplateResponse("configure.html", {"request": request})


@router.post("/configure/generate")
async def generate_config(request: Request):
    form_data = await request.form()
    user = User(username=form_data.get("username"), password=form_data.get("password"))
    logger.info(f"Received configuration request for username: {user.username}")
    try:
        users = load_users()
        logger.debug(f"Loaded users from file. Found {len(users)} users")

        if user.username not in users:
            logger.warning(f"User not found: {user.username}")
            return JSONResponse(
                status_code=400,
                content={"status": "error", "message": "User not found"},
            )

        stored_hash = users[user.username]["password"]  # Access password from dict
        # Decode the base64 url-safe hash back to the original bcrypt hash
        original_hash = base64.urlsafe_b64decode(stored_hash.encode()).decode()
        logger.debug(f"Found stored hash for user: {user.username}")

        try:
            is_valid = bcrypt.checkpw(user.password.encode(), original_hash.encode())
            logger.debug(f"Password verification result: {is_valid}")
        except Exception as e:
            logger.error(f"Password verification error: {str(e)}")
            return JSONResponse(
                status_code=500,
                content={"status": "error", "message": "Error verifying password"},
            )

        if not is_valid:
            logger.warning(f"Invalid password for user: {user.username}")
            return JSONResponse(
                status_code=401,
                content={"status": "error", "message": "Invalid password"},
            )

        url = f"{config.addon_url}/user={user.username}|password={stored_hash}/manifest.json"
        logger.info(f"Generated URL for user: {user.username}")

        return JSONResponse(status_code=200, content={"status": "success", "url": url})
    except Exception as e:
        logger.error(f"Unexpected error in generate_config: {str(e)}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": f"Error generating configuration: {str(e)}",
            },
        )


@router.get("/admin", response_class=HTMLResponse)
async def admin_page(
    request: Request, credentials: HTTPBasicCredentials = Depends(HTTPBasic())
):
    if not admin_auth.verify_admin(credentials.username, credentials.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    users = load_users()

    user_histories = {}
    user_last_active = {}
    for username in users:
        try:
            history_key = f"media_history:{username}"
            history = await cache.get(history_key) or []
            
            if history and history[0].get('timestamp'):
                last_timestamp = history[0].get('timestamp')
                try:
                    last_dt = datetime.fromisoformat(last_timestamp)
                    now = datetime.now()
                    diff = now - last_dt
                    
                    # Calculate relative time
                    if diff.days > 30:
                        weeks = diff.days // 7
                        last_active = f"{weeks} weeks ago" if weeks > 1 else "1 week ago"
                    elif diff.days > 0:
                        last_active = f"{diff.days} days ago" if diff.days > 1 else "1 day ago"
                    elif diff.seconds >= 3600:
                        hours = diff.seconds // 3600
                        last_active = f"{hours} hours ago" if hours > 1 else "1 hour ago"
                    elif diff.seconds >= 60:
                        minutes = diff.seconds // 60
                        last_active = f"{minutes} minutes ago" if minutes > 1 else "1 minute ago"
                    else:
                        last_active = "just now"
                    
                    user_last_active[username] = last_active
                except:
                    user_last_active[username] = "never"
            else:
                user_last_active[username] = "never"
            
            # Format timestamps for history entries
            for entry in history:
                if 'timestamp' in entry:
                    try:
                        dt = datetime.fromisoformat(entry['timestamp'])
                        entry['timestamp'] = dt.strftime('%m/%d/%y')
                    except:
                        entry['timestamp'] = 'Unknown'
            user_histories[username] = history[:25]  # Get last 25 entries
        except Exception as e:
            logger.error(f"Error getting history for {username}: {str(e)}", exc_info=True)
            user_histories[username] = []
            user_last_active[username] = "never"
    
    return templates.TemplateResponse(
        "admin.html", {
            "request": request, 
            "users": users,
            "user_histories": user_histories,
            "user_last_active": user_last_active
        }
    )


@router.post("/admin/add_user")
async def add_user(
    request: Request, credentials: HTTPBasicCredentials = Depends(HTTPBasic())
):
    if not admin_auth.verify_admin(credentials.username, credentials.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    form_data = await request.form()
    username = form_data.get("username")
    password = form_data.get("password")
    proxy_streams = form_data.get("proxy_streams") == "on"
    vidi_mode = form_data.get("vidi_mode") == "on"
    simple_format = form_data.get("simple_format") == "on"
    one_per_quality = form_data.get("one_per_quality") == "on"

    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required")

    if not (3 <= len(username) <= 32) or not username.isalnum():
        raise HTTPException(
            status_code=400, detail="Username must be 3-32 alphanumeric characters"
        )

    if len(password) < 8:
        raise HTTPException(
            status_code=400, detail="Password must be at least 8 characters"
        )

    users = load_users()
    if username in users:
        raise HTTPException(status_code=400, detail="Unable to create user")

    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    safe_hash = base64.urlsafe_b64encode(hashed_password).decode()
    users[username] = {
        "password": safe_hash,
        "proxy_streams": proxy_streams,
        "enabled_services": [],
        "vidi_mode": vidi_mode,
        "simple_format": simple_format,
        "one_per_quality": one_per_quality
    }
    save_users(users)

    logger.info(f"New user added: {username} (proxy_streams: {proxy_streams})")
    return {"status": "success", "message": "User created successfully"}


@router.delete("/admin/delete_user/{username}")
async def delete_user(username: str, credentials: HTTPBasicCredentials = Depends(HTTPBasic())):
    if not admin_auth.verify_admin(credentials.username, credentials.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    users = load_users()
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")

    del users[username]
    save_users(users)

    logger.info(f"User deleted: {username}")
    return {"status": "success", "message": "User deleted successfully"}


@router.post("/admin/toggle_proxy/{username}")
async def toggle_proxy(
    username: str, credentials: HTTPBasicCredentials = Depends(HTTPBasic())
):
    if not admin_auth.verify_admin(credentials.username, credentials.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    users = load_users()
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")

    users[username]["proxy_streams"] = not users[username]["proxy_streams"]
    save_users(users)

    logger.info(
        f"Toggled proxy for user: {username} (now: {users[username]['proxy_streams']})"
    )
    return {
        "status": "success",
        "message": "Proxy toggled successfully",
        "proxy_streams": users[username]["proxy_streams"],
    }


@router.post("/admin/toggle_vidi_mode/{username}")
async def toggle_vidi_mode(
    username: str, credentials: HTTPBasicCredentials = Depends(HTTPBasic())
):
    if not admin_auth.verify_admin(credentials.username, credentials.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    users = load_users()
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")

    users[username]["vidi_mode"] = not users[username].get("vidi_mode", False)
    save_users(users)

    logger.info(
        f"Toggled vidi mode for user: {username} (now: {users[username]['vidi_mode']})"
    )
    return {
        "status": "success",
        "message": "Vidi mode toggled successfully",
        "vidi_mode": users[username]["vidi_mode"],
    }


@router.post("/admin/toggle_simple_format/{username}")
async def toggle_simple_format(
    username: str, credentials: HTTPBasicCredentials = Depends(HTTPBasic())
):
    if not admin_auth.verify_admin(credentials.username, credentials.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    users = load_users()
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")

    users[username]["simple_format"] = not users[username].get("simple_format", False)
    save_users(users)

    logger.info(
        f"Toggled simple format for user: {username} (now: {users[username]['simple_format']})"
    )
    return {
        "status": "success",
        "message": "Simple format toggled successfully",
        "simple_format": users[username]["simple_format"],
    }


@router.post("/admin/toggle_one_per_quality/{username}")
async def toggle_one_per_quality(
    username: str, credentials: HTTPBasicCredentials = Depends(HTTPBasic())
):
    if not admin_auth.verify_admin(credentials.username, credentials.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    users = load_users()
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")

    users[username]["one_per_quality"] = not users[username].get("one_per_quality", False)
    save_users(users)

    logger.info(
        f"Toggled one per quality for user: {username} (now: {users[username]['one_per_quality']})"
    )
    return {
        "status": "success",
        "message": "One per quality toggled successfully",
        "one_per_quality": users[username]["one_per_quality"],
    }


@router.get("/admin/available_services")
async def get_available_services(credentials: HTTPBasicCredentials = Depends(HTTPBasic())):
    if not admin_auth.verify_admin(credentials.username, credentials.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return {"services": [service.name for service in streaming_services]}


@router.get("/admin/user_services/{username}")
async def get_user_services(username: str, credentials: HTTPBasicCredentials = Depends(HTTPBasic())):
    if not admin_auth.verify_admin(credentials.username, credentials.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    users = load_users()
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")
    return {"enabled_services": users[username].get("enabled_services", [])}


@router.post("/admin/update_services/{username}")
async def update_user_services(username: str, request: Request, credentials: HTTPBasicCredentials = Depends(HTTPBasic())):
    if not admin_auth.verify_admin(credentials.username, credentials.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    users = load_users()
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")
    
    form_data = await request.form()
    services = form_data.getlist("services")
    
    # Validate that all services exist
    available_services = [service.name for service in streaming_services]
    for service in services:
        if service not in available_services:
            raise HTTPException(status_code=400, detail=f"Invalid service: {service}")
    
    if set(services) == set(available_services):
        services = []
    
    users[username]["enabled_services"] = services
    save_users(users)
    return {"status": "success", "message": "Services updated successfully"}


@router.get("/{user_path}/stream/{meta_id:path}")
async def stream(user_path: str, meta_id: str):
    username, proxy_streams = await verify_user(user_path)
    if rate_limiter.is_rate_limited(username):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    try:
        users = load_users()
        user_data = users[username]
        enabled_services = user_data.get("enabled_services", [])
        
        # Track media request
        await track_media_request(username, meta_id)
        
        # Generate cache key for raw streams
        cache_key = f"raw_streams:{meta_id}"
        
        # Try to get raw streams from cache
        cached_data = await cache.get(cache_key)
        
        if cached_data:
            raw_streams = cached_data["streams"]
            logger.info(f"Cache hit for {meta_id} ({username})")
        else:
            # Fetch and cache raw streams
            raw_streams = await service_manager.fetch_all_streams(meta_id, username)
            if not raw_streams:
                raise HTTPException(status_code=404, detail="No streams found")
            await cache.set(cache_key, {"streams": raw_streams}, ttl=CACHE_TTL)
            logger.info(f"Cache miss for {meta_id} ({username})")

        # Process streams with user-specific settings
        username_part = f"user={username}"
        password_part = f"password={user_data['password']}"
        user_path = f"{username_part}|{password_part}"
        
        # Process streams with URL generation and formatting
        processed_streams = await stream_formatter.process_streams(
            raw_streams,
            user_path,
            proxy_streams,
            meta_id,
            username
        )
        
        # Filter streams based on user's enabled services
        filtered_streams = stream_formatter.filter_streams_by_services(
            processed_streams,
            enabled_services
        )

        return {"streams": filtered_streams}
    except Exception as e:
        logger.error(f"Error in stream endpoint: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{user_path}/proxy/{encrypted_url:path}")
async def proxy_stream(user_path: str, encrypted_url: str, request: Request):
    username, proxy_streams = await verify_user(user_path)
    if rate_limiter.is_rate_limited(username):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    try:
        if not username:
            return {"status": "error", "message": "Invalid credentials"}

        logger.info(
            f"Proxy stream starting for user: {username} (proxy_streams: {proxy_streams})"
        )

        original_url = url_processor.decrypt_url(encrypted_url)

        return await stream_manager.create_streaming_response(
            original_url, request.headers
        )

    except aiohttp.ClientError as e:
        logger.error(f"Request failed: {str(e)}")
        raise HTTPException(
            status_code=502, detail=f"Failed to fetch content: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Unexpected proxy error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=502, detail="Internal proxy error")


@router.get("/{user_path}/manifest.json")
async def user_manifest(user_path: str):
    username, proxy_streams = await verify_user(user_path)
    logger.info(f"Manifest request from user: {username}")

    global_services = [service.name for service in streaming_services]
    global_services_str = ", ".join(global_services)

    users = load_users()
    user_data = users[username]
    enabled_services = user_data.get("enabled_services", [])
    simple_format = user_data.get("simple_format", False)
    mediaflow_enabled = config.mediaflow_enabled

    if enabled_services:
        enabled_services_str = ", ".join(enabled_services)
        disabled_services = [s for s in global_services if s not in enabled_services]
        disabled_services_str = ", ".join(disabled_services) if disabled_services else "None"
    else:
        enabled_services_str = ", ".join(global_services)
        disabled_services_str = "None"

    manifest_data = {
        "id": f"win.stkc.aio.{''.join(c for c in username if c.isalnum())}",
        "version": "1.0.0",
        "name": "AIO", 
        "description": f"""Logged in as {username}

Options:
{"🔐 Proxy Enabled" if proxy_streams else "🔓 Proxy Disabled"} {"(MediaFlow)" if mediaflow_enabled else "(Internal)"}
{"📝 Simple Formatting On" if simple_format else "📝 Simple Formatting Off"}

Enabled Addons:
{enabled_services_str}

Disabled Addons:
{disabled_services_str}

https://stkc.win/""",
        "catalogs": [],
        "resources": [
            {
                "name": "stream",
                "types": ["movie", "series"],
                "idPrefixes": ["tt", "kitsu"],
            }
        ],
        "types": ["movie", "series", "anime", "other"],
        "background": "",
        "logo": "",
        "behaviorHints": {"configurable": True, "configurationRequired": False},
    }
    return manifest_data


@router.get("/{user_path}")
async def redirect_to_manifest(user_path: str):
    if "|" in user_path and "username=" in user_path and "password=" in user_path:
        return RedirectResponse(url=f"/{user_path}/manifest.json")
    return {
        "status": "error",
        "message": f"Invalid request - {config.addon_url}/user=username|password=password/manifest.json",
    }


@router.get("/{user_path}/history")
async def get_history(user_path: str):
    """Get media request history for a user."""
    username, _ = await verify_user(user_path)
    if rate_limiter.is_rate_limited(username):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    try:
        history_key = f"media_history:{username}"
        history = await cache.get(history_key) or []
        return {"history": history}
    except Exception as e:
        logger.error(f"Error getting media history: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
