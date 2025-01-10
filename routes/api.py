import base64
import json
import os
import time
from collections import defaultdict
import copy

import aiohttp
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from passlib.context import CryptContext

from utils.cache import cached_decorator, cache
from utils.config import config
from utils.logger import logger
from utils.service_manager import ServiceManager
from utils.streaming import StreamManager
from utils.url_processor import URLProcessor

router = APIRouter()

from main import (
    ACTIVE_TIMEOUT,
    CACHE_TTL,
    ENCRYPTION_KEY,
    USERS_FILE,
    User,
    active_user_timestamps,
    active_users,
    admin_auth,
    fernet,
    rate_limiter,
    streaming_services,
    templates,
)

service_manager = ServiceManager(streaming_services)
stream_manager = StreamManager()
url_processor = URLProcessor(ENCRYPTION_KEY)


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
        # Decode the base64 url-safe format back to original hash
        original_hash = base64.urlsafe_b64decode(safe_hash.encode()).decode()
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
            pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
            is_valid = pwd_context.verify(user.password, original_hash)
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


@router.get("/active_users")
async def get_active_users(request: Request):
    current_time = time.time()
    active_count = 0
    active_userlist = []

    for username, timestamp in list(active_user_timestamps.items()):
        if current_time - timestamp < ACTIVE_TIMEOUT:
            active_count += 1
            active_userlist.append(username)
            active_users[username] = 1
        else:
            del active_user_timestamps[username]
            if username in active_users:
                del active_users[username]
                logger.debug(f"Cleaned up inactive user: {username}")

    is_admin = False
    if "referer" in request.headers:
        referer = request.headers["referer"]
        is_admin = "/admin" in referer

    return {
        "count": active_count,
        "users": active_userlist if is_admin else [],
    }


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
    return templates.TemplateResponse(
        "admin.html", {"request": request, "users": users}
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
    proxy_streams = form_data.get("proxy_streams", "true").lower() == "true"

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

    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    hashed_password = pwd_context.hash(password)
    safe_hash = base64.urlsafe_b64encode(hashed_password.encode()).decode()
    users[username] = {"password": safe_hash, "proxy_streams": proxy_streams}
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

    if username in active_user_timestamps:
        del active_user_timestamps[username]
    if username in active_users:
        del active_users[username]

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


@router.get("/{user_path}/stream/{meta_id:path}")
async def stream(user_path: str, meta_id: str):
    username, proxy_streams = await verify_user(user_path)
    if rate_limiter.is_rate_limited(username):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    active_user_timestamps[username] = time.time()
    active_users[username] = 1

    try:
        proxy_key = f"stream:{meta_id}:True"
        direct_key = f"stream:{meta_id}:False"
        
        # Try to get streams from cache first
        streams = None
        if proxy_streams:
            streams = await cache.get(proxy_key)
        else:
            streams = await cache.get(direct_key)

        # If not in cache, fetch fresh streams
        if not streams:
            original_streams = await service_manager.fetch_all_streams(meta_id)
            if not original_streams:
                raise HTTPException(status_code=404, detail="No streams found")

            regular_streams = [s for s in original_streams if s.get("name") != "Error"]
            process_stream_formatting(regular_streams)

            direct_streams = {"streams": copy.deepcopy(regular_streams)}
            proxy_streams_copy = {"streams": copy.deepcopy(regular_streams)}

            users = load_users()
            user_data = users[username]
            username_part = f"user={username}"
            password_part = f"password={user_data['password']}"

            user_path = f"{username_part}|{password_part}"

            await url_processor.process_stream_urls(
                proxy_streams_copy["streams"], user_path, True, meta_id=meta_id
            )
            await url_processor.process_stream_urls(
                direct_streams["streams"], user_path, False, meta_id=meta_id
            )

            await cache.set(proxy_key, proxy_streams_copy, ttl=CACHE_TTL)
            await cache.set(direct_key, direct_streams, ttl=CACHE_TTL)

            return proxy_streams_copy if proxy_streams else direct_streams

        return streams
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

        def update_active_user():
            active_user_timestamps[username] = time.time()
            active_users[username] = 1

        return await stream_manager.create_streaming_response(
            original_url, request.headers, update_active_user
        )

    except aiohttp.ClientError as e:
        logger.error(f"Request failed: {str(e)}")
        raise HTTPException(
            status_code=502, detail=f"Failed to fetch content: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Unexpected proxy error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=502, detail="Internal proxy error")


def process_stream_formatting(streams: list) -> None:
    """Process stream titles and descriptions."""

    def make_bold_text(text):
        bold_chars = "𝗮𝗯𝗰𝗱𝗲𝗳𝗴𝗵𝗶𝗷𝗸𝗹𝗺𝗻𝗼𝗽𝗾𝗿𝘀𝘁𝘂𝘃𝘄𝘅𝘆𝘇𝗔𝗕𝗖𝗗𝗘𝗙𝗚𝗛𝗜𝗝𝗞𝗟𝗠𝗡𝗢𝗣𝗤𝗥𝗦𝗧𝗨𝗩𝗪𝗫𝗬𝗭𝟬𝟭𝟮𝟯𝟰𝟱𝟲𝟳𝟴𝟵"
        normal_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        trans = str.maketrans(normal_chars, bold_chars)
        return text.translate(trans)

    # Vidi does not show titles such as "[RD+] Torrentio 4k" so we add it to the description
    if config.vidi_mode:
        service_processors = {
            "Comet": lambda stream: (
                "description",
                f"{stream.get('name', stream['service']).replace('\n', '')}\n{stream['description']}",
            ),
            "Easynews": lambda stream: (
                "description",
                f"{stream.get('name', stream['service']).replace('\n', '')}\n{stream['description'].lstrip()}",
            ),
            "MediaFusion": lambda stream: (
                "description",
                f"{stream.get('name', stream['service']).replace('\n', '')}\n{stream['description']}",
            ),
            "TorBox": lambda stream: (
                "description",
                f"{stream.get('name', stream['service']).replace('\n', '')}\n{stream['description']}",
            ),
            "Torrentio": lambda stream: (
                "title",
                f"{stream.get('name', stream['service']).replace('\n', ' ')}\n{stream['title']}",
            )
        }

        for stream in streams:
            service_name = stream.get("service")
            if service_name in service_processors:
                key, value = service_processors[service_name](stream)
                stream[key] = value
    # If Vidi mode is disabled, we don't format the streams
    else:
        pass


@router.get("/{user_path}/manifest.json")
@cached_decorator(ttl=60)
async def user_manifest(user_path: str):
    username, proxy_streams = await verify_user(user_path)
    logger.info(f"Manifest request from user: {username}")

    enabled_services = [service.name for service in streaming_services]
    enabled_services_str = ", ".join(enabled_services)

    manifest_data = {
        "id": "win.stkc.aio",
        "version": "0.0.1",
        "name": "AIO",
        "description": f"""Logged in as {username} {"(🔐 Proxy Enabled)" if proxy_streams else "(🔓 Proxy Disabled)"}

Combine results from {len(enabled_services)} addons:
{enabled_services_str}

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
        "background": "https://i.ibb.co/VtSfFP9/t8wVwcg.jpg",
        "logo": "https://i.ibb.co/w4BnkC9/GwxAcDV.png",
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
