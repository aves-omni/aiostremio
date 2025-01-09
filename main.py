import asyncio
import httpx
import os
import time
from collections import defaultdict
from contextlib import asynccontextmanager

import uvicorn
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext
from pydantic import BaseModel

from routes.api import router
from services.comet import CometService
from services.easynews import EasynewsService
from services.mediafusion import MediaFusionService
from services.torbox import TorboxService
from services.torrentio import TorrentioService
from utils.cache import get_cache_info
from utils.config import config
from utils.logger import logger

load_dotenv()

# Order is reflected in Stremio
streaming_services = [
    service
    for service in [
        TorboxService() if config.debrid_service.lower() == "torbox" else None,
        TorrentioService() if config.debrid_service is not None else None,
        CometService() if config.debrid_service is not None else None,
        MediaFusionService() if os.getenv("MEDIAFUSION_OPTIONS") else None,
        (
            EasynewsService()
            if os.getenv("EASYNEWS_USERNAME") and os.getenv("EASYNEWS_PASSWORD")
            else None
        ),
    ]
    if service is not None
]


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Cache status - Size: {(await get_cache_info())['total_size_mb']}MB")
    cleanup_task = asyncio.create_task(periodic_cleanup())
    yield
    cleanup_task.cancel()
    await cleanup_task


async def periodic_cleanup():
    while True:
        await asyncio.sleep(30)
        current_time = time.time()
        for username, timestamp in list(active_user_timestamps.items()):
            if current_time - timestamp >= ACTIVE_TIMEOUT and username in active_users:
                active_user_timestamps.pop(username)
                active_users.pop(username)
                logger.debug(f"Cleaned up inactive user: {username}")


app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

USERS_FILE = "db/users.json"
RATE_LIMIT_MINUTES = 1
MAX_REQUESTS = 30
CACHE_TTL = config.cache_ttl_seconds

active_users = defaultdict(int)
active_user_timestamps = defaultdict(float)
ACTIVE_TIMEOUT = 30

ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    ENCRYPTION_KEY = Fernet.generate_key()
    logger.warning(
        "No ENCRYPTION_KEY set, a new key will be generated on every restart."
    )
fernet = Fernet(ENCRYPTION_KEY)

rate_limits = defaultdict(list)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class User(BaseModel):
    username: str
    password: str
    proxy_streams: bool = True


class RateLimiter:
    def __init__(self, max_requests: int, window_minutes: int):
        self.max_requests = max_requests
        self.window_minutes = window_minutes

    def is_rate_limited(self, user: str) -> bool:
        now = time.time()
        minute_ago = now - (self.window_minutes * 60)

        # Clean old requests
        rate_limits[user] = [
            req_time for req_time in rate_limits[user] if req_time > minute_ago
        ]

        # Check if rate limited
        if len(rate_limits[user]) >= self.max_requests:
            logger.info(
                f"Rate limit exceeded for user: {user} ({len(rate_limits[user])}/{self.max_requests})"
            )
            return True

        # Add new request
        rate_limits[user].append(now)
        return False


rate_limiter = RateLimiter(MAX_REQUESTS, RATE_LIMIT_MINUTES)


class AdminAuth:
    def __init__(self):
        admin_username = os.getenv("ADMIN_USERNAME")
        admin_password = os.getenv("ADMIN_PASSWORD")

        self.admin_credentials = {
            "username": admin_username,
            "password_hash": pwd_context.hash(admin_password),
        }

    def verify_admin(self, username: str, password: str) -> bool:
        if username != self.admin_credentials["username"]:
            return False
        return pwd_context.verify(password, self.admin_credentials["password_hash"])


admin_auth = AdminAuth()

templates = Jinja2Templates(directory="templates")

app.include_router(router)


async def sanity_check():
    logger.info(f"Performing sanity check...")

    addon_urls = [service.base_url for service in streaming_services]

    logger.info(f"Checking addons...")

    for url in addon_urls:
        async with httpx.AsyncClient() as client:
            response = await client.get(url)
            if response.status_code not in [200, 302, 307]:
                logger.warning(f"Addons | ⚠️  {url}")
            else:
                logger.info(f"Addons | ✅ {url}")

    logger.info(f"Checking config...")

    if (
        not os.getenv("DEBRID_SERVICE")
        and not os.getenv("MEDIAFUSION_OPTIONS")
        and not (os.getenv("EASYNEWS_USERNAME") and os.getenv("EASYNEWS_PASSWORD"))
    ):
        logger.warning(f"Config | ⚠️ No services configured")
        exit(1)

    if os.getenv("DEBRID_SERVICE") and not os.getenv("DEBRID_API_KEY"):
        logger.warning(f"Config | ⚠️ Default debrid service is configured but no API key is set.")
        exit(1)

    for service_name in config._config.get("addon_config", {}).keys():
        debrid_service = config.get_addon_debrid_service(service_name)
        debrid_api_key = config.get_addon_debrid_api_key(service_name)
        if not debrid_api_key:
            logger.info(f"Config | ➡️  Using {config.debrid_service} for {service_name}")
        else:
            logger.info(f"Config | ✅ Using {debrid_service} for {service_name}")

    logger.info("Sanity check passed!")


if __name__ == "__main__":
    asyncio.run(sanity_check())
    uvicorn.run(app, host="0.0.0.0", port=8469)
