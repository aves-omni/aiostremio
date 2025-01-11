import functools
import hashlib
import inspect
import os
import pickle

from aiocache import Cache
from aiocache.serializers import PickleSerializer

from utils.logger import logger
from utils.config import config


def default_key_builder(func, *args, **kwargs):
    module = func.__module__
    qualname = func.__qualname__
    func_name = f"{module}.{qualname}"

    try:
        if inspect.ismethod(func):
            args = args[1:]
        args_serialized = pickle.dumps(args)
        kwargs_serialized = pickle.dumps(kwargs)
    except pickle.PicklingError:
        args_serialized = str(args).encode()
        kwargs_serialized = str(kwargs).encode()

    args_hash = hashlib.sha256(args_serialized).hexdigest()
    kwargs_hash = hashlib.sha256(kwargs_serialized).hexdigest()

    key = f"{func_name}:{args_hash}:{kwargs_hash}"
    return key


cache = Cache.REDIS(
    namespace="main",
    endpoint=os.getenv("REDIS_HOST", "debridproxy_redis"),
    port=int(os.getenv("REDIS_PORT", 6379)),
    password=os.getenv("REDIS_PASSWORD"),
    serializer=PickleSerializer(),
)


def cached_decorator(
    ttl=config.cache_ttl_seconds, key_builder=default_key_builder, key_prefix=None, namespace=None
):
    def wrapper(func):
        cache_namespace = namespace or func.__name__

        @functools.wraps(func)
        async def wrapped(*args, **kwargs):
            if key_prefix:
                if callable(key_prefix):
                    key = key_prefix(*args, **kwargs)
                else:
                    key = key_prefix
            else:
                key = key_builder(func, *args, **kwargs)

            result = await cache.get(key)
            if result is not None:
                return result

            result = await func(*args, **kwargs)

            await cache.set(key, result, ttl=ttl)
            return result

        for attr in dir(func):
            if not attr.startswith("__"):
                setattr(wrapped, attr, getattr(func, attr))

        return wrapped

    return wrapper


async def get_cache_info():
    try:
        keys = await cache.raw("keys", "*")
        total_size = 0
        item_count = len(keys)

        for key in keys:
            value = await cache.raw("get", key)
            total_size += len(value) if value else 0

        return {
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "item_count": item_count,
        }
    except Exception as e:
        logger.error(f"Error getting cache info: {str(e)}")
        return {"total_size_mb": 0, "item_count": 0}
