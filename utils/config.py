import json
import os
from typing import Any, Dict


class Config:
    _instance = None
    _config: Dict[str, Any] = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Config, cls).__new__(cls)
            cls._instance._load_config()
        return cls._instance

    def _load_config(self):
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "config.json"
        )
        try:
            with open(config_path, "r") as f:
                self._config = json.load(f)
        except Exception as e:
            raise RuntimeError(f"Failed to load config.json: {str(e)}")

    @property
    def debrid_service(self) -> str:
        return self._config.get("debrid_service", "torbox")

    @property
    def addon_url(self) -> str:
        return self._config.get("addon_url", "https://debridproxy.stkc.win")

    @property
    def cache_ttl_seconds(self) -> int:
        return self._config.get("cache_ttl_seconds", 60)

    @property
    def buffer_size_mb(self) -> int:
        return self._config.get("buffer_size_mb", 256)

    @property
    def chunk_size_mb(self) -> int:
        return self._config.get("chunk_size_mb", 4)


config = Config()
