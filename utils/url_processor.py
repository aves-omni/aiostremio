import base64
from typing import Dict

from cryptography.fernet import Fernet
from fastapi import HTTPException

from utils.config import config
from utils.logger import logger


class URLProcessor:
    def __init__(self, encryption_key: bytes):
        self.fernet = Fernet(encryption_key)
        self.addon_url = config.addon_url

    def process_stream_urls(
        self, streams: Dict[str, list], user_path: str, proxy_enabled: bool
    ) -> None:
        """Process URLs in streams, encrypting them if proxy is enabled."""
        for stream in streams:
            if "url" in stream:
                if proxy_enabled:
                    encrypted_url = self.fernet.encrypt(stream["url"].encode()).decode()
                    safe_encrypted_url = base64.urlsafe_b64encode(
                        encrypted_url.encode()
                    ).decode()
                    proxy_url = (
                        f"{self.addon_url}/{user_path}/proxy/{safe_encrypted_url}"
                    )
                    stream["url"] = proxy_url

    def decrypt_url(self, encrypted_url: str) -> str:
        """Decrypt an encrypted URL."""
        try:
            # Add padding if needed
            padding_needed = len(encrypted_url) % 4
            if padding_needed:
                encrypted_url += "=" * (4 - padding_needed)

            decoded_url = base64.urlsafe_b64decode(encrypted_url.encode()).decode()
            original_url = self.fernet.decrypt(decoded_url.encode()).decode()
            return original_url

        except Exception as e:
            logger.error(f"URL processing error: {str(e)}")
            raise HTTPException(status_code=400, detail="Invalid URL format")
