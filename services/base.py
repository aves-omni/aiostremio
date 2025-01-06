from abc import ABC, abstractmethod
from typing import Dict, List


class StreamingService(ABC):
    @abstractmethod
    async def get_streams(self, meta_id: str) -> List[Dict]:
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        pass
