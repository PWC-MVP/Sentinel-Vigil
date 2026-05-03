"""Proactive token cache — refresh 5 min before expiry."""
import threading
import time
from typing import Optional
from azure.core.credentials import AccessToken


class TokenManager:
    _instances: dict[str, "TokenManager"] = {}
    _lock = threading.Lock()

    def __init__(self, credential, scope: str):
        self._credential = credential
        self._scope = scope
        self._token: Optional[AccessToken] = None
        self._refresh_lock = threading.Lock()

    @classmethod
    def get(cls, credential, scope: str) -> "TokenManager":
        key = f"{id(credential)}:{scope}"
        with cls._lock:
            if key not in cls._instances:
                cls._instances[key] = cls(credential, scope)
        return cls._instances[key]

    @classmethod
    def invalidate_all(cls) -> None:
        with cls._lock:
            cls._instances.clear()

    def get_token(self) -> str:
        with self._refresh_lock:
            if self._needs_refresh():
                self._token = self._credential.get_token(self._scope)
        return self._token.token

    def _needs_refresh(self) -> bool:
        if self._token is None:
            return True
        return time.time() >= (self._token.expires_on - 300)
