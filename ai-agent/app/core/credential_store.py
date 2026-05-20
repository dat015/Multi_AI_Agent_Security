# core/credential_store.py
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class UserCredential:
    role:          str
    email:         str
    password:      str
    token:         Optional[str]   = None
    refresh_token: Optional[str]   = None
    expires_at:    Optional[float] = None
    user_id:       Optional[str]   = None

    def is_token_valid(self) -> bool:
        if not self.token:
            return False
        if self.expires_at is None:
            return True
        return time.time() < self.expires_at - 60


class CredentialStore:
    """
    Lưu credentials tất cả users trong memory suốt session.
    Không persist ra disk — credentials chỉ sống trong 1 session.
    """

    def __init__(self):
        self._users:            dict[str, UserCredential] = {}
        self.base_url:          str = ""
        self.login_endpoint:    str = "/identity/api/auth/login"
        self.refresh_endpoint:  str = "/identity/api/auth/refresh"

    def load(self, config: dict) -> None:
        target = config.get("target", {})
        self.base_url         = target.get("base_url", "").rstrip("/")
        self.login_endpoint   = target.get("login_endpoint",   self.login_endpoint)
        self.refresh_endpoint = target.get("refresh_endpoint", self.refresh_endpoint)

        for u in config.get("users", []):
            expires_at = None
            if exp_str := u.get("token_expires_at"):
                try:
                    expires_at = datetime.fromisoformat(exp_str).timestamp()
                except ValueError:
                    pass

            self._users[u["role"]] = UserCredential(
                role=          u["role"],
                email=         u["email"],
                password=      u["password"],
                token=         u.get("token"),
                refresh_token= u.get("refresh_token"),
                expires_at=    expires_at,
                user_id=       u.get("user_id"),
            )

    def get(self, role: str) -> Optional[UserCredential]:
        return self._users.get(role)

    def all_roles(self) -> list[str]:
        return list(self._users.keys())

    def update_after_auth(
        self,
        role:          str,
        token:         str,
        user_id:       Optional[str] = None,
        refresh_token: Optional[str] = None,
        ttl:           int = 6600,
    ) -> None:
        u = self._users.get(role)
        if not u:
            return
        u.token      = token
        u.expires_at = time.time() + ttl
        if refresh_token:
            u.refresh_token = refresh_token
        if user_id:
            u.user_id = user_id