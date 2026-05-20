# core/auth_manager.py
import httpx
from typing import Optional
from app.core.credential_store import CredentialStore


class AuthError(Exception):
    pass


class AuthManager:

    def __init__(self, store: CredentialStore):
        self._store = store

    def get_token(self, role: str) -> str:
        """
        Điểm vào duy nhất — Execution Agent chỉ cần gọi hàm này.

        Thứ tự ưu tiên:
          1. Cache còn hạn       → trả ngay (0 network call)
          2. Có refresh_token    → POST /refresh
          3. Fallback login      → POST /login
          4. Thất bại hoàn toàn → raise AuthError
        """
        user = self._store.get(role)
        if not user:
            raise AuthError(
                f"Role '{role}' không tồn tại trong config. "
                f"Các role hiện có: {self._store.all_roles()}"
            )

        if user.is_token_valid():
            return user.token

        if user.refresh_token:
            try:
                return self._do_refresh(role, user.refresh_token)
            except Exception as e:
                print(f"  [AUTH] '{role}': refresh thất bại ({e}) → thử login")

        try:
            return self._do_login(role, user.email, user.password)
        except Exception as e:
            raise AuthError(
                f"Không thể xác thực '{role}' ({user.email}): {e}\n"
                f"Kiểm tra email/password trong file config."
            )

    def get_headers(self, role: str) -> dict:
        return {
            "Authorization": f"Bearer {self.get_token(role)}",
            "Content-Type":  "application/json",
        }

    def get_user_id(self, role: str) -> str:
        self.get_token(role)
        user = self._store.get(role)
        return user.user_id or "" if user else ""


    def _do_login(self, role: str, email: str, password: str) -> str:
        url  = self._store.base_url + self._store.login_endpoint
        resp = httpx.post(
            url,
            json={"email": email, "password": password},
            timeout=10, verify=False,
        )
        if resp.status_code not in (200, 201):
            raise ValueError(f"HTTP {resp.status_code}: {resp.text[:200]}")

        data = resp.json()
        token = self._extract_field(data, ["token", "access_token", "accessToken"])
        if not token:
            raise ValueError(f"Không tìm thấy token trong response: {list(data.keys())}")

        self._store.update_after_auth(
            role=          role,
            token=         token,
            user_id=       str(self._extract_field(data, ["id", "user_id", "userId"]) or ""),
            refresh_token= self._extract_field(data, ["refresh_token", "refreshToken"]),
        )
        return token

    def _do_refresh(self, role: str, refresh_token: str) -> str:
        url  = self._store.base_url + self._store.refresh_endpoint
        resp = httpx.post(
            url,
            json={"refresh_token": refresh_token},
            headers={"Content-Type": "application/json"},
            timeout=10, verify=False,
        )
        if resp.status_code not in (200, 201):
            raise ValueError(f"HTTP {resp.status_code}")

        data  = resp.json()
        token = self._extract_field(data, ["token", "access_token", "accessToken"])
        if not token:
            raise ValueError("Không tìm thấy token mới")

        self._store.update_after_auth(
            role=          role,
            token=         token,
            refresh_token= self._extract_field(data, ["refresh_token", "refreshToken"]),
        )
        return token

    @staticmethod
    def _extract_field(data: dict, keys: list) -> Optional[str]:
        """Thử nhiều tên field khác nhau — API không chuẩn tên."""
        for key in keys:
            if key in data and data[key]:
                return data[key]
            # Nested: data.data.token
            if "data" in data and isinstance(data["data"], dict):
                if key in data["data"] and data["data"][key]:
                    return data["data"][key]
        return None