
import re
import json
import jsonschema
from datetime import datetime
from dataclasses import dataclass
from typing import Optional
from app.core.constants import AUTH_CONFIG_SCHEMA, CONFIG_TEMPLATE

@dataclass
class ConfigError:
    field:   str    
    message: str   
    value:   str


@dataclass
class ConfigWarning:
    message: str


class ValidationResult:
    def __init__(self):
        self.errors:   list[ConfigError]   = []
        self.warnings: list[ConfigWarning] = []

    @property
    def is_valid(self) -> bool:
        return len(self.errors) == 0

    def error(self, field: str, message: str, value: str = ""):
        self.errors.append(ConfigError(field, message, str(value)))

    def warn(self, message: str):
        self.warnings.append(ConfigWarning(message))

    def to_response(self) -> dict:
        return {
            "valid":    self.is_valid,
            "errors":   [
                {"field": e.field, "message": e.message, "value": e.value}
                for e in self.errors
            ],
            "warnings": [w.message for w in self.warnings],
        }

    def format_for_print(self) -> str:
        if self.is_valid and not self.warnings:
            return "Config hợp lệ"
        lines = []
        if self.errors:
            lines.append(f" {len(self.errors)} lỗi cần sửa:\n")
            for i, e in enumerate(self.errors, 1):
                val_hint = f" (giá trị: '{e.value}')" if e.value else ""
                lines.append(f"  {i}. [{e.field}]{val_hint}\n     → {e.message}")
        if self.warnings:
            lines.append(f"\n {len(self.warnings)} cảnh báo:")
            for w in self.warnings:
                lines.append(f"  - {w.message}")
        return "\n".join(lines)



class ConfigValidator:

    @staticmethod
    def parse_json(raw_bytes: bytes) -> tuple[Optional[dict], Optional[str]]:
        try:
            text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return None, "File phải được encode bằng UTF-8"

        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            return None, (
                f"JSON không hợp lệ tại dòng {e.lineno}, cột {e.colno}: {e.msg}\n"
                f"Kiểm tra: dấu phẩy thừa, thiếu dấu ngoặc, giá trị không có quotes"
            )

        if not isinstance(data, dict):
            return None, "File phải là JSON object {}, không phải array [] hay giá trị đơn"

        return data, None

    @staticmethod
    def _schema_validate(data: dict, result: ValidationResult) -> bool:

        validator = jsonschema.Draft7Validator(AUTH_CONFIG_SCHEMA)
        schema_errors = sorted(
            validator.iter_errors(data),
            key=lambda e: e.path
        )

        for err in schema_errors:
            # Chuyển jsonschema path → human-readable field name
            path_parts = list(err.absolute_path)
            if path_parts:
                # ["users", 1, "email"] → "users[1].email"
                field = ""
                for part in path_parts:
                    if isinstance(part, int):
                        field += f"[{part}]"
                    else:
                        field += f".{part}" if field else part
            else:
                field = err.schema_path[-1] if err.schema_path else "root"

            message = ConfigValidator._translate_schema_error(err)
            value   = str(err.instance)[:80] if err.instance is not None else ""
            result.error(field, message, value)

        return result.is_valid

    @staticmethod
    def _translate_schema_error(err: jsonschema.ValidationError) -> str:
        validator = err.validator

        if validator == "required":
            missing = err.validator_value
            # Lấy tên field bị thiếu
            missing_key = err.message.split("'")[1] if "'" in err.message else missing
            labels = {
                "target":   "Thiếu section 'target' (thông tin server)",
                "users":    "Thiếu section 'users' (danh sách tài khoản)",
                "base_url": "Thiếu 'base_url' — URL của API server",
                "role":     "Thiếu 'role' — tên vai trò của user này",
                "email":    "Thiếu 'email' — địa chỉ email đăng nhập",
                "password": "Thiếu 'password' — mật khẩu đăng nhập",
            }
            return labels.get(missing_key, f"Thiếu field bắt buộc: '{missing_key}'")

        if validator == "type":
            expected = err.validator_value
            type_names = {
                "string": "chuỗi ký tự",
                "array":  "danh sách []",
                "object": "object {}",
                "integer": "số nguyên",
                "boolean": "true/false",
            }
            return f"Phải là {type_names.get(expected, expected)}, không phải {type(err.instance).__name__}"

        if validator == "pattern":
            if "^https?://" in str(err.schema_path):
                return "Phải bắt đầu bằng 'http://' hoặc 'https://'"
            if "^/" in str(err.schema_path):
                return "Phải bắt đầu bằng '/', ví dụ: '/api/auth/login'"
            if "^[a-zA-Z0-9_-]+$" in str(err.validator_value):
                return "Chỉ được chứa chữ cái, số, dấu gạch dưới (_) hoặc gạch ngang (-)"
            return f"Không đúng định dạng yêu cầu"

        if validator == "minLength":
            min_len = err.validator_value
            field_name = list(err.absolute_path)[-1] if err.absolute_path else ""
            if field_name == "password":
                return f"Mật khẩu quá ngắn — tối thiểu {min_len} ký tự"
            return f"Giá trị quá ngắn — tối thiểu {min_len} ký tự"

        if validator == "minItems":
            return f"Danh sách users không được rỗng — cần ít nhất {err.validator_value} user"

        if validator == "additionalProperties":
            extra = err.message.split("'")[1] if "'" in err.message else "?"
            return (
                f"Field '{extra}' không được phép — "
                f"chỉ chấp nhận: {', '.join(sorted(err.schema.get('properties', {}).keys()))}"
            )

        if validator == "format" and err.validator_value == "email":
            return f"Không phải địa chỉ email hợp lệ"

        return err.message


    @staticmethod
    def _business_validate(data: dict, result: ValidationResult) -> None:
        users = data.get("users", [])
        if not isinstance(users, list):
            return

        roles_seen:  dict[str, int] = {}  
        emails_seen: dict[str, int] = {}

        for i, user in enumerate(users):
            if not isinstance(user, dict):
                continue

            role  = user.get("role", "")
            email = user.get("email", "")

            # Kiểm tra email trùng
            if email:
                email_lower = email.lower()
                if email_lower in emails_seen:
                    result.error(
                        f"users[{i}].email",
                        f"Email '{email}' đã được dùng ở users[{emails_seen[email_lower]}]",
                        email
                    )
                else:
                    emails_seen[email_lower] = i

            exp = user.get("token_expires_at")
            if exp and isinstance(exp, str):
                try:
                    datetime.fromisoformat(exp)
                except ValueError:
                    result.error(
                        f"users[{i}].token_expires_at",
                        f"Không đúng định dạng ISO 8601 — "
                        f"ví dụ đúng: '2025-12-31T23:59:59'",
                        exp
                    )

            if user.get("token") and not user.get("token_expires_at"):
                result.warn(
                    f"users[{i}] (role: {role}): có token nhưng không có "
                    f"'token_expires_at' — hệ thống sẽ dùng token này đến khi "
                    f"server trả về 401 thì mới login lại"
                )

        all_roles = set(roles_seen.keys())

        if len(users) == 1:
            result.warn(
                "Chỉ có 1 user — test BOLA/BFLA yêu cầu ít nhất 2 user "
                "(ví dụ: 'attacker' + 'victim'). Thêm user thứ 2 để test đầy đủ hơn."
            )

        # Gợi ý roles quan trọng còn thiếu
        IMPORTANT_ROLES = {
            "admin":    "test API5 (BFLA — Broken Function Level Authorization)",
            "attacker": "test BOLA — truy cập resource của user khác",
            "victim":   "cung cấp resource ID để attacker test",
        }
        for role, purpose in IMPORTANT_ROLES.items():
            if role not in all_roles:
                result.warn(
                    f"Không có user với role '{role}' — "
                    f"sẽ không test được: {purpose}"
                )

    # ── Public entry point ────────────────────────────────────────────

    @classmethod
    def validate(cls, data: dict) -> ValidationResult:
        result = ValidationResult()

        schema_passed = cls._schema_validate(data, result)

        if schema_passed:
            cls._business_validate(data, result)

        return result