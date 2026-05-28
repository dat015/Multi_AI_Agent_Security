# core/session_store.py
"""
Shared in-memory stores — dùng chung giữa main.py và agent_controller.py.

Lý do tách ra module riêng:
  - main.py định nghĩa /upload-config → lưu config vào đây
  - agent_controller.py chạy pipeline → đọc config từ đây
  - Nếu mỗi file tự khai báo dict riêng → không share được (2 object khác nhau)
"""

# Lưu raw config dict theo config_id
# Key:   config_id (str UUID)
# Value: config dict {"target": {...}, "users": [...]}
CONFIG_STORE: dict[str, dict] = {}

# Lưu trạng thái các session đang chạy
# Key:   session_id (str UUID)
# Value: {"status": "running"|"done"|"error", "test_plan": [...], ...}
SESSION_STORE: dict[str, dict] = {}
