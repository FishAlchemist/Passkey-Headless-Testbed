from typing import Dict, List, Optional
from webauthn.helpers import bytes_to_base64url

# 模擬一個簡單的記憶體資料庫
# 在實際應用中，應替換為 Redis, PostgreSQL 等

# { "username": "challenge_bytes" }
challenges: Dict[str, bytes] = {}
# { "username": {"id": "user_id_b64url", "username": "...", ...} }
users: Dict[str, Dict] = {}
# { "user_id_b64url": [{ "id": "cred_id_b64url", "public_key": "...", "sign_count": 0 }] }
credentials: Dict[str, List[Dict]] = {}


def save_challenge_for_user(username: str, challenge: bytes):
    challenges[username] = challenge


def get_challenge_for_user(username: str) -> Optional[bytes]:
    return challenges.pop(username, None)


def get_user(username: str) -> Optional[Dict]:
    return users.get(username)


def add_user(username: str, user_id: bytes, display_name: str):
    user_id_b64url = bytes_to_base64url(user_id)
    if username not in users:
        users[username] = {
            "id": user_id_b64url,
            "username": username,
            "display_name": display_name,
        }


def get_credentials_by_user_id(user_id_b64url: str) -> List[Dict]:
    return credentials.get(user_id_b64url, [])


def add_credential_for_user(
    user_id_b64url: str, cred_id: bytes, pub_key: bytes, sign_count: int
):
    if user_id_b64url not in credentials:
        credentials[user_id_b64url] = []

    credentials[user_id_b64url].append(
        {
            "id": bytes_to_base64url(cred_id),
            "public_key": bytes_to_base64url(pub_key),
            "sign_count": sign_count,
        }
    )


def clear_db():
    """清除所有資料庫內容 (主要用於測試)"""
    global challenges, users, credentials
    challenges = {}
    users = {}
    credentials = {}
