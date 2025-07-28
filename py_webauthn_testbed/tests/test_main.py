# test_main.py

import pytest
import json
import hashlib

from fastapi.testclient import TestClient
from fido2 import cbor
from fido2.webauthn import AuthenticatorData
from fido2.utils import websafe_encode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from main import app, RP_ID, ORIGIN
from database import clear_db, get_credentials_by_user_id

# --- Fixtures ---


@pytest.fixture(scope="module")
def client():
    """
    提供一個在整個測試模組中共享的 TestClient。
    """
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def registered_user_data(client: TestClient):
    """
    一個 setup/teardown fixture，負責註冊一個新使用者並提供其資料。
    每次使用此 fixture 的測試執行前，都會重新註冊一個乾淨的用戶。
    """
    clear_db()
    username = "fixture-user"
    display_name = "Fixture User"

    # 步驟 1: 獲取註冊選項
    response = client.post(
        "/generate-registration-options",
        json={"username": username, "display_name": display_name},
    )
    assert response.status_code == 200
    reg_options = response.json()
    challenge_b64url = reg_options["challenge"]
    user_id_from_server = reg_options["user"]["id"]

    # 步驟 2: 模擬客戶端註冊
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    rp_id_hash = hashlib.sha256(RP_ID.encode("utf-8")).digest()
    flags = (
        AuthenticatorData.FLAG.USER_PRESENT
        | AuthenticatorData.FLAG.USER_VERIFIED
        | AuthenticatorData.FLAG.AT
    )
    sign_count = 0
    credential_id = b"fixture_credential_id_12345"

    cose_key = {
        1: 2,
        3: -7,
        -1: 1,
        -2: public_key.public_numbers().x.to_bytes(32, "big"),
        -3: public_key.public_numbers().y.to_bytes(32, "big"),
    }

    aaguid = b"\x00" * 16
    credential_id_len = len(credential_id).to_bytes(2, "big")
    public_key_cbor = cbor.encode(cose_key)
    attested_credential_data = (
        aaguid + credential_id_len + credential_id + public_key_cbor
    )

    auth_data_bytes = (
        rp_id_hash
        + flags.to_bytes(1, "big")
        + sign_count.to_bytes(4, "big")
        + attested_credential_data
    )
    auth_data = AuthenticatorData(auth_data_bytes)

    client_data_dict = {
        "type": "webauthn.create",
        "challenge": challenge_b64url,
        "origin": ORIGIN,
        "crossOrigin": False,
    }
    client_data_json = json.dumps(client_data_dict).encode("utf-8")

    attestation_object_dict = {"fmt": "none", "attStmt": {}, "authData": auth_data}

    registration_credential = {
        "id": websafe_encode(credential_id),
        "rawId": websafe_encode(credential_id),
        "response": {
            "clientDataJSON": websafe_encode(client_data_json),
            "attestationObject": websafe_encode(cbor.encode(attestation_object_dict)),
        },
        "type": "public-key",
    }

    # 步驟 3: 驗證註冊
    response = client.post(
        "/verify-registration",
        json={"username": username, "credential": registration_credential},
    )
    assert response.status_code == 200, response.text
    assert response.json() == {"verified": True}

    # 將必要的數據 yield 給測試函數
    yield {
        "username": username,
        "user_id": user_id_from_server,
        "credential_id": credential_id,
        "private_key": private_key,
    }

    # 清理資料庫，確保下一個測試是乾淨的
    clear_db()


# --- Test Functions ---


def test_generate_registration_options(client: TestClient):
    """測試是否可以成功獲取註冊選項。"""
    clear_db()
    response = client.post(
        "/generate-registration-options",
        json={"username": "testuser", "display_name": "Test User"},
    )
    assert response.status_code == 200
    options = response.json()
    assert "challenge" in options
    assert "rp" in options
    assert options["rp"]["id"] == RP_ID
    assert options["user"]["name"] == "testuser"
    clear_db()


def test_authentication_options_for_unregistered_user(client: TestClient):
    """測試未註冊的使用者無法獲取認證選項。"""
    clear_db()
    response = client.post(
        "/generate-authentication-options", json={"username": "ghost-user"}
    )
    assert response.status_code == 404
    clear_db()


def test_generate_authentication_options(
    client: TestClient, registered_user_data: dict
):
    """測試已註冊的使用者可以成功獲取認證選項。"""
    response = client.post(
        "/generate-authentication-options",
        json={"username": registered_user_data["username"]},
    )
    assert response.status_code == 200
    options = response.json()
    assert "challenge" in options
    assert options["rpId"] == RP_ID


def test_full_authentication_flow(client: TestClient, registered_user_data: dict):
    """測試完整的認證流程（獲取 challenge -> 簽章 -> 驗證）。"""
    # 從 fixture 獲取已註冊用戶的資料
    username = registered_user_data["username"]
    user_id = registered_user_data["user_id"]
    credential_id = registered_user_data["credential_id"]
    private_key = registered_user_data["private_key"]

    # 步驟 1: 為已註冊使用者獲取認證 challenge
    response = client.post(
        "/generate-authentication-options", json={"username": username}
    )
    assert response.status_code == 200
    auth_options = response.json()
    auth_challenge_b64url = auth_options["challenge"]

    # 步驟 2: 模擬客戶端簽章
    auth_client_data_dict = {
        "type": "webauthn.get",
        "challenge": auth_challenge_b64url,
        "origin": ORIGIN,
        "crossOrigin": False,
    }
    auth_client_data_json = json.dumps(auth_client_data_dict).encode("utf-8")

    rp_id_hash = hashlib.sha256(RP_ID.encode("utf-8")).digest()
    new_sign_count = 25
    auth_flags = (
        AuthenticatorData.FLAG.USER_PRESENT | AuthenticatorData.FLAG.USER_VERIFIED
    )
    auth_auth_data_bytes = (
        rp_id_hash + auth_flags.to_bytes(1, "big") + new_sign_count.to_bytes(4, "big")
    )

    message_to_sign = (
        auth_auth_data_bytes + hashlib.sha256(auth_client_data_json).digest()
    )
    signature = private_key.sign(message_to_sign, ec.ECDSA(hashes.SHA256()))

    authentication_credential = {
        "id": websafe_encode(credential_id),
        "rawId": websafe_encode(credential_id),
        "response": {
            "clientDataJSON": websafe_encode(auth_client_data_json),
            "authenticatorData": websafe_encode(auth_auth_data_bytes),
            "signature": websafe_encode(signature),
            "userHandle": user_id,
        },
        "type": "public-key",
    }

    # 步驟 3: 驗證認證
    response = client.post("/verify-authentication", json=authentication_credential)
    assert response.status_code == 200, response.text
    assert response.json() == {"verified": True}

    # 步驟 4: 檢查資料庫狀態
    final_user_creds = get_credentials_by_user_id(user_id)
    assert final_user_creds[0]["sign_count"] == new_sign_count
