from fastapi import FastAPI, HTTPException, Body, Response
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
    base64url_to_bytes,
)
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from pydantic import BaseModel
from typing import Dict

import database

app = FastAPI()

RP_ID = "localhost"
RP_NAME = "PyWebAuthn FastAPI Example"
ORIGIN = "http://localhost:8000"


class RegistrationStartRequest(BaseModel):
    username: str
    display_name: str


class AuthenticationStartRequest(BaseModel):
    username: str


@app.post("/generate-registration-options")
def registration_options_start(request: RegistrationStartRequest):
    username = request.username
    display_name = request.display_name

    if database.get_user(username):
        raise HTTPException(status_code=400, detail="User already exists")

    user_id = f"user_{username}".encode("utf-8")
    database.add_user(username, user_id=user_id, display_name=display_name)

    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=user_id,
        user_name=username,
        user_display_name=display_name,
        attestation=AttestationConveyancePreference.NONE,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )
    database.save_challenge_for_user(username, options.challenge)
    return Response(content=options_to_json(options), media_type="application/json")


@app.post("/verify-registration")
def registration_options_verify(
    username: str = Body(...), credential: Dict = Body(...)
):
    challenge = database.get_challenge_for_user(username)
    if not challenge:
        raise HTTPException(status_code=400, detail="Challenge not found for user")

    user = database.get_user(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    try:
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            require_user_verification=True,
        )
        database.add_credential_for_user(
            user_id_b64url=user["id"],
            cred_id=verification.credential_id,
            pub_key=verification.credential_public_key,
            sign_count=verification.sign_count,
        )
        return {"verified": True}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Registration failed: {e}")


@app.post("/generate-authentication-options")
def authentication_options_start(request: AuthenticationStartRequest):
    username = request.username
    if not database.get_user(username):
        raise HTTPException(status_code=404, detail="User not found")

    options = generate_authentication_options(
        rp_id=RP_ID,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    database.save_challenge_for_user(username, options.challenge)
    return Response(content=options_to_json(options), media_type="application/json")


@app.post("/verify-authentication")
def authentication_options_verify(credential: Dict = Body(...)):
    raw_id_b64url = credential.get("id")
    if not raw_id_b64url:
        raise HTTPException(status_code=400, detail="Credential missing 'id'")

    # `userHandle` 應由驗證器在 resident key 登入時提供
    user_handle_b64url = credential.get("response", {}).get("userHandle")
    if not user_handle_b64url:
        raise HTTPException(status_code=400, detail="Credential missing 'userHandle'")

    all_user_creds = database.get_credentials_by_user_id(user_handle_b64url)
    cred_to_verify = next(
        (cred for cred in all_user_creds if cred["id"] == raw_id_b64url), None
    )

    if not cred_to_verify:
        raise HTTPException(status_code=404, detail="Credential not found for user")

    # 由於我們允許 discoverable credentials, challenge 是與請求者綁定的，而不是 user handle
    # 在一個真實的應用中，這裡需要一個方法來從請求上下文中確定使用者名稱（例如 session）
    # 為了簡化，我們假設可以從某處獲取它，或要求客戶端在驗證時也提供使用者名稱
    # 這裡我們假設可以從 userHandle 反向查找使用者
    username = ""
    for u_name, u_data in database.users.items():
        if u_data["id"] == user_handle_b64url:
            username = u_name
            break

    if not username:
        raise HTTPException(
            status_code=404, detail="Could not map userHandle to a user"
        )

    challenge = database.get_challenge_for_user(username)
    if not challenge:
        raise HTTPException(status_code=400, detail="Challenge not found for user")

    try:
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=base64url_to_bytes(cred_to_verify["public_key"]),
            credential_current_sign_count=cred_to_verify["sign_count"],
            require_user_verification=True,
        )
        # 更新簽章計數以防重放攻擊
        cred_to_verify["sign_count"] = verification.new_sign_count
        return {"verified": True}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Authentication failed: {e}")
