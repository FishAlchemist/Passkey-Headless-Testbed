from playwright.sync_api import sync_playwright


def webauthn_auto_register_and_login():
    with sync_playwright() as p:
        # 啟動 Chromium 瀏覽器
        # headless=True 開啟無頭測試在自動化測試環境的可行性。
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        # 建立一個 CDP 會話
        client = page.context.new_cdp_session(page)

        # 啟用 WebAuthn 域
        client.send("WebAuthn.enable")
        print("WebAuthn 域已啟用。")

        # 設定一個虛擬的 Authenticator
        # 這裡設定為 internal，模擬內建的平台驗證器
        authenticator_id = client.send(
            "WebAuthn.addVirtualAuthenticator",
            {
                "options": {
                    "protocol": "ctap2",
                    "transport": "internal",
                    "hasCredentials": True,  # 設定為True，以便它能儲存憑證
                    "isUserVerifyingPlatformAuthenticator": True,
                    "isUserConsenting": True,
                    "isUserVerified": True,
                }
            },
        )["authenticatorId"]
        print(f"虛擬驗證器 ID: {authenticator_id}")

        # 導航到測試網站
        test_url = "https://webauthn.io/"
        page.goto(test_url)
        print(f"導航到: {test_url}")

        # --- 註冊流程 ---
        print("\n--- 開始註冊流程 ---")
        # 找到使用者名稱輸入框並輸入一個測試使用者名稱
        username_input = page.wait_for_selector("#input-email")
        test_username = "testuser_playwright_001"  # 可以每次運行更換，確保唯一性
        username_input.fill(test_username)
        print(f"輸入使用者名稱: {test_username}")

        # 點擊註冊按鈕
        # 注意：webauthn.io 的註冊按鈕是 #register-button
        register_button = page.wait_for_selector("#register-button")
        register_button.click()
        print("點擊註冊按鈕...")

        # 等待註冊成功的訊息出現
        # webauthn.io 會在成功後顯示一個綠色的成功訊息
        success_message_selector = "body > header > div > div > div > div > div.hero-left.order-2.col-lg-6.order-lg-1 > div > section > form > div:nth-child(1) > div:nth-child(3) > div"
        try:
            page.wait_for_selector(success_message_selector, timeout=100000)
            print("成功訊息已顯示：註冊成功！")
        except Exception:
            print("錯誤：未能偵測到註冊成功訊息。")
            browser.close()
            return

        # 等待幾秒，讓使用者可以看到結果
        page.wait_for_timeout(2000)

        # --- 登入流程 ---
        print("\n--- 開始登入流程 ---")
        # 確保使用者名稱輸入框還是有值（通常會保留）
        # 如果沒有，重新填寫
        if not username_input.input_value():
            username_input.fill(test_username)
            print("重新填寫使用者名稱。")

        # 點擊登入按鈕
        # 注意：webauthn.io 的登入按鈕是 #login-button
        login_button = page.wait_for_selector("#login-button")
        login_button.click()
        print("點擊登入按鈕...")

        # 等待登入成功的訊息出現
        try:
            page.wait_for_selector(
                "body > header > div > div > div > div > div > div.hero-left.order-2.col-lg-9.order-lg-1 > div:nth-child(1) > div > h3",
                timeout=10000,
            )
            print("成功訊息已顯示：登入成功！")
        except Exception:
            print("錯誤：未能偵測到登入成功訊息。")
            browser.close()
            return

        # 等待幾秒，讓使用者可以看到結果
        page.wait_for_timeout(3000)

        print("\n--- 清理階段 ---")
        # 清除此虛擬驗證器的所有憑證 (可選，但有助於重覆測試)
        client.send("WebAuthn.clearCredentials", {"authenticatorId": authenticator_id})
        print(f"虛擬驗證器 {authenticator_id} 的憑證已清除。")

        # 移除此虛擬驗證器 (可選)
        client.send(
            "WebAuthn.removeVirtualAuthenticator", {"authenticatorId": authenticator_id}
        )
        print(f"虛擬驗證器 {authenticator_id} 已移除。")

        # 停用 WebAuthn 域
        client.send("WebAuthn.disable")
        print("WebAuthn 域已停用。")
        input("WAIT Enter")
        # 關閉瀏覽器
        browser.close()
        print("瀏覽器已關閉。")


if __name__ == "__main__":
    webauthn_auto_register_and_login()
