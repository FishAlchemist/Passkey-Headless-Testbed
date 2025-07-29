# Passkey-Headless-Testbed

這個儲存庫旨在探索和驗證 Passkey 在無頭 (Headless) 自動化環境下的測試可行性。

## 專案概述
**主要目標：**
- 驗證 Passkey 註冊 (Registration) 流程在無頭瀏覽器環境下的自動化可行性。
- 驗證 Passkey 登入 (Authentication) 流程在無頭瀏覽器環境下的自動化可行性。

## 專案結構

- `playwright_testbed/`: 包含使用 `Playwright` 撰寫的自動化腳本，模擬瀏覽器使用者操作。
- `py_webauthn_testbed/`: 包含基於 `py_webauthn` 庫的程式碼，可能用於模擬 WebAuthn 伺服器端或輔助處理 WebAuthn 訊息。

## 註記
我個人認為使用 Playwright 較為適合，因為 Playwright 是多程式語言支援的，一些 WebAuthn API 的更新也能跟著瀏覽器更新。
