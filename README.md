# PrivacyPilot V6.1 — SHI-ready local backend prototype

## Architecture
Chrome extension → localhost FastAPI (127.0.0.1:8765).

PII values are never written to backend logs or plaintext vault storage. Form data is encrypted in the extension with AES-GCM before `/api/vault/save`; the backend stores ciphertext only. `/api/scan` receives page text only for in-memory detection and does not persist it.

## Install
1. Extract this folder.
2. Run `backend/run_backend.bat`.
3. Chrome → `chrome://extensions` → Developer mode → Load unpacked → select `extension`.
4. Reload the target webpage.
5. Open PrivacyPilot.

## Demo
Scan Page → Capture + Redact → Save Current Form → clear fields → Fill Saved.
Sensitive and non-sensitive values are both restored locally after decrypting the device-local vault record.

## Important limitation
This is a competition prototype, not a security-certified password manager. AES-GCM protects the stored vault record, but the encryption key is held by the extension so the same installed extension can decrypt it for autofill.
# SIH
