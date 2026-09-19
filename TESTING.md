# Testing checklist

- [ ] Backend starts on 127.0.0.1:8765.
- [ ] Extension shows BACKEND • ONLINE.
- [ ] Test email `test@example.com` appears in page text → Scan detects Email.
- [ ] An input named `email` with a value → Scan reports field name Email.
- [ ] Phone, Aadhaar, PAN, card, IP and IBAN patterns are detected.
- [ ] Capture + Redact masks detected form fields and text locally.
- [ ] PII tickets show ✓ after redaction and ✕ before redaction.
- [ ] Action Log records scan, redact, save, autofill, command and submit actions.
- [ ] Save Current Form stores sensitive and non-sensitive values encrypted.
- [ ] Backend `data/vault.json` contains ciphertext fields only; never plaintext form values.
- [ ] Clear form → Fill Saved restores sensitive + non-sensitive fields.
- [ ] Kill Switch blocks commands; Continue re-enables them.
- [ ] Main page and same-origin/cross-origin accessible iframes are scanned when Chrome permits the frame.
