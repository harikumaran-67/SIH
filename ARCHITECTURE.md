# Architecture

Browser page/iframes → Chrome content scripts → local PII detection/redaction/form automation.
Extension service worker → localhost FastAPI for in-memory scan/analyze/chat and encrypted-ciphertext vault storage.
No cloud endpoint is configured. Backend binds to 127.0.0.1 only.
