import os
from dotenv import load_dotenv

load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.openai.com")

MOCK_MODE = os.getenv("MOCK_MODE", "true").lower() == "true"
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if GEMINI_API_KEY:
    print(f"[Wren Config] Gemini API Key loaded. Prefix: {GEMINI_API_KEY[:5]}...", flush=True)
else:
    print("[Wren Config] WARNING: Gemini API Key NOT found in environment.", flush=True)

WREN_API_KEYS = {
    "acme-secret-key",
    "demo-secret-key"
}