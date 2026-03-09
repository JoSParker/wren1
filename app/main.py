from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from .proxy import forward_request
from .config import WREN_API_KEYS
import httpx
import sqlite3
import os

app = FastAPI(title="Wren AI Security Gateway")

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# SQLite Database for API Keys (Simplified for demo)
DB_PATH = "wren.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    return conn

async def validate_wren_key(request: Request):
    x_wren_key = request.headers.get("x-wren-key")
    if not x_wren_key:
        raise HTTPException(status_code=401, detail="Missing API Key")

    # Local key fallback
    if x_wren_key in WREN_API_KEYS:
        class MockKey:
            def __init__(self, tenant_id):
                self.tenant_id = tenant_id
        return MockKey("demo-tenant")

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT tenant_id FROM api_keys WHERE key = ?", (x_wren_key,))
    cached = cursor.fetchone()
    db.close()

    if cached:
        class MockKey:
            def __init__(self, tenant_id):
                self.tenant_id = tenant_id
        return MockKey(cached[0])

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://api.wren.security/auth/validate",
                headers={"Authorization": f"Bearer {x_wren_key}"}
            )
            if resp.status_code == 200:
                data = resp.json()
                return data
            else:
                raise HTTPException(status_code=401, detail="Invalid API Key")
    except Exception:
        raise HTTPException(status_code=401, detail="Unauthorized")

@app.post("/v1/chat/completions")
async def chat_completions(request: Request, auth=Depends(validate_wren_key)):
    request.state.tenant_id = auth.tenant_id if hasattr(auth, "tenant_id") else "default"
    return await forward_request(request)

@app.get("/health")
async def health():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)