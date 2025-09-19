import os, hmac, hashlib, json
from fastapi import FastAPI, Request, HTTPException, Query
from fastapi.responses import PlainTextResponse
import httpx

app = FastAPI()

VERIFY_TOKEN = os.getenv("VERIFY_TOKEN")
APP_SECRET   = os.getenv("APP_SECRET")
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN")
PHONE_NUMBER_ID = os.getenv("PHONE_NUMBER_ID")
GRAPH_URL = os.getenv("GRAPH_URL", "https://graph.facebook.com/v21.0")

@app.get("/")
async def verify(
    hub_mode: str = Query(None, alias="hub.mode"),
    hub_challenge: str = Query(None, alias="hub.challenge"),
    hub_verify_token: str = Query(None, alias="hub.verify_token"),
):
    if hub_mode == "subscribe" and hub_verify_token == VERIFY_TOKEN:
        return PlainTextResponse(hub_challenge or "")
    raise HTTPException(status_code=403, detail="Verification failed")

def _valid_signature(app_secret: str, body: bytes, xhub: str | None) -> bool:
    if not app_secret or not xhub:
        return False
    try:
        prefix, their = xhub.split("=", 1)
        if prefix != "sha256":
            return False
    except ValueError:
        return False
    digest = hmac.new(app_secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(their, digest)

@app.post("/")
async def webhook(request: Request):
    raw = await request.body()
    sig = request.headers.get("X-Hub-Signature-256") or request.headers.get("X-Hub-Signature")
    if APP_SECRET and not _valid_signature(APP_SECRET, raw, sig):
        raise HTTPException(status_code=403, detail="Invalid signature")

    payload = json.loads(raw.decode("utf-8") or "{}")
    entries = payload.get("entry", []) or []
    for entry in entries:
        for change in entry.get("changes", []) or []:
            value = change.get("value", {}) or {}
            for msg in value.get("messages", []) or []:
                from_ = msg.get("from")
                if msg.get("type") == "text" and from_:
                    text = msg.get("text", {}).get("body", "")
                    await send_text(from_, f"Вы написали: {text}")

    return PlainTextResponse("EVENT_RECEIVED")

async def send_text(to: str, body: str):
    if not (WHATSAPP_TOKEN and PHONE_NUMBER_ID):
        return
    url = f"{GRAPH_URL}/{PHONE_NUMBER_ID}/messages"
    headers = {"Authorization": f"Bearer {WHATSAPP_TOKEN}", "Content-Type": "application/json"}
    data = {"messaging_product": "whatsapp", "to": to, "text": {"body": body}}
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(url, headers=headers, json=data)
        r.raise_for_status()
