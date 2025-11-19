import os
import base64
from io import BytesIO
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional

import pyotp
import qrcode

from database import db, create_document

app = FastAPI(title="2FA Service")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class SetupRequest(BaseModel):
    user_id: str = Field(..., description="Unique user identifier")
    issuer: str = Field(default="Flames 2FA", description="Issuer shown in authenticator apps")
    label: Optional[str] = Field(default=None, description="Account label shown in authenticator apps")


class VerifyRequest(BaseModel):
    user_id: str
    code: str


class DisableRequest(BaseModel):
    user_id: str


@app.get("/")
def read_root():
    return {"message": "2FA backend running"}


@app.get("/api/hello")
def hello():
    return {"message": "Hello from the backend API!"}


@app.get("/test")
def test_database():
    """Test endpoint to check if database is available and accessible"""
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }

    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"

            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"

    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"

    return response


def _generate_qr_data_url(text: str) -> str:
    qr = qrcode.QRCode(box_size=8, border=2)
    qr.add_data(text)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    b64 = base64.b64encode(buffer.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{b64}"


@app.post("/2fa/setup")
def setup_2fa(req: SetupRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")

    collection = db["twofasecret"]

    # Use provided label or default to user_id
    label = req.label or req.user_id

    # Check existing secret
    existing = collection.find_one({"user_id": req.user_id})

    if existing and existing.get("secret"):
        secret = existing["secret"]
        enabled = bool(existing.get("enabled", False))
    else:
        secret = pyotp.random_base32()
        enabled = False
        # create new document with timestamps via helper for consistency
        try:
            # create_document adds timestamps; we still want to keep only one per user
            # so we will upsert below. create_document not strictly needed but kept for audit trail
            create_document("twofasecret_audit", {
                "user_id": req.user_id,
                "action": "create_secret",
                "issuer": req.issuer,
                "label": label,
                "secret_tail": secret[-4:],
            })
        except Exception:
            pass

    totp = pyotp.TOTP(secret)
    otpauth_url = totp.provisioning_uri(name=label, issuer_name=req.issuer)
    qr_data_url = _generate_qr_data_url(otpauth_url)

    # Upsert record
    collection.update_one(
        {"user_id": req.user_id},
        {"$set": {
            "user_id": req.user_id,
            "secret": secret,
            "issuer": req.issuer,
            "label": label,
            "enabled": enabled,
        }},
        upsert=True,
    )

    return {
        "user_id": req.user_id,
        "issuer": req.issuer,
        "label": label,
        "secret": secret,
        "otpauth_url": otpauth_url,
        "qr_data_url": qr_data_url,
        "enabled": enabled,
    }


@app.post("/2fa/verify")
def verify_2fa(req: VerifyRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")

    doc = db["twofasecret"].find_one({"user_id": req.user_id})
    if not doc:
        raise HTTPException(status_code=404, detail="2FA not set up for this user")

    secret = doc.get("secret")
    totp = pyotp.TOTP(secret)

    try:
        is_valid = totp.verify(req.code, valid_window=1)
    except Exception:
        is_valid = False

    if not is_valid:
        return {"success": False, "verified": False, "enabled": bool(doc.get("enabled", False))}

    # Mark enabled after first successful verification
    db["twofasecret"].update_one({"user_id": req.user_id}, {"$set": {"enabled": True}})

    return {"success": True, "verified": True, "enabled": True}


@app.get("/2fa/status")
def status_2fa(user_id: str = Query(..., description="User identifier")):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")

    doc = db["twofasecret"].find_one({"user_id": user_id}, {"_id": 0, "secret": 0})
    if not doc:
        return {"user_id": user_id, "enabled": False, "configured": False}
    doc["configured"] = True
    return doc


@app.post("/2fa/disable")
def disable_2fa(req: DisableRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")

    res = db["twofasecret"].update_one({"user_id": req.user_id}, {"$set": {"enabled": False}})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="2FA not set up for this user")
    return {"success": True, "enabled": False}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
