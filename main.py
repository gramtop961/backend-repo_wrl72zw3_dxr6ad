import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr
import jwt
import stripe

from database import db, create_document, get_documents
from schemas import Setting, Service, Payment

# Environment
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "password")
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:3000")
SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SMTP_FROM = os.getenv("SMTP_FROM", "no-reply@sv-adult-health.com")

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

app = FastAPI(title="SV Adult Health Payments API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth utils
bearer_scheme = HTTPBearer()

def create_jwt(payload: dict, expires_minutes: int = 60*24) -> str:
    payload_copy = payload.copy()
    payload_copy["exp"] = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    return jwt.encode(payload_copy, JWT_SECRET, algorithm="HS256")

def verify_jwt(token: str) -> dict:
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return data
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def admin_required(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    data = verify_jwt(credentials.credentials)
    if not data or data.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    return data

# Email utility (best-effort)
import smtplib
from email.mime.text import MIMEText

def send_email(to_email: str, subject: str, body: str):
    if not SMTP_HOST or not SMTP_USERNAME or not SMTP_PASSWORD:
        # SMTP not configured; skip silently
        return
    msg = MIMEText(body, "plain")
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
    except Exception:
        # Do not block payment flow due to email errors
        pass

# Models for requests
class AdminLoginRequest(BaseModel):
    username: str
    password: str

class ServiceCreateRequest(BaseModel):
    name: str
    price: float
    category: Optional[str] = None
    active: bool = True

class ServiceUpdateRequest(BaseModel):
    id: str
    name: Optional[str] = None
    price: Optional[float] = None
    category: Optional[str] = None
    active: Optional[bool] = None

class CheckoutItem(BaseModel):
    name: str
    price: float
    quantity: int = 1

class CheckoutRequest(BaseModel):
    items: List[CheckoutItem] = Field(..., description="Selected services and/or custom amounts")
    patient_name: str
    patient_email: Optional[EmailStr] = None
    patient_phone: Optional[str] = None
    dob: Optional[str] = None
    comment: Optional[str] = None

class ConfirmRequest(BaseModel):
    session_id: str

# Helpers for DB collections
from bson import ObjectId

def collection(name: str):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    return db[name]

# Startup defaults
@app.on_event("startup")
def seed_defaults():
    # If database is not configured, skip seeding to avoid startup failure
    if db is None:
        return
    try:
        # Settings
        settings_col = collection("setting")
        if settings_col.count_documents({}) == 0:
            settings = Setting(
                practice_name="SV Adult Health NP PC",
                practice_address="Brooklyn, NY",
                practice_phone="(555) 123-4567",
                practice_email="clinic@example.com",
            )
            create_document("setting", settings)
        # Services
        services = [
            ("Office visit", 150.0),
            ("Telehealth visit", 120.0),
            ("Joint injection", 180.0),
            ("Migraine injection", 200.0),
            ("Sciatica treatment", 220.0),
            ("Botox", 300.0),
            ("Orthovisc injections", 450.0),
            ("IV therapy and vitamin infusions", 250.0),
            ("Lipo injections", 180.0),
            ("Weight loss program", 299.0),
            ("Ultrasound", 200.0),
        ]
        service_col = collection("service")
        if service_col.count_documents({}) == 0:
            for n, p in services:
                create_document("service", Service(name=n, price=p, category=None, active=True))
    except Exception:
        # Never block startup due to seeding issues
        pass

@app.get("/")
def root():
    return {"status": "ok", "app": "SV Adult Health Payments API"}

@app.get("/test")
def test_database():
    # Reuse existing pattern
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            collections = db.list_collection_names()
            response["collections"] = collections
            response["connection_status"] = "Connected"
    except Exception as e:
        response["database"] = f"⚠️ {str(e)[:80]}"
    return response

# Auth endpoints
@app.post("/api/admin/login")
def admin_login(payload: AdminLoginRequest):
    if payload.username == ADMIN_USERNAME and payload.password == ADMIN_PASSWORD:
        token = create_jwt({"role": "admin", "sub": ADMIN_USERNAME})
        return {"token": token}
    raise HTTPException(status_code=401, detail="Invalid credentials")

# Settings endpoints
@app.get("/api/settings")
def get_settings():
    if db is None:
        # Return default if DB not configured so UI can load
        return {
            "practice_name": "SV Adult Health NP PC",
            "practice_address": "Brooklyn, NY",
            "practice_phone": "",
            "practice_email": "",
            "_id": None,
        }
    doc = collection("setting").find_one({}, sort=[("created_at", -1)])
    if not doc:
        raise HTTPException(status_code=404, detail="Settings not found")
    doc["_id"] = str(doc["_id"]) if "_id" in doc else None
    return doc

class SettingsUpdateRequest(BaseModel):
    practice_name: Optional[str] = None
    practice_address: Optional[str] = None
    practice_phone: Optional[str] = None
    practice_email: Optional[EmailStr] = None

@app.put("/api/admin/settings")
def update_settings(payload: SettingsUpdateRequest, user=Depends(admin_required)):
    settings_col = collection("setting")
    current = settings_col.find_one({}, sort=[("created_at", -1)])
    if not current:
        current = {}
    update_data = {k: v for k, v in payload.model_dump().items() if v is not None}
    update_data["updated_at"] = datetime.now(timezone.utc)
    if "_id" in current:
        settings_col.update_one({"_id": current["_id"]}, {"$set": update_data})
        current.update(update_data)
        current["_id"] = str(current["_id"])  # type: ignore
        return current
    else:
        _id = create_document("setting", update_data)
        created = settings_col.find_one({"_id": ObjectId(_id)})
        created["_id"] = str(created["_id"])  # type: ignore
        return created

# Service endpoints
@app.get("/api/services")
def public_services():
    if db is None:
        # Default list when DB not configured
        defaults = [
            ("Office visit", 150.0),
            ("Telehealth visit", 120.0),
            ("Joint injection", 180.0),
            ("Migraine injection", 200.0),
            ("Sciatica treatment", 220.0),
            ("Botox", 300.0),
            ("Orthovisc injections", 450.0),
            ("IV therapy and vitamin infusions", 250.0),
            ("Lipo injections", 180.0),
            ("Weight loss program", 299.0),
            ("Ultrasound", 200.0),
        ]
        return [{"_id": str(i), "name": n, "price": p, "active": True} for i, (n, p) in enumerate(defaults)]
    docs = list(collection("service").find({"active": True}).sort("name", 1))
    for d in docs:
        d["_id"] = str(d["_id"])  # type: ignore
    return docs

@app.get("/api/admin/services")
def admin_services(user=Depends(admin_required)):
    docs = list(collection("service").find({}).sort("name", 1))
    for d in docs:
        d["_id"] = str(d["_id"])  # type: ignore
    return docs

@app.post("/api/admin/services")
def create_service(payload: ServiceCreateRequest, user=Depends(admin_required)):
    _id = create_document("service", Service(**payload.model_dump()))
    doc = collection("service").find_one({"_id": ObjectId(_id)})
    doc["_id"] = str(doc["_id"])  # type: ignore
    return doc

@app.put("/api/admin/services/{service_id}")
def update_service(service_id: str, payload: ServiceUpdateRequest, user=Depends(admin_required)):
    update = {k: v for k, v in payload.model_dump().items() if v is not None and k != "id"}
    result = collection("service").update_one({"_id": ObjectId(service_id)}, {"$set": update})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Service not found")
    doc = collection("service").find_one({"_id": ObjectId(service_id)})
    doc["_id"] = str(doc["_id"])  # type: ignore
    return doc

@app.delete("/api/admin/services/{service_id}")
def delete_service(service_id: str, user=Depends(admin_required)):
    result = collection("service").delete_one({"_id": ObjectId(service_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Service not found")
    return {"deleted": True}

# Payments
@app.post("/api/create-checkout-session")
def create_checkout_session(payload: CheckoutRequest):
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="Stripe not configured")
    # Build line items
    line_items = []
    for item in payload.items:
        unit_amount = int(round(item.price * 100))
        if unit_amount < 0:
            raise HTTPException(status_code=400, detail="Invalid amount")
        line_items.append({
            "price_data": {
                "currency": "usd",
                "product_data": {"name": item.name},
                "unit_amount": unit_amount,
            },
            "quantity": item.quantity or 1,
        })
    metadata = {
        "patient_name": payload.patient_name,
        "patient_email": payload.patient_email or "",
        "patient_phone": payload.patient_phone or "",
        "dob": payload.dob or "",
        "comment": payload.comment or "",
    }
    try:
        session = stripe.checkout.Session.create(
            mode="payment",
            payment_method_types=["card"],
            allow_promotion_codes=False,
            submit_type="pay",
            customer_email=payload.patient_email if payload.patient_email else None,
            line_items=line_items,
            success_url=f"{APP_BASE_URL}/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{APP_BASE_URL}/",
            metadata=metadata,
        )
        return {"url": session.url, "id": session.id}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/confirm-session")
def confirm_session(payload: ConfirmRequest):
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="Stripe not configured")
    try:
        session = stripe.checkout.Session.retrieve(payload.session_id, expand=["payment_intent", "payment_intent.charges", "line_items"])
        payment_intent = session.payment_intent
        status = payment_intent.status if hasattr(payment_intent, "status") else session.status
        charge = None
        last4 = None
        if hasattr(payment_intent, "charges") and payment_intent.charges and payment_intent.charges.data:
            charge = payment_intent.charges.data[0]
            if charge.payment_method_details and charge.payment_method_details.card:
                last4 = charge.payment_method_details.card.get("last4")
        # Build services list from session
        services_list: List[Dict[str, Any]] = []
        total_amount = 0.0
        if hasattr(session, "line_items") and session.line_items and session.line_items.data:
            for li in session.line_items.data:
                price = 0.0
                if getattr(li, "amount_total", None) is not None:
                    price = li.amount_total / 100.0
                elif getattr(li, "price", None) and getattr(li.price, "unit_amount", None) is not None:
                    price = li.price.unit_amount / 100.0
                services_list.append({"name": li.description or (li.price.nickname if getattr(li, "price", None) else "Service"), "price": price, "quantity": li.quantity})
                total_amount += price * (li.quantity or 1)
        # Fallback if line_items not expanded
        if not services_list:
            total_amount = (session.amount_total or 0) / 100.0
            services_list = [{"name": "Payment", "price": total_amount, "quantity": 1}]
        payment_doc = {
            "payment_id": payment_intent.id if hasattr(payment_intent, "id") else session.id,
            "patient_name": session.metadata.get("patient_name") if session.metadata else None,
            "patient_email": session.metadata.get("patient_email") if session.metadata else None,
            "patient_phone": session.metadata.get("patient_phone") if session.metadata else None,
            "dob": session.metadata.get("dob") if session.metadata else None,
            "comment": session.metadata.get("comment") if session.metadata else None,
            "services": services_list,
            "amount": total_amount,
            "status": status,
            "card_last4": last4,
            "refunded": False,
        }
        # Upsert by payment_id
        col = collection("payment")
        existing = col.find_one({"payment_id": payment_doc["payment_id"]})
        if existing:
            col.update_one({"_id": existing["_id"]}, {"$set": {**payment_doc, "updated_at": datetime.now(timezone.utc)}})
            saved = col.find_one({"_id": existing["_id"]})
        else:
            create_document("payment", payment_doc)
            saved = col.find_one({"payment_id": payment_doc["payment_id"]})
        # Send emails (best-effort)
        settings = None
        try:
            settings = collection("setting").find_one({}, sort=[("created_at", -1)])
        except Exception:
            settings = None
        practice_name = (settings or {}).get("practice_name", "Your Clinic")
        clinic_email = (settings or {}).get("practice_email")
        if payment_doc.get("patient_email"):
            send_email(payment_doc["patient_email"], f"Receipt - {practice_name}", f"Thank you for your payment of ${total_amount:.2f}. Status: {status}.\nPayment ID: {payment_doc['payment_id']}")
        if clinic_email:
            send_email(clinic_email, f"New Payment - {practice_name}", f"A new payment of ${total_amount:.2f} was received from {payment_doc.get('patient_name')}.\nStatus: {status}.\nPayment ID: {payment_doc['payment_id']}")
        saved["_id"] = str(saved["_id"])  # type: ignore
        return saved
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Admin payments listing, filtering, search
from fastapi import Query

@app.get("/api/admin/payments")
def list_payments(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    service: Optional[str] = None,
    q: Optional[str] = Query(default=None, description="Search by name/email/phone"),
    user=Depends(admin_required)
):
    filters: Dict[str, Any] = {}
    date_filter: Dict[str, Any] = {}
    if start_date:
        try:
            dt = datetime.fromisoformat(start_date)
            date_filter["$gte"] = dt
        except Exception:
            pass
    if end_date:
        try:
            dt = datetime.fromisoformat(end_date)
            date_filter["$lte"] = dt
        except Exception:
            pass
    if date_filter:
        filters["created_at"] = date_filter
    if service:
        filters["services.name"] = service
    if q:
        filters["$or"] = [
            {"patient_name": {"$regex": q, "$options": "i"}},
            {"patient_email": {"$regex": q, "$options": "i"}},
            {"patient_phone": {"$regex": q, "$options": "i"}},
        ]
    docs = list(collection("payment").find(filters).sort("created_at", -1))
    for d in docs:
        d["_id"] = str(d["_id"])  # type: ignore
    # Stats
    now = datetime.now(timezone.utc)
    start_today = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
    start_week = start_today - timedelta(days=now.weekday())
    start_month = datetime(now.year, now.month, 1, tzinfo=timezone.utc)
    def total_since(start):
        pipe = [
            {"$match": {"created_at": {"$gte": start}, "status": {"$in": ["succeeded", "processing"]}}},
            {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
        ]
        res = list(collection("payment").aggregate(pipe))
        return round(res[0]["total"], 2) if res else 0.0
    stats = {
        "today": total_since(start_today),
        "week": total_since(start_week),
        "month": total_since(start_month),
    }
    return {"items": docs, "stats": stats}

@app.post("/api/admin/payments/{payment_id}/mark-refunded")
def mark_refunded(payment_id: str, user=Depends(admin_required)):
    col = collection("payment")
    doc = col.find_one({"_id": ObjectId(payment_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Payment not found")
    col.update_one({"_id": doc["_id"]}, {"$set": {"refunded": True, "status": "refunded", "updated_at": datetime.now(timezone.utc)}})
    doc = col.find_one({"_id": doc["_id"]})
    doc["_id"] = str(doc["_id"])  # type: ignore
    return doc

# CSV export
import csv
from io import StringIO

@app.get("/api/admin/payments/export")
def export_payments_csv(user=Depends(admin_required)):
    col = collection("payment")
    docs = list(col.find({}).sort("created_at", -1))
    csv_buffer = StringIO()
    writer = csv.writer(csv_buffer)
    writer.writerow(["Payment ID", "Date", "Patient Name", "Email", "Phone", "Services", "Amount", "Status", "Card Last4", "Refunded"])    
    for d in docs:
        services_str = "; ".join([f"{s.get('name')} x{s.get('quantity',1)} ${s.get('price')}" for s in d.get("services", [])])
        writer.writerow([
            d.get("payment_id"),
            d.get("created_at").isoformat() if d.get("created_at") else "",
            d.get("patient_name"),
            d.get("patient_email"),
            d.get("patient_phone"),
            services_str,
            d.get("amount"),
            d.get("status"),
            d.get("card_last4"),
            d.get("refunded"),
        ])
    csv_data = csv_buffer.getvalue()
    return Response(content=csv_data, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=payments.csv"})

# Optional webhook for production setups
@app.post("/stripe/webhook")
async def stripe_webhook(request: Request):
    if not STRIPE_WEBHOOK_SECRET:
        return {"received": True}
    payload = await request.body()
    sig = request.headers.get('stripe-signature')
    try:
        event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        # After completion, we can attempt to confirm and store
        try:
            confirm_session(ConfirmRequest(session_id=session['id']))
        except Exception:
            pass
    return {"received": True}

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
