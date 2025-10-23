from fastapi import FastAPI, APIRouter, HTTPException, Depends, Header
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
import string
import secrets
import re
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
from passlib.context import CryptContext
import pandas as pd
from fastapi.responses import StreamingResponse
from fastapi import UploadFile, File
import io
import hashlib

# ----------------------
# Init & Config
# ----------------------
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

mongo_url = os.environ.get('MONGO_URL')
if not mongo_url:
    raise RuntimeError("MONGO_URL not set in environment")

client = AsyncIOMotorClient(mongo_url)
db = client[os.environ.get('DB_NAME', 'app_db')]

app = FastAPI()
api_router = APIRouter(prefix="/api")

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ----------------------
# Helpers
# ----------------------
PWD_CTX = CryptContext(schemes=["bcrypt"], deprecated="auto")
JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret-change-me")
JWT_ALG = "HS256"
JWT_EXPIRE_DAYS = 7

ID_RE = re.compile(r"^[A-Z0-9]{18}$")


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def new_id(length: int = 18) -> str:
    # 18-char uppercase alphanumeric ID
    alphabet = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def is_valid_id18(x: Optional[str]) -> bool:
    return bool(x and ID_RE.fullmatch(x))


def ensure_valid_or_400(label: str, x: Optional[str]):
    if not is_valid_id18(x):
        raise HTTPException(status_code=400, detail=f"{label} harus 18 karakter alfanumerik huruf besar")


def hash_password(pw: str) -> str:
    return PWD_CTX.hash(pw)


def verify_password(pw: str, hashed: str) -> bool:
    try:
        return PWD_CTX.verify(pw, hashed)
    except Exception:
        return False


def generate_session_token() -> str:
    """Generate a secure random session token"""
    random_bytes = secrets.token_bytes(32)
    return hashlib.sha256(random_bytes).hexdigest()


async def create_session(user: Dict[str, Any]) -> str:
    """Create a new session in database and return token"""
    session_token = generate_session_token()
    session = {
        "id": new_id(),
        "token": session_token,
        "user_id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "workshop_id": user.get("workshop_id"),
        "created_at": now_iso(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=JWT_EXPIRE_DAYS)).isoformat(),
        "last_activity": now_iso(),
    }
    await db.sessions.insert_one({**session})
    return session_token


async def verify_session(token: str) -> Optional[Dict[str, Any]]:
    """Verify session token from database"""
    session = await db.sessions.find_one({"token": token})
    if not session:
        return None
    
    # Check if session expired
    expires_at = datetime.fromisoformat(session["expires_at"])
    if expires_at < datetime.now(timezone.utc):
        # Delete expired session
        await db.sessions.delete_one({"token": token})
        return None
    
    # Update last activity
    await db.sessions.update_one(
        {"token": token},
        {"$set": {"last_activity": now_iso()}}
    )
    
    return session


def create_token(user: Dict[str, Any]) -> str:
    """Legacy function - kept for backward compatibility but will use session-based auth"""
    payload = {
        "sub": user["id"],
        "username": user["username"],
        "role": user["role"],
        "workshop_id": user.get("workshop_id"),
        "exp": datetime.now(timezone.utc) + timedelta(days=JWT_EXPIRE_DAYS),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def safe_doc(doc: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not doc:
        return doc
    d = dict(doc)
    d.pop("_id", None)
    return d


async def get_current_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    """Verify user from session database"""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    token = authorization.split(" ", 1)[1].strip()
    
    # Verify session from database
    session = await verify_session(token)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    
    # Get user from database
    user = await db.users.find_one({"id": session["user_id"]})
    if not user:
        # User deleted, remove session
        await db.sessions.delete_one({"token": token})
        raise HTTPException(status_code=401, detail="User not found")
    
    return user


# ----------------------
# Models
# ----------------------
class AuthLogin(BaseModel):
    username: str
    password: str


class AuthRegister(BaseModel):
    username: str
    password: str
    role: str = Field(pattern="^(owner|employee)$")
    email: Optional[str] = None
    workshop_name: Optional[str] = None  # required when role=owner
    workshop_id: Optional[str] = None    # required when role=employee


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: Dict[str, Any]


class UpdateUserProfile(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    current_password: Optional[str] = None
    new_password: Optional[str] = None


class NewCustomer(BaseModel):
    name: str
    phone: str


class NewServiceSession(BaseModel):
    customer_id: str
    session_name: str


class NewServiceItem(BaseModel):
    customer_id: str
    service_session_id: str
    description: str
    price: float


class UpdateServiceItem(BaseModel):
    description: str
    price: float


class NewPayment(BaseModel):
    customer_id: str
    amount: float
    description: Optional[str] = ""
    service_session_id: Optional[str] = None


class UpdatePayment(BaseModel):
    amount: float
    description: Optional[str] = ""


# Workshop Models
class UpdateWorkshopName(BaseModel):
    workshop_name: str


# Products Models
class NewProduct(BaseModel):
    code: str
    name: str
    stock: int = 0
    unit: str = "pcs"
    cost_price: float = 0.0
    sale_price: float = 0.0
    workshop_price: float = 0.0
    note: Optional[str] = ""

class UpdateProduct(BaseModel):
    code: Optional[str] = None
    name: Optional[str] = None
    stock: Optional[int] = None
    unit: Optional[str] = None
    cost_price: Optional[float] = None
    sale_price: Optional[float] = None
    workshop_price: Optional[float] = None
    note: Optional[str] = None

class AdjustStock(BaseModel):
    delta: int

class DeleteSessionResult(BaseModel):
    session_id: str
    deleted: bool
    deleted_counts: Dict[str, int]


# ----------------------
# Basic Root & Health
# ----------------------
@api_router.get("/")
async def root():
    return {"message": "hello world"}


@api_router.get("/db/ping")
async def db_ping():
    try:
        names = await db.list_collection_names()
        return {"ok": True, "collections": names}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DB ping failed: {e}")


# ----------------------
# Auth Endpoints
# ----------------------
@api_router.post("/auth/register", response_model=TokenResponse)
async def register(input: AuthRegister):
    # Validate role specific fields
    if input.role == "owner" and not input.workshop_name:
        raise HTTPException(status_code=400, detail="workshop_name diperlukan untuk owner")
    if input.role == "employee" and not input.workshop_id:
        raise HTTPException(status_code=400, detail="workshop_id diperlukan untuk employee")

    # Validate workshop_id untuk employee
    if input.role == "employee":
        if not input.workshop_id or len(input.workshop_id.strip()) == 0:
            raise HTTPException(status_code=400, detail="ID Bengkel tidak boleh kosong")

    existing = await db.users.find_one({"username": input.username})
    if existing:
        raise HTTPException(status_code=409, detail="Username sudah terpakai")

    user = {
        "id": new_id(),
        "username": input.username,
        "email": input.email or "",
        "role": input.role,
        "password_hash": hash_password(input.password),
        "created_at": now_iso(),
    }

    if input.role == "owner":
        # Generate workshop_id for owner (18-char alphanumeric)
        wid = new_id(18)
        user.update({"workshop_id": wid, "workshop_name": input.workshop_name})
    else:
        # For employee: find existing workshop and get workshop_name
        # Try exact match first, then case-insensitive, then partial match
        search_id = input.workshop_id.strip()
        existing_workshop = None
        
        # 1. Exact match
        existing_workshop = await db.users.find_one({"workshop_id": search_id, "role": "owner"})
        
        # 2. Case-insensitive match
        if not existing_workshop:
            existing_workshop = await db.users.find_one({
                "workshop_id": {"$regex": f"^{re.escape(search_id)}$", "$options": "i"}, 
                "role": "owner"
            })
        
        # 3. Partial match (starts with)
        if not existing_workshop:
            existing_workshop = await db.users.find_one({
                "workshop_id": {"$regex": f"^{re.escape(search_id.upper())}", "$options": "i"}, 
                "role": "owner"
            })
        
        if not existing_workshop:
            raise HTTPException(status_code=404, detail=f"ID Bengkel '{search_id}' tidak ditemukan. Pastikan ID bengkel benar dan bengkel sudah terdaftar.")
        
        actual_workshop_id = existing_workshop.get("workshop_id")
        workshop_name = existing_workshop.get("workshop_name", "")
        user.update({"workshop_id": actual_workshop_id, "workshop_name": workshop_name})

    await db.users.insert_one({**user})
    
    # Create session in database instead of JWT
    session_token = await create_session(user)
    
    safe_user = {k: user[k] for k in ["id", "username", "role", "workshop_id", "workshop_name"]}
    return TokenResponse(access_token=session_token, user=safe_user)


@api_router.post("/auth/login", response_model=TokenResponse)
async def login(input: AuthLogin):
    user = await db.users.find_one({"username": input.username})
    if not user or not verify_password(input.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Username atau password salah")
    
    # Create session in database
    session_token = await create_session(user)
    
    safe_user = {k: user.get(k, None) for k in ["id", "username", "role", "workshop_id", "workshop_name"]}
    return TokenResponse(access_token=session_token, user=safe_user)


@api_router.get("/auth/me")
async def me(user=Depends(get_current_user)):
    return {k: user.get(k) for k in ["id", "username", "role", "workshop_id", "workshop_name", "email", "created_at"]}


@api_router.post("/auth/logout")
async def logout(authorization: Optional[str] = Header(None)):
    """Logout user and delete session from database"""
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        # Delete session from database
        await db.sessions.delete_one({"token": token})
    return {"success": True, "message": "Logged out successfully"}


@api_router.put("/auth/profile")
async def update_profile(body: UpdateUserProfile, user=Depends(get_current_user)):
    user_id = user.get("id")
    updates = {}
    
    # Update username if provided and different
    if body.username and body.username != user.get("username"):
        # Check if username already exists
        existing = await db.users.find_one({"username": body.username, "id": {"$ne": user_id}})
        if existing:
            raise HTTPException(status_code=409, detail="Username sudah terpakai")
        updates["username"] = body.username
    
    # Update email if provided
    if body.email is not None:
        updates["email"] = body.email
    
    # Update password if provided
    if body.new_password and body.current_password:
        if not verify_password(body.current_password, user.get("password_hash", "")):
            raise HTTPException(status_code=400, detail="Password lama tidak benar")
        updates["password_hash"] = hash_password(body.new_password)
    elif body.new_password and not body.current_password:
        raise HTTPException(status_code=400, detail="Password lama diperlukan untuk mengubah password")
    
    if not updates:
        raise HTTPException(status_code=400, detail="Tidak ada perubahan yang diberikan")
    
    # Update user
    updates["updated_at"] = now_iso()
    await db.users.update_one({"id": user_id}, {"$set": updates})
    
    # Get updated user
    updated_user = await db.users.find_one({"id": user_id})
    return {k: updated_user.get(k) for k in ["id", "username", "role", "workshop_id", "workshop_name", "email", "created_at", "updated_at"]}


# ----------------------
# Workshop Management
# ----------------------
@api_router.get("/workshop/detail")
async def get_workshop_detail(user=Depends(get_current_user)):
    """Get workshop detail with owner info and employee count"""
    if user.get("role") not in ["owner", "employee"]:
        raise HTTPException(status_code=403, detail="Akses ditolak")
    
    workshop_id = user.get("workshop_id")
    if not workshop_id:
        raise HTTPException(status_code=404, detail="Workshop tidak ditemukan")
    
    # Get owner info
    owner = await db.users.find_one({"workshop_id": workshop_id, "role": "owner"})
    if not owner:
        raise HTTPException(status_code=404, detail="Owner workshop tidak ditemukan")
    
    # Count employees
    employee_count = await db.users.count_documents({"workshop_id": workshop_id, "role": "employee"})
    
    # Count customers
    customer_count = await db.customers.count_documents({"workshop_id": workshop_id})
    
    return {
        "workshop_id": workshop_id,
        "workshop_name": owner.get("workshop_name", ""),
        "owner": {
            "id": owner.get("id"),
            "username": owner.get("username"),
            "email": owner.get("email", ""),
            "created_at": owner.get("created_at", "")
        },
        "employee_count": employee_count,
        "customer_count": customer_count,
        "created_at": owner.get("created_at", "")
    }


@api_router.put("/workshop/name")
async def update_workshop_name(body: UpdateWorkshopName, user=Depends(get_current_user)):
    """Update workshop name (owner only)"""
    if user.get("role") != "owner":
        raise HTTPException(status_code=403, detail="Hanya owner yang bisa mengubah nama bengkel")
    
    workshop_id = user.get("workshop_id")
    if not workshop_id:
        raise HTTPException(status_code=404, detail="Workshop tidak ditemukan")
    
    new_name = body.workshop_name.strip()
    if not new_name:
        raise HTTPException(status_code=400, detail="Nama bengkel tidak boleh kosong")
    
    # Update workshop name for owner and all employees
    await db.users.update_many(
        {"workshop_id": workshop_id},
        {"$set": {"workshop_name": new_name, "updated_at": now_iso()}}
    )
    
    return {"success": True, "workshop_name": new_name}


@api_router.get("/workshop/employees")
async def get_workshop_employees(user=Depends(get_current_user)):
    """Get list of employees in workshop (owner only)"""
    if user.get("role") != "owner":
        raise HTTPException(status_code=403, detail="Hanya owner yang bisa melihat daftar karyawan")
    
    workshop_id = user.get("workshop_id")
    if not workshop_id:
        raise HTTPException(status_code=404, detail="Workshop tidak ditemukan")
    
    employees = await db.users.find(
        {"workshop_id": workshop_id, "role": "employee"}
    ).to_list(length=None)
    
    employee_list = []
    for emp in employees:
        employee_list.append({
            "id": emp.get("id"),
            "username": emp.get("username"),
            "email": emp.get("email", ""),
            "created_at": emp.get("created_at", "")
        })
    
    return {"employees": employee_list}


@api_router.delete("/workshop/employees/{employee_id}")
async def delete_employee(employee_id: str, user=Depends(get_current_user)):
    """Delete employee from workshop (owner only)"""
    if user.get("role") != "owner":
        raise HTTPException(status_code=403, detail="Hanya owner yang bisa menghapus karyawan")
    
    ensure_valid_or_400("employee_id", employee_id)
    
    workshop_id = user.get("workshop_id")
    if not workshop_id:
        raise HTTPException(status_code=404, detail="Workshop tidak ditemukan")
    
    # Verify employee exists and belongs to same workshop
    employee = await db.users.find_one({"id": employee_id, "workshop_id": workshop_id, "role": "employee"})
    if not employee:
        raise HTTPException(status_code=404, detail="Karyawan tidak ditemukan")
    
    # Delete employee
    result = await db.users.delete_one({"id": employee_id})
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Gagal menghapus karyawan")
    
    return {"success": True, "deleted_employee_id": employee_id}


# ----------------------
# Customers
# ----------------------
@api_router.post("/customers")
async def add_customer(body: NewCustomer, user=Depends(get_current_user)):
    cust = {
        "id": new_id(),
        "name": body.name,
        "phone": body.phone,
        "workshop_id": user.get("workshop_id"),
        "created_at": now_iso(),
    }
    await db.customers.insert_one({**cust})
    return {"customer": safe_doc(cust)}


@api_router.delete("/customers/{customer_id}")
async def delete_customer(customer_id: str, user=Depends(get_current_user)):
    ensure_valid_or_400("customer_id", customer_id)
    # Hapus semua data pelanggan: sessions, services, payments (& audits)
    sessions = await db.service_sessions.find({"customer_id": customer_id}).to_list(length=None)
    session_ids = [s.get("id") for s in sessions if s.get("id")]

    # Related deletions
    await db.services.delete_many({"customer_id": customer_id})
    pays = await db.payments.find({"customer_id": customer_id}).to_list(length=None)
    pay_ids = [p.get("id") for p in pays if p.get("id")]
    await db.payments.delete_many({"customer_id": customer_id})
    try:
        await db.payment_audits.delete_many({"payment_id": {"$in": pay_ids}})
    except Exception:
        pass
    await db.service_sessions.delete_many({"id": {"$in": session_ids}})

    res = await db.customers.delete_one({"id": customer_id, "workshop_id": user.get("workshop_id")})
    if getattr(res, "deleted_count", 0) == 0:
        raise HTTPException(status_code=404, detail="Pelanggan tidak ditemukan")
    return {"deleted": True}


@api_router.get("/customers/{customer_id}/summary")
async def customer_summary(customer_id: str, user=Depends(get_current_user)):
    ensure_valid_or_400("customer_id", customer_id)
    cust = await db.customers.find_one({"id": customer_id, "workshop_id": user.get("workshop_id")})
    if not cust:
        raise HTTPException(status_code=404, detail="Pelanggan tidak ditemukan")

    sessions = await db.service_sessions.find({"customer_id": customer_id}).to_list(length=None)
    result_sessions = []
    total_services_amount = 0.0
    total_payments_amount = 0.0

    for ss in sessions:
        ss_id = ss["id"]
        services = await db.services.find({"service_session_id": ss_id}).to_list(length=None)
        payments = await db.payments.find({"service_session_id": ss_id}).to_list(length=None)
        sum_services = sum(float(s.get("price", 0)) for s in services)
        sum_payments = sum(float(p.get("amount", 0)) for p in payments)
        total_services_amount += sum_services
        total_payments_amount += sum_payments
        result_sessions.append({
            "session": {
                "id": ss_id,
                "session_name": ss.get("session_name", "Sesi"),
                "session_date": ss.get("session_date", now_iso()),
            },
            "services": [{"id": s.get("id"), "description": s.get("description"), "price": s.get("price", 0)} for s in services],
            "payments": [{"id": p.get("id"), "amount": p.get("amount", 0), "description": p.get("description", ""), "payment_date": p.get("payment_date", now_iso())} for p in payments],
            "remaining_debt": round(sum_services - sum_payments, 2)
        })

    # Tambahkan pembayaran umum (tanpa service_session_id) ke total customer
    general_payments = await db.payments.find({"customer_id": customer_id, "service_session_id": None}).to_list(length=None)
    total_payments_amount += sum(float(p.get("amount", 0)) for p in general_payments)

    customer_remaining_debt = round(total_services_amount - total_payments_amount, 2)
    summary = {
        "customer": {"id": cust["id"], "name": cust["name"], "phone": cust.get("phone", "")},
        "service_sessions": result_sessions,
        "total_services_amount": round(total_services_amount, 2),
        "total_payments_amount": round(total_payments_amount, 2),
        "remaining_debt": customer_remaining_debt,
    }
    return summary


# ----------------------
# Service Sessions
# ----------------------
@api_router.post("/service-sessions")
async def create_service_session(body: NewServiceSession, user=Depends(get_current_user)):
    ensure_valid_or_400("customer_id", body.customer_id)
    # Validate customer exists
    cust = await db.customers.find_one({"id": body.customer_id, "workshop_id": user.get("workshop_id")})
    if not cust:
        raise HTTPException(status_code=404, detail="Pelanggan tidak ditemukan")
    ss = {
        "id": new_id(),
        "customer_id": body.customer_id,
        "workshop_id": user.get("workshop_id"),
        "session_name": body.session_name,
        "session_date": now_iso(),
        "created_at": now_iso(),
    }
    await db.service_sessions.insert_one({**ss})
    return {"session": safe_doc(ss)}


@api_router.delete("/service-sessions/{session_id}", response_model=DeleteSessionResult)
async def delete_service_session(session_id: str, user=Depends(get_current_user)):
    ensure_valid_or_400("session_id", session_id)
    deleted_counts: Dict[str, int] = {"services": 0, "payments": 0, "payment_audits": 0, "service_sessions": 0, "general_payments": 0}

    # Find session to ensure workshop scope
    session_doc = await db.service_sessions.find_one({"id": session_id, "workshop_id": user.get("workshop_id")})
    if not session_doc:
        # idempotent: still return ok with zeros
        return DeleteSessionResult(session_id=session_id, deleted=False, deleted_counts=deleted_counts)

    customer_id = session_doc.get("customer_id")

    # Fetch related payments to gather ids for audits
    payments = await db.payments.find({"service_session_id": session_id}).to_list(length=None)
    payment_ids = [p.get("id") for p in payments if p.get("id")]

    res_services = await db.services.delete_many({"service_session_id": session_id})
    deleted_counts["services"] = getattr(res_services, "deleted_count", 0)

    res_payments = await db.payments.delete_many({"service_session_id": session_id})
    deleted_counts["payments"] = getattr(res_payments, "deleted_count", 0)

    try:
        res_audits = await db.payment_audits.delete_many({"payment_id": {"$in": payment_ids}})
        deleted_counts["payment_audits"] = getattr(res_audits, "deleted_count", 0)
    except Exception:
        deleted_counts["payment_audits"] = 0

    res_session = await db.service_sessions.delete_one({"id": session_id})
    deleted_counts["service_sessions"] = getattr(res_session, "deleted_count", 0)

    # Check if there are any remaining sessions for this customer
    remaining_sessions_count = await db.service_sessions.count_documents({"customer_id": customer_id})
    
    # If no more sessions exist for this customer, delete general payments (sisa uang)
    if remaining_sessions_count == 0:
        res_general = await db.payments.delete_many({
            "customer_id": customer_id,
            "service_session_id": None
        })
        deleted_counts["general_payments"] = getattr(res_general, "deleted_count", 0)

    deleted = any(v > 0 for v in deleted_counts.values())
    return DeleteSessionResult(session_id=session_id, deleted=deleted, deleted_counts=deleted_counts)


# ----------------------
# Services
# ----------------------
@api_router.post("/services")
async def add_service(body: NewServiceItem, user=Depends(get_current_user)):
    ensure_valid_or_400("customer_id", body.customer_id)
    ensure_valid_or_400("service_session_id", body.service_session_id)
    # Validate session ownership
    ss = await db.service_sessions.find_one({"id": body.service_session_id, "workshop_id": user.get("workshop_id")})
    if not ss:
        raise HTTPException(status_code=404, detail="Sesi tidak ditemukan")
    svc = {
        "id": new_id(),
        "customer_id": body.customer_id,
        "service_session_id": body.service_session_id,
        "description": body.description,
        "price": float(body.price),
        "created_at": now_iso(),
    }
    await db.services.insert_one({**svc})
    return {"service": safe_doc(svc)}


@api_router.put("/services/{service_id}")
async def update_service(service_id: str, body: UpdateServiceItem, user=Depends(get_current_user)):
    ensure_valid_or_400("service_id", service_id)
    svc = await db.services.find_one({"id": service_id})
    if not svc:
        raise HTTPException(status_code=404, detail="Item servis tidak ditemukan")
    await db.services.update_one({"id": service_id}, {"$set": {"description": body.description, "price": float(body.price)}})
    svc = await db.services.find_one({"id": service_id})
    return {"service": safe_doc(svc)}


@api_router.delete("/services/{service_id}")
async def delete_service(service_id: str, user=Depends(get_current_user)):
    ensure_valid_or_400("service_id", service_id)
    res = await db.services.delete_one({"id": service_id})
    return {"deleted": getattr(res, "deleted_count", 0) > 0}


# ----------------------
# Payments
# ----------------------
@api_router.post("/payments")
async def add_payment(body: NewPayment, user=Depends(get_current_user)):
    ensure_valid_or_400("customer_id", body.customer_id)
    if body.service_session_id is not None:
        ensure_valid_or_400("service_session_id", body.service_session_id)
    # Jika memilih sesi tertentu, simpan langsung
    if body.service_session_id:
        pay = {
            "id": new_id(),
            "customer_id": body.customer_id,
            "service_session_id": body.service_session_id,
            "amount": float(body.amount),
            "description": body.description or "Pembayaran umum",
            "payment_date": now_iso(),
            "created_at": now_iso(),
        }
        await db.payments.insert_one({**pay})
        return {"payment": safe_doc(pay)}

    # Pembayaran umum: alokasikan ke sesi yang masih punya hutang (terlama dulu)
    remaining = float(body.amount)
    created: list[dict] = []

    # Ambil semua sesi milik customer, urut tanggal lama -> baru
    sessions = await db.service_sessions.find({"customer_id": body.customer_id}).to_list(length=None)
    sessions_sorted = sorted(sessions, key=lambda s: s.get("session_date", ""))

    for ss in sessions_sorted:
        if remaining <= 0:
            break
        ss_id = ss.get("id")
        services = await db.services.find({"service_session_id": ss_id}).to_list(length=None)
        payments = await db.payments.find({"service_session_id": ss_id}).to_list(length=None)
        sum_services = sum(float(s.get("price", 0)) for s in services)
        sum_payments = sum(float(p.get("amount", 0)) for p in payments)
        debt = round(sum_services - sum_payments, 2)
        if debt <= 0:
            continue
        pay_amount = min(remaining, debt)
        pay_doc = {
            "id": new_id(),
            "customer_id": body.customer_id,
            "service_session_id": ss_id,
            "amount": pay_amount,
            "description": body.description or "Pembayaran umum",
            "payment_date": now_iso(),
            "created_at": now_iso(),
        }
        await db.payments.insert_one({**pay_doc})
        created.append(safe_doc(pay_doc))
        remaining = round(remaining - pay_amount, 2)

    # Jika masih sisa setelah semua sesi lunas, catat sebagai sisa uang (pembayaran umum)
    leftover_doc = None
    if remaining > 0:
        leftover_doc = {
            "id": new_id(),
            "customer_id": body.customer_id,
            "service_session_id": None,
            "amount": remaining,
            "description": body.description or "Sisa uang",
            "payment_date": now_iso(),
            "created_at": now_iso(),
        }
        await db.payments.insert_one({**leftover_doc})
        created.append(safe_doc(leftover_doc))
        remaining = 0.0

    return {"payments": created}


@api_router.put("/payments/{payment_id}")
async def update_payment(payment_id: str, body: UpdatePayment, user=Depends(get_current_user)):
    ensure_valid_or_400("payment_id", payment_id)
    prev = await db.payments.find_one({"id": payment_id})
    if not prev:
        raise HTTPException(status_code=404, detail="Pembayaran tidak ditemukan")

    await db.payments.update_one({"id": payment_id}, {"$set": {"amount": float(body.amount), "description": body.description or ""}})

    # audit
    try:
        audit = {
            "id": new_id(18),
            "payment_id": payment_id,
            "updated_at": now_iso(),
            "updated_by_id": user.get("id"),
            "updated_by_name": user.get("username"),
            "updated_by_role": user.get("role"),
            "old_amount": float(prev.get("amount", 0)),
            "new_amount": float(body.amount),
            "old_description": prev.get("description", ""),
            "new_description": body.description or "",
        }
        await db.payment_audits.insert_one({**audit})
    except Exception:
        pass

    cur = await db.payments.find_one({"id": payment_id})
    return {"payment": safe_doc(cur)}


@api_router.delete("/payments/{payment_id}")
async def delete_payment(payment_id: str, user=Depends(get_current_user)):
    ensure_valid_or_400("payment_id", payment_id)
    res = await db.payments.delete_one({"id": payment_id})
    return {"deleted": getattr(res, "deleted_count", 0) > 0}


@api_router.get("/payments/{payment_id}/audits")
async def get_payment_audits(payment_id: str, user=Depends(get_current_user)):
    ensure_valid_or_400("payment_id", payment_id)
    audits = await db.payment_audits.find({"payment_id": payment_id}).to_list(length=None)
    # strip _id from each
    audits = [safe_doc(a) for a in audits]
    return {"audits": audits}


# ----------------------
# Dashboard

# ----------------------
# Products CRUD
# ----------------------
@api_router.post("/products")
async def create_product(body: NewProduct, user=Depends(get_current_user)):
    # unique code per workshop
    existing = await db.products.find_one({"workshop_id": user.get("workshop_id"), "code": body.code.strip()})
    if existing:
        raise HTTPException(status_code=409, detail="Kode item sudah terpakai")
    
    # Sanitize input data
    prod = {
        "id": new_id(),
        "workshop_id": user.get("workshop_id"),
        "code": body.code.strip(),
        "name": body.name.strip(),
        "stock": int(body.stock or 0),
        "unit": body.unit or "pcs",
        "cost_price": sanitize_float(body.cost_price or 0),
        "sale_price": sanitize_float(body.sale_price or 0),
        "workshop_price": sanitize_float(body.workshop_price or 0),
        "note": body.note or "",
        "created_at": now_iso(),
        "updated_at": now_iso(),
    }
    await db.products.insert_one({**prod})
    return {"product": sanitize_product_data(safe_doc(prod))}


def sanitize_float(value):
    """Sanitize float values to ensure JSON compliance"""
    import math
    if isinstance(value, (int, float)):
        if math.isnan(value) or math.isinf(value):
            return 0.0
        return float(value)
    return value

def sanitize_product_data(product):
    """Sanitize product data to ensure all float values are JSON compliant"""
    if not product:
        return product
    
    # Sanitize float fields
    float_fields = ['cost_price', 'sale_price', 'workshop_price']
    for field in float_fields:
        if field in product:
            product[field] = sanitize_float(product[field])
    
    # Sanitize stock (integer)
    if 'stock' in product:
        try:
            product['stock'] = int(product['stock'] or 0)
        except (ValueError, TypeError):
            product['stock'] = 0
    
    return product

@api_router.get("/products")
async def list_products(user=Depends(get_current_user)):
    try:
        items = await db.products.find({"workshop_id": user.get("workshop_id")}).to_list(length=None)
        # Sanitize and sort by name
        sanitized_items = []
        for item in items:
            sanitized_item = sanitize_product_data(safe_doc(item))
            sanitized_items.append(sanitized_item)
        
        items = sorted(sanitized_items, key=lambda x: x.get("name", ""))
        return {"products": items}
    except Exception as e:
        logger.error(f"Error listing products: {e}")
        raise HTTPException(status_code=500, detail="Gagal mengambil data produk")


@api_router.put("/products/{product_id}")
async def update_product(product_id: str, body: UpdateProduct, user=Depends(get_current_user)):
    ensure_valid_or_400("product_id", product_id)
    
    # Check if product exists
    existing = await db.products.find_one({"id": product_id, "workshop_id": user.get("workshop_id")})
    if not existing:
        raise HTTPException(status_code=404, detail="Produk tidak ditemukan")
    
    updates = {k: v for k, v in body.dict().items() if v is not None}
    if not updates:
        return {"product": sanitize_product_data(safe_doc(existing))}
    
    # Validate code uniqueness
    if "code" in updates:
        exist = await db.products.find_one({
            "workshop_id": user.get("workshop_id"), 
            "code": updates["code"].strip(), 
            "id": {"$ne": product_id}
        })
        if exist:
            raise HTTPException(status_code=409, detail="Kode item sudah terpakai")
        updates["code"] = updates["code"].strip()
    
    # Sanitize float values in updates
    if "name" in updates:
        updates["name"] = updates["name"].strip()
    
    for field in ['cost_price', 'sale_price', 'workshop_price']:
        if field in updates:
            updates[field] = sanitize_float(updates[field])
    
    if 'stock' in updates:
        try:
            updates['stock'] = int(updates['stock'] or 0)
        except (ValueError, TypeError):
            updates['stock'] = 0
    
    # Add updated timestamp
    updates["updated_at"] = now_iso()
    
    # Perform update
    await db.products.update_one({"id": product_id}, {"$set": updates})
    
    # Return updated product
    updated_product = await db.products.find_one({"id": product_id})
    return {"product": sanitize_product_data(safe_doc(updated_product))}

# ----------------------
# Backup & Restore
# ----------------------
@api_router.get("/backup/products")
async def backup_products(user=Depends(get_current_user)):
    wid = user.get("workshop_id")
    items = await db.products.find({"workshop_id": wid}).to_list(length=None)
    return {"products": [safe_doc(i) for i in items]}


@api_router.post("/backup/products")
async def restore_products(payload: dict, user=Depends(get_current_user)):
    wid = user.get("workshop_id")
    incoming = payload.get("products", []) if isinstance(payload, dict) else []
    # wipe existing products for this workshop, then insert provided
    await db.products.delete_many({"workshop_id": wid})
    docs = []
    for p in incoming:
        if not isinstance(p, dict):
            continue
        doc = {
            "id": p.get("id") or new_id(),
            "workshop_id": wid,
            "code": (p.get("code") or "").strip(),
            "name": (p.get("name") or "").strip(),
            "stock": int(p.get("stock") or 0),
            "unit": p.get("unit") or "pcs",
            "cost_price": float(p.get("cost_price") or 0),
            "sale_price": float(p.get("sale_price") or 0),
            "workshop_price": float(p.get("workshop_price") or 0),
            "note": p.get("note") or "",
            "created_at": p.get("created_at") or now_iso(),
            "updated_at": now_iso(),
        }
        docs.append(doc)
    inserted = 0
    if docs:
        await db.products.insert_many(docs)
        inserted = len(docs)
    return {"restored": True, "inserted": inserted}


@api_router.get("/backup/all")
async def backup_all(user=Depends(get_current_user)):
    wid = user.get("workshop_id")
    customers = await db.customers.find({"workshop_id": wid}).to_list(length=None)
    sessions = await db.service_sessions.find({"workshop_id": wid}).to_list(length=None)
    cust_ids = [c.get("id") for c in customers if c.get("id")]
    services = await db.services.find({"customer_id": {"$in": cust_ids}}).to_list(length=None)
    payments = await db.payments.find({"customer_id": {"$in": cust_ids}}).to_list(length=None)
    pay_ids = [p.get("id") for p in payments if p.get("id")]
    try:
        payment_audits = await db.payment_audits.find({"payment_id": {"$in": pay_ids}}).to_list(length=None)
    except Exception:
        payment_audits = []
    products = await db.products.find({"workshop_id": wid}).to_list(length=None)

    return {
        "customers": [safe_doc(x) for x in customers],
        "service_sessions": [safe_doc(x) for x in sessions],
        "services": [safe_doc(x) for x in services],
        "payments": [safe_doc(x) for x in payments],
        "payment_audits": [safe_doc(x) for x in payment_audits],
        "products": [safe_doc(x) for x in products],
    }


@api_router.post("/backup/all")
async def restore_all(payload: dict, user=Depends(get_current_user)):
    wid = user.get("workshop_id")
    data = payload if isinstance(payload, dict) else {}
    # wipe existing for this workshop
    await db.customers.delete_many({"workshop_id": wid})
    await db.service_sessions.delete_many({"workshop_id": wid})
    # derive customer ids first to wipe related
    # services & payments defined by customer_id
    # Note: remove those whose customer_id belong to wid
    # This is safe since we wiped customers
    await db.services.delete_many({})
    await db.payments.delete_many({})
    try:
        await db.payment_audits.delete_many({})
    except Exception:
        pass
    await db.products.delete_many({"workshop_id": wid})

    # Insert back in order
    def norm_id(x):
        return x if (isinstance(x, str) and len(x) == 18) else new_id()

    customers = []
    for c in data.get("customers", []) or []:
        if not isinstance(c, dict):
            continue
        customers.append({
            "id": norm_id(c.get("id")),
            "name": c.get("name", ""),
            "phone": c.get("phone", ""),
            "workshop_id": wid,
            "created_at": c.get("created_at") or now_iso(),
        })
    if customers:
        await db.customers.insert_many(customers)

    sessions = []
    for s in data.get("service_sessions", []) or []:
        if not isinstance(s, dict):
            continue
        sessions.append({
            "id": norm_id(s.get("id")),
            "customer_id": s.get("customer_id"),
            "workshop_id": wid,
            "session_name": s.get("session_name", "Sesi"),
            "session_date": s.get("session_date") or now_iso(),
            "created_at": s.get("created_at") or now_iso(),
        })
    if sessions:
        await db.service_sessions.insert_many(sessions)

    services = []
    for sv in data.get("services", []) or []:
        if not isinstance(sv, dict):
            continue
        services.append({
            "id": norm_id(sv.get("id")),
            "customer_id": sv.get("customer_id"),
            "service_session_id": sv.get("service_session_id"),
            "description": sv.get("description", ""),
            "price": float(sv.get("price") or 0),
            "created_at": sv.get("created_at") or now_iso(),
        })
    if services:
        await db.services.insert_many(services)

    payments = []
    for p in data.get("payments", []) or []:
        if not isinstance(p, dict):
            continue
        payments.append({
            "id": norm_id(p.get("id")),
            "customer_id": p.get("customer_id"),
            "service_session_id": p.get("service_session_id", None),
            "amount": float(p.get("amount") or 0),
            "description": p.get("description", ""),
            "payment_date": p.get("payment_date") or now_iso(),
            "created_at": p.get("created_at") or now_iso(),
        })
    if payments:
        await db.payments.insert_many(payments)

    try:
        audits = []
        for a in data.get("payment_audits", []) or []:
            if not isinstance(a, dict):
                continue
            audits.append({
                "id": norm_id(a.get("id")),
                "payment_id": a.get("payment_id"),
                "updated_at": a.get("updated_at") or now_iso(),
                "updated_by_id": a.get("updated_by_id"),
                "updated_by_name": a.get("updated_by_name"),
                "updated_by_role": a.get("updated_by_role"),
                "old_amount": float(a.get("old_amount") or 0),
                "new_amount": float(a.get("new_amount") or 0),
                "old_description": a.get("old_description", ""),
                "new_description": a.get("new_description", ""),
            })
        if audits:
            await db.payment_audits.insert_many(audits)
    except Exception:
        pass

    products = []
    for pr in data.get("products", []) or []:
        if not isinstance(pr, dict):
            continue
        products.append({
            "id": norm_id(pr.get("id")),
            "workshop_id": wid,
            "code": (pr.get("code") or "").strip(),
            "name": (pr.get("name") or "").strip(),
            "stock": int(pr.get("stock") or 0),
            "unit": pr.get("unit") or "pcs",
            "cost_price": float(pr.get("cost_price") or 0),
            "sale_price": float(pr.get("sale_price") or 0),
            "workshop_price": float(pr.get("workshop_price") or 0),
            "note": pr.get("note") or "",
            "created_at": pr.get("created_at") or now_iso(),
            "updated_at": now_iso(),
        })
    if products:
        await db.products.insert_many(products)

    return {"restored": True, "counts": {
        "customers": len(customers),
        "service_sessions": len(sessions),
        "services": len(services),
        "payments": len(payments),
        "payment_audits": len(data.get("payment_audits", []) or []),
        "products": len(products),
    }}


# ----------------------
# Excel Backup & Restore
# ----------------------
@api_router.get("/backup/excel/products")
async def backup_products_excel(user=Depends(get_current_user)):
    wid = user.get("workshop_id")
    items = await db.products.find({"workshop_id": wid}).to_list(length=None)
    
    # Convert to DataFrame
    products_data = []
    for item in items:
        products_data.append({
            "ID": item.get("id", ""),
            "Kode": item.get("code", ""),
            "Nama": item.get("name", ""),
            "Stok": item.get("stock", 0),
            "Satuan": item.get("unit", "pcs"),
            "Harga Modal": item.get("cost_price", 0),
            "Harga Jual": item.get("sale_price", 0),
            "Harga Bengkel": item.get("workshop_price", 0),
            "Keterangan": item.get("note", ""),
            "Dibuat": item.get("created_at", ""),
            "Diupdate": item.get("updated_at", "")
        })
    
    df = pd.DataFrame(products_data)
    
    # Create Excel file in memory
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name='Produk', index=False)
        
        # Get workbook and worksheet for formatting
        workbook = writer.book
        worksheet = writer.sheets['Produk']
        
        # Auto-adjust column widths
        for column in worksheet.columns:
            max_length = 0
            column = [cell for cell in column]
            for cell in column:
                try:
                    if len(str(cell.value)) > max_length:
                        max_length = len(str(cell.value))
                except:
                    pass
            adjusted_width = min(max_length + 2, 50)
            worksheet.column_dimensions[column[0].column_letter].width = adjusted_width
    
    output.seek(0)
    
    # Return as streaming response
    return StreamingResponse(
        io.BytesIO(output.read()),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=backup_produk.xlsx"}
    )


@api_router.post("/backup/excel/products")
async def restore_products_excel(file: UploadFile = File(...), user=Depends(get_current_user)):
    if not file.filename.endswith(('.xlsx', '.xls')):
        raise HTTPException(status_code=400, detail="File harus berformat Excel (.xlsx atau .xls)")
    
    wid = user.get("workshop_id")

    # Normalizers to prevent NaN/None/blank issues
    import math
    def nstr(v: Any) -> str:
        try:
            if v is None:
                return ""
            if isinstance(v, float) and math.isnan(v):
                return ""
            s = str(v).strip()
            if s.lower() in ("nan", "none"):
                return ""
            return s
        except Exception:
            return ""

    def nfloat(v: Any) -> float:
        try:
            if v is None:
                return 0.0
            if isinstance(v, float) and math.isnan(v):
                return 0.0
            if isinstance(v, str) and v.strip() == "":
                return 0.0
            return float(v)
        except Exception:
            return 0.0

    def nint(v: Any) -> int:
        try:
            if v is None:
                return 0
            if isinstance(v, float) and math.isnan(v):
                return 0
            if isinstance(v, str) and v.strip() == "":
                return 0
            return int(float(v))
        except Exception:
            return 0
    
    try:
        # Read Excel file
        contents = await file.read()
        df = pd.read_excel(io.BytesIO(contents), sheet_name='Produk')
        
        # Wipe existing products for this workshop
        await db.products.delete_many({"workshop_id": wid})
        
        docs = []
        for _, row in df.iterrows():
            doc = {
                "id": nstr(row.get("ID", "")) or new_id(),
                "workshop_id": wid,
                "code": nstr(row.get("Kode", "")),
                "name": nstr(row.get("Nama", "")),
                "stock": nint(row.get("Stok", 0)),
                "unit": nstr(row.get("Satuan", "pcs")) or "pcs",
                "cost_price": nfloat(row.get("Harga Modal", 0)),
                "sale_price": nfloat(row.get("Harga Jual", 0)),
                "workshop_price": nfloat(row.get("Harga Bengkel", 0)),
                "note": nstr(row.get("Keterangan", "")),
                "created_at": nstr(row.get("Dibuat", "")) or now_iso(),
                "updated_at": now_iso(),
            }
            docs.append(doc)
        
        inserted = 0
        if docs:
            await db.products.insert_many(docs)
            inserted = len(docs)
        
        return {"restored": True, "inserted": inserted}
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error memproses file Excel: {str(e)}")


@api_router.get("/backup/excel/all")
async def backup_all_excel(user=Depends(get_current_user)):
    wid = user.get("workshop_id")
    
    # Get all data
    customers = await db.customers.find({"workshop_id": wid}).to_list(length=None)
    sessions = await db.service_sessions.find({"workshop_id": wid}).to_list(length=None)
    cust_ids = [c.get("id") for c in customers if c.get("id")]
    services = await db.services.find({"customer_id": {"$in": cust_ids}}).to_list(length=None)
    payments = await db.payments.find({"customer_id": {"$in": cust_ids}}).to_list(length=None)
    products = await db.products.find({"workshop_id": wid}).to_list(length=None)
    
    # Convert to DataFrames
    customers_data = []
    for item in customers:
        customers_data.append({
            "ID": item.get("id", ""),
            "Nama": item.get("name", ""),
            "No HP": item.get("phone", ""),
            "Dibuat": item.get("created_at", "")
        })
    
    sessions_data = []
    for item in sessions:
        sessions_data.append({
            "ID": item.get("id", ""),
            "ID Pelanggan": item.get("customer_id", ""),
            "Nama Sesi": item.get("session_name", ""),
            "Tanggal Sesi": item.get("session_date", ""),
            "Dibuat": item.get("created_at", "")
        })
    
    services_data = []
    for item in services:
        services_data.append({
            "ID": item.get("id", ""),
            "ID Pelanggan": item.get("customer_id", ""),
            "ID Sesi": item.get("service_session_id", ""),
            "Deskripsi": item.get("description", ""),
            "Harga": item.get("price", 0),
            "Dibuat": item.get("created_at", "")
        })
    
    payments_data = []
    for item in payments:
        payments_data.append({
            "ID": item.get("id", ""),
            "ID Pelanggan": item.get("customer_id", ""),
            "ID Sesi": item.get("service_session_id", ""),
            "Jumlah": item.get("amount", 0),
            "Keterangan": item.get("description", ""),
            "Tanggal Bayar": item.get("payment_date", ""),
            "Dibuat": item.get("created_at", "")
        })
    
    products_data = []
    for item in products:
        products_data.append({
            "ID": item.get("id", ""),
            "Kode": item.get("code", ""),
            "Nama": item.get("name", ""),
            "Stok": item.get("stock", 0),
            "Satuan": item.get("unit", "pcs"),
            "Harga Modal": item.get("cost_price", 0),
            "Harga Jual": item.get("sale_price", 0),
            "Harga Bengkel": item.get("workshop_price", 0),
            "Keterangan": item.get("note", ""),
            "Dibuat": item.get("created_at", ""),
            "Diupdate": item.get("updated_at", "")
        })
    
    # Create Excel file with multiple sheets
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        pd.DataFrame(customers_data).to_excel(writer, sheet_name='Pelanggan', index=False)
        pd.DataFrame(sessions_data).to_excel(writer, sheet_name='Sesi Servis', index=False)
        pd.DataFrame(services_data).to_excel(writer, sheet_name='Item Servis', index=False)
        pd.DataFrame(payments_data).to_excel(writer, sheet_name='Pembayaran', index=False)
        pd.DataFrame(products_data).to_excel(writer, sheet_name='Produk', index=False)
        
        # Auto-adjust column widths for all sheets
        for sheet_name in writer.sheets:
            worksheet = writer.sheets[sheet_name]
            for column in worksheet.columns:
                max_length = 0
                column = [cell for cell in column]
                for cell in column:
                    try:
                        if len(str(cell.value)) > max_length:
                            max_length = len(str(cell.value))
                    except:
                        pass
                adjusted_width = min(max_length + 2, 50)
                worksheet.column_dimensions[column[0].column_letter].width = adjusted_width
    
    output.seek(0)
    
    return StreamingResponse(
        io.BytesIO(output.read()),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=backup_semua_data.xlsx"}
    )


@api_router.post("/backup/excel/all")
async def restore_all_excel(file: UploadFile = File(...), user=Depends(get_current_user)):
    if not file.filename.endswith(('.xlsx', '.xls')):
        raise HTTPException(status_code=400, detail="File harus berformat Excel (.xlsx atau .xls)")
    
    wid = user.get("workshop_id")

    # Normalizers (same as products restore)
    import math
    def nstr(v: Any) -> str:
        try:
            if v is None:
                return ""
            if isinstance(v, float) and math.isnan(v):
                return ""
            s = str(v).strip()
            if s.lower() in ("nan", "none"):
                return ""
            return s
        except Exception:
            return ""

    def nfloat(v: Any) -> float:
        try:
            if v is None:
                return 0.0
            if isinstance(v, float) and math.isnan(v):
                return 0.0
            if isinstance(v, str) and v.strip() == "":
                return 0.0
            return float(v)
        except Exception:
            return 0.0

    def nint(v: Any) -> int:
        try:
            if v is None:
                return 0
            if isinstance(v, float) and math.isnan(v):
                return 0
            if isinstance(v, str) and v.strip() == "":
                return 0
            return int(float(v))
        except Exception:
            return 0
    
    try:
        # Read Excel file
        contents = await file.read()
        
        # Read all sheets
        customers_df = pd.read_excel(io.BytesIO(contents), sheet_name='Pelanggan')
        sessions_df = pd.read_excel(io.BytesIO(contents), sheet_name='Sesi Servis')
        services_df = pd.read_excel(io.BytesIO(contents), sheet_name='Item Servis')
        payments_df = pd.read_excel(io.BytesIO(contents), sheet_name='Pembayaran')
        products_df = pd.read_excel(io.BytesIO(contents), sheet_name='Produk')
        
        # Wipe existing data for this workshop
        await db.customers.delete_many({"workshop_id": wid})
        await db.service_sessions.delete_many({"workshop_id": wid})
        await db.services.delete_many({})
        await db.payments.delete_many({})
        await db.products.delete_many({"workshop_id": wid})
        
        # Process customers
        customers = []
        for _, row in customers_df.iterrows():
            customers.append({
                "id": nstr(row.get("ID", "")) or new_id(),
                "name": nstr(row.get("Nama", "")),
                "phone": nstr(row.get("No HP", "")),
                "workshop_id": wid,
                "created_at": nstr(row.get("Dibuat", "")) or now_iso(),
            })
        if customers:
            await db.customers.insert_many(customers)
        
        # Process sessions
        sessions = []
        for _, row in sessions_df.iterrows():
            sessions.append({
                "id": nstr(row.get("ID", "")) or new_id(),
                "customer_id": nstr(row.get("ID Pelanggan", "")),
                "workshop_id": wid,
                "session_name": nstr(row.get("Nama Sesi", "")),
                "session_date": nstr(row.get("Tanggal Sesi", "")) or now_iso(),
                "created_at": nstr(row.get("Dibuat", "")) or now_iso(),
            })
        if sessions:
            await db.service_sessions.insert_many(sessions)
        
        # Process services
        services = []
        for _, row in services_df.iterrows():
            services.append({
                "id": nstr(row.get("ID", "")) or new_id(),
                "customer_id": nstr(row.get("ID Pelanggan", "")),
                "service_session_id": nstr(row.get("ID Sesi", "")),
                "description": nstr(row.get("Deskripsi", "")),
                "price": nfloat(row.get("Harga", 0)),
                "created_at": nstr(row.get("Dibuat", "")) or now_iso(),
            })
        if services:
            await db.services.insert_many(services)
        
        # Process payments
        payments = []
        for _, row in payments_df.iterrows():
            payments.append({
                "id": nstr(row.get("ID", "")) or new_id(),
                "customer_id": nstr(row.get("ID Pelanggan", "")),
                "service_session_id": nstr(row.get("ID Sesi", "") or None) or None,
                "amount": nfloat(row.get("Jumlah", 0)),
                "description": nstr(row.get("Keterangan", "")),
                "payment_date": nstr(row.get("Tanggal Bayar", "")) or now_iso(),
                "created_at": nstr(row.get("Dibuat", "")) or now_iso(),
            })
        if payments:
            await db.payments.insert_many(payments)
        
        # Process products
        products = []
        for _, row in products_df.iterrows():
            products.append({
                "id": nstr(row.get("ID", "")) or new_id(),
                "workshop_id": wid,
                "code": nstr(row.get("Kode", "")),
                "name": nstr(row.get("Nama", "")),
                "stock": nint(row.get("Stok", 0)),
                "unit": nstr(row.get("Satuan", "pcs")) or "pcs",
                "cost_price": nfloat(row.get("Harga Modal", 0)),
                "sale_price": nfloat(row.get("Harga Jual", 0)),
                "workshop_price": nfloat(row.get("Harga Bengkel", 0)),
                "note": nstr(row.get("Keterangan", "")),
                "created_at": nstr(row.get("Dibuat", "")) or now_iso(),
                "updated_at": now_iso(),
            })
        if products:
            await db.products.insert_many(products)
        
        return {"restored": True, "counts": {
            "customers": len(customers),
            "service_sessions": len(sessions),
            "services": len(services),
            "payments": len(payments),
            "products": len(products),
        }}
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error memproses file Excel: {str(e)}")


@api_router.post("/products/{product_id}/adjust-stock")
async def product_adjust_stock(product_id: str, body: AdjustStock, user=Depends(get_current_user)):
    ensure_valid_or_400("product_id", product_id)
    prod = await db.products.find_one({"id": product_id, "workshop_id": user.get("workshop_id")})
    if not prod:
        raise HTTPException(status_code=404, detail="Produk tidak ditemukan")
    
    # Ensure stock adjustment is safe
    current_stock = int(prod.get("stock", 0))
    delta = int(body.delta)
    new_stock = max(0, current_stock + delta)  # Prevent negative stock
    
    await db.products.update_one(
        {"id": product_id}, 
        {"$set": {"stock": new_stock, "updated_at": now_iso()}}
    )
    cur = await db.products.find_one({"id": product_id})
    return {"product": sanitize_product_data(safe_doc(cur))}


@api_router.delete("/products/{product_id}")
async def delete_product(product_id: str, user=Depends(get_current_user)):
    ensure_valid_or_400("product_id", product_id)
    res = await db.products.delete_one({"id": product_id, "workshop_id": user.get("workshop_id")})
    return {"deleted": getattr(res, "deleted_count", 0) > 0}

# ----------------------
@api_router.get("/dashboard")
async def get_dashboard(user=Depends(get_current_user)):
    workshop_id = user.get("workshop_id")
    customers = await db.customers.find({"workshop_id": workshop_id}).to_list(length=None)

    result = []
    for cust in customers:
        cust_id = cust["id"]
        sessions = await db.service_sessions.find({"customer_id": cust_id}).to_list(length=None)
        total_ss = len(sessions)
        services_docs = await db.services.find({"customer_id": cust_id}).to_list(length=None)
        payments_docs = await db.payments.find({"customer_id": cust_id}).to_list(length=None)
        total_services = len(services_docs)
        total_payments = len(payments_docs)
        total_debt = sum(float(s.get("price", 0)) for s in services_docs) - sum(float(p.get("amount", 0)) for p in payments_docs)
        result.append({
            "customer": {"id": cust_id, "name": cust.get("name"), "phone": cust.get("phone", "")},
            "total_debt": round(total_debt, 2),
            "total_service_sessions": total_ss,
            "total_services": total_services,
            "total_payments": total_payments,
        })

    return {"customers": result}


# ----------------------
# WhatsApp helper
# ----------------------
@api_router.get("/customers/{customer_id}/whatsapp-message")
async def whatsapp_message(customer_id: str, session_id: Optional[str] = None, user=Depends(get_current_user)):
    ensure_valid_or_400("customer_id", customer_id)
    if session_id is not None:
        ensure_valid_or_400("session_id", session_id)
    cust = await db.customers.find_one({"id": customer_id, "workshop_id": user.get("workshop_id")})
    if not cust:
        raise HTTPException(status_code=404, detail="Pelanggan tidak ditemukan")

    lines = []
    if session_id:
        ss = await db.service_sessions.find_one({"id": session_id})
        if not ss:
            raise HTTPException(status_code=404, detail="Sesi tidak ditemukan")
        services = await db.services.find({"service_session_id": session_id}).to_list(length=None)
        payments = await db.payments.find({"service_session_id": session_id}).to_list(length=None)
        total_services = sum(float(s.get("price", 0)) for s in services)
        total_payments = sum(float(p.get("amount", 0)) for p in payments)
        sisa = total_services - total_payments
        lines.append(f"Ringkasan Sesi: {ss.get('session_name')}")
        for s in services:
            lines.append(f"- {s.get('description')}: Rp {int(float(s.get('price',0))):,}")
        lines.append(f"Total: Rp {int(total_services):,}")
        lines.append(f"Dibayar: Rp {int(total_payments):,}")
        lines.append(f"Sisa: Rp {int(sisa):,}")
    else:
        sessions = await db.service_sessions.find({"customer_id": customer_id}).to_list(length=None)
        total_services = 0.0
        total_payments = 0.0
        for ss in sessions:
            services = await db.services.find({"service_session_id": ss["id"]}).to_list(length=None)
            payments = await db.payments.find({"service_session_id": ss["id"]}).to_list(length=None)
            total_services += sum(float(s.get("price", 0)) for s in services)
            total_payments += sum(float(p.get("amount", 0)) for p in payments)
        sisa = total_services - total_payments
        lines.append(f"Ringkasan Pelanggan: {cust.get('name')}")
        lines.append(f"Total Servis: Rp {int(total_services):,}")
        lines.append(f"Total Bayar: Rp {int(total_payments):,}")
        lines.append(f"Sisa: Rp {int(sisa):,}")

    text = "\n".join(lines).replace(",", ".")
    whatsapp_url = f"https://wa.me/?text={text.replace(' ', '%20')}"
    return {"whatsapp_url": whatsapp_url}


# ----------------------
# Shutdown
# ----------------------
@api_router.on_event("shutdown")
async def shutdown_db_client():
    client.close()

# Mount router
app.include_router(api_router)