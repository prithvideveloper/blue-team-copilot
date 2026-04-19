"""
Blue Team Co-Pilot — Authentication Module
MongoDB-backed user auth with JWT tokens.
"""

import os
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends, Request  # type: ignore
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials  # type: ignore
from pydantic import BaseModel, EmailStr  # type: ignore
from passlib.context import CryptContext  # type: ignore
from jose import jwt, JWTError  # type: ignore
import motor.motor_asyncio  # type: ignore

# ─── Configuration ────────────────────────────────────────────────────────────
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = "blue_team_copilot"
JWT_SECRET = os.getenv("JWT_SECRET", "btc-secret-key-change-in-production-2024")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 24

# ─── MongoDB Client ──────────────────────────────────────────────────────────
client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URI)
db = client[DB_NAME]
users_collection = db["users"]

# ─── Password Hashing ────────────────────────────────────────────────────────
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ─── Pydantic Models ─────────────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    username: str
    email: str
    role: str
    created_at: str

# ─── JWT Utilities ────────────────────────────────────────────────────────────
def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        return None

# ─── Auth Dependency ──────────────────────────────────────────────────────────
security = HTTPBearer()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = verify_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    user = await users_collection.find_one({"username": payload.get("sub")})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    return {
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
    }

# ─── Router ───────────────────────────────────────────────────────────────────
auth_router = APIRouter(prefix="/api/auth", tags=["auth"])


@auth_router.post("/register")
async def register(req: RegisterRequest):
    """Register a new user."""
    # Check if user already exists
    existing = await users_collection.find_one({
        "$or": [{"username": req.username}, {"email": req.email}]
    })
    if existing:
        raise HTTPException(status_code=400, detail="Username or email already registered")
    
    # Hash password and store
    user_doc = {
        "username": req.username,
        "email": req.email,
        "password_hash": pwd_context.hash(req.password),
        "role": "analyst",
        "created_at": datetime.utcnow().isoformat() + "Z",
    }
    await users_collection.insert_one(user_doc)

    token = create_access_token({"sub": req.username, "role": "analyst"})
    return {
        "message": "User registered successfully",
        "token": token,
        "user": {
            "username": req.username,
            "email": req.email,
            "role": "analyst",
        },
    }


@auth_router.post("/login")
async def login(req: LoginRequest):
    """Authenticate and return JWT."""
    user = await users_collection.find_one({"username": req.username})
    if not user or not pwd_context.verify(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_access_token({"sub": user["username"], "role": user["role"]})
    return {
        "message": "Login successful",
        "token": token,
        "user": {
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
        },
    }


@auth_router.get("/me")
async def get_me(user: dict = Depends(get_current_user)):
    """Get current user info from JWT."""
    return user


# ─── Seed Default Admin ──────────────────────────────────────────────────────
async def seed_admin():
    """Create a default admin user if the collection is empty."""
    count = await users_collection.count_documents({})
    if count == 0:
        admin_doc = {
            "username": "admin",
            "email": "admin@blueteam.local",
            "password_hash": pwd_context.hash("admin123"),
            "role": "admin",
            "created_at": datetime.utcnow().isoformat() + "Z",
        }
        await users_collection.insert_one(admin_doc)
        print("✅ Default admin user created (admin / admin123)")
