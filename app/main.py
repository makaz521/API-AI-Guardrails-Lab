import os, time, logging
from collections import defaultdict, deque
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, Integer, String, Text
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from app.security import inspect_prompt, redact_output

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
log = logging.getLogger("sil-lab")
SECRET_KEY = os.getenv("JWT_SECRET", "CHANGE-THIS-DEMO-SECRET-BEFORE-DEPLOYMENT")
ALGORITHM = "HS256"
TOKEN_MINUTES = 30
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./sil_lab.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()
pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer = HTTPBearer(auto_error=False)
app = FastAPI(title="SIL Infosec Assessment API Lab", version="1.0.0")
rate_windows = defaultdict(deque)
RATE_LIMIT = 30
WINDOW_SECONDS = 60

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(30), nullable=False)

class Patient(Base):
    __tablename__ = "patients"
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    note = Column(Text, nullable=False)

Base.metadata.create_all(engine)

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def seed():
    db=SessionLocal()
    if not db.query(User).filter_by(username="analyst").first():
        db.add(User(username="analyst", password_hash=pwd.hash("LabOnly-ChangeMe!"), role="analyst"))
    if not db.query(Patient).first():
        db.add_all([Patient(name="Synthetic Patient Alpha", note="Synthetic test record; no real PHI."),
                    Patient(name="Synthetic Patient Beta", note="Synthetic test record; no real PHI.")])
    db.commit(); db.close()
seed()

def current_user(creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer), db: Session = Depends(get_db)):
    if not creds:
        raise HTTPException(status_code=401, detail="Bearer token required")
    try:
        payload=jwt.decode(creds.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username=payload.get("sub")
        user=db.query(User).filter_by(username=username).first()
        if not user: raise HTTPException(status_code=401, detail="Invalid token subject")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

@app.middleware("http")
async def simple_rate_limit(request: Request, call_next):
    # Demo in-memory limiter: per client IP, resets on process restart; use gateway/WAF
    # or Redis-backed distributed limiting in production.
    ip=request.client.host if request.client else "unknown"
    now=time.time(); q=rate_windows[ip]
    while q and now-q[0] > WINDOW_SECONDS: q.popleft()
    if len(q) >= RATE_LIMIT:
        log.warning("rate_limit_block client=%s path=%s", ip, request.url.path)
        return __import__("fastapi").responses.JSONResponse(status_code=429, content={"detail":"Rate limit exceeded"})
    q.append(now)
    return await call_next(request)

class LoginInput(BaseModel):
    username: str
    password: str

class PromptInput(BaseModel):
    prompt: str = Field(min_length=1, max_length=4000)

@app.get("/health")
def health():
    return {"status":"ok", "environment":"local assessment lab"}

@app.post("/auth/token")
def token(body: LoginInput, db: Session = Depends(get_db)):
    user=db.query(User).filter_by(username=body.username).first()
    if not user or not pwd.verify(body.password, user.password_hash):
        log.warning("auth_failure username=%s", body.username[:80])
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token=jwt.encode({"sub":user.username,"role":user.role,"exp":int(time.time())+TOKEN_MINUTES*60}, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token":token,"token_type":"bearer","expires_in":TOKEN_MINUTES*60}

@app.get("/api/patients")
def patients(user=Depends(current_user), db: Session=Depends(get_db)):
    # Demo role gate; real systems need per-record authorization and audit policy.
    if user.role not in ("analyst","admin"):
        raise HTTPException(status_code=403, detail="Insufficient role")
    log.info("patient_list_access username=%s", user.username)
    return [{"id":p.id,"name":p.name,"note":p.note} for p in db.query(Patient).all()]

@app.get("/api/analytics")
def analytics(user=Depends(current_user), db: Session=Depends(get_db)):
    count=db.query(Patient).count()
    log.info("analytics_access username=%s", user.username)
    return {"synthetic_patient_count":count,"generated_at":int(time.time())}

@app.post("/api/ai/inspect")
def ai_inspect(body: PromptInput, user=Depends(current_user)):
    allowed, reason=inspect_prompt(body.prompt)
    if not allowed:
        log.warning("ai_request_blocked username=%s reason=%s", user.username, reason)
        raise HTTPException(status_code=400, detail={"blocked":True,"reason":reason})
    # Offline mock response; no external LLM is called in this starter lab.
    mock_response=f"Demo response to approved prompt: {body.prompt}"
    safe_response=redact_output(mock_response)
    log.info("ai_request_allowed username=%s", user.username)
    return {"status":"allowed","response":safe_response,"provider":"mock-no-external-llm"}

@app.post("/api/ai/test-redaction")
def test_redaction(body: PromptInput, user=Depends(current_user)):
    # Simulates an LLM output for deterministic redaction testing.
    return {"redacted_output":redact_output(body.prompt)}

@app.get("/api/admin/audit")
def audit_hint(user=Depends(current_user)):
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return {"message":"In production, send structured audit events to CloudWatch/SIEM."}
