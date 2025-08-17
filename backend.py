# -*- coding: utf-8 -*-
import os, time, uuid, asyncio
from typing import Optional, List

import aiosqlite
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import jwt

# -------------------------
# ENV
# -------------------------
JWT_SECRET = os.getenv("SHARED_SECRET", "CHANGE_ME_SECRET")
JWT_ALG = "HS256"
JWT_ISS = os.getenv("JWT_ISS", "bitbet")
JWT_AUD = os.getenv("JWT_AUD", "bitbet-web")

# 5 min bez aktywności
SESSION_IDLE_TIMEOUT = int(os.getenv("SESSION_IDLE_TIMEOUT", "300"))
DB_PATH = os.getenv("DB_PATH", "./sessions.db")

# (opcjonalnie tylko do wygodnego zwracania pełnego linku)
FRONT_BASE_URL = os.getenv("FRONT_BASE_URL", "https://twoj-user.github.io/bitbet-stack")

# CORS – podaj dokładny URL GitHub Pages (lub kilka, po przecinku)
origins = [o.strip() for o in os.getenv("ALLOW_ORIGINS", "*").split(",") if o.strip()]

app = FastAPI(title="BitBet session backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins if origins != ["*"] else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------
# DB
# -------------------------
CREATE_SQL = """
CREATE TABLE IF NOT EXISTS sessions(
  session_id TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  last_active INTEGER NOT NULL,
  active     INTEGER NOT NULL,
  jti        TEXT NOT NULL
);
"""

async def db():
    return await aiosqlite.connect(DB_PATH)

async def init_db():
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute(CREATE_SQL)
        await conn.commit()

# -------------------------
# MODELE
# -------------------------
class CreateSessionIn(BaseModel):
    user_id: int
    username: Optional[str] = None

class CreateSessionOut(BaseModel):
    session_id: str
    url: str
    token: str
    expires_idle_seconds: int

class SessionClaims(BaseModel):
    sub: str   # user_id (string)
    sid: str   # session_id
    jti: str
    iss: str
    aud: str
    iat: int
    exp: int   # twarda ważność tokenu (np. 24h)

# -------------------------
# JWT + AUTH
# -------------------------
def now() -> int:
    return int(time.time())

def make_token(user_id: int, session_id: str, jti: str, ttl_seconds: int = 24*3600) -> str:
    payload = {
        "sub": str(user_id),
        "sid": session_id,
        "jti": jti,
        "iss": JWT_ISS,
        "aud": JWT_AUD,
        "iat": now(),
        "exp": now() + ttl_seconds,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def parse_auth_token(request: Request) -> SessionClaims:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Missing bearer token")
    token = auth.split(" ", 1)[1]
    try:
        data = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALG],
            audience=JWT_AUD,
            issuer=JWT_ISS,
        )
        return SessionClaims(**data)
    except Exception:
        raise HTTPException(401, "Invalid token")

# -------------------------
# CLEANUP TASK
# -------------------------
async def cleanup_loop():
    while True:
        try:
            async with aiosqlite.connect(DB_PATH) as conn:
                cutoff = now() - SESSION_IDLE_TIMEOUT
                await conn.execute(
                    "UPDATE sessions SET active=0 WHERE active=1 AND last_active<?",
                    (cutoff,),
                )
                await conn.commit()
        except Exception:
            pass
        await asyncio.sleep(60)  # co minutę

@app.on_event("startup")
async def on_startup():
    await init_db()
    asyncio.create_task(cleanup_loop())

# -------------------------
# ENDPOINTY
# -------------------------
@app.post("/api/sessions/create", response_model=CreateSessionOut)
async def create_session(payload: CreateSessionIn):
    s_id = uuid.uuid4().hex[:22]
    jti = uuid.uuid4().hex
    tkn = make_token(payload.user_id, s_id, jti, ttl_seconds=24*3600)

    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute(
            "INSERT INTO sessions(session_id, user_id, created_at, last_active, active, jti) VALUES(?,?,?,?,?,?)",
            (s_id, payload.user_id, now(), now(), 1, jti),
        )
        await conn.commit()

    # „Podstrona” to po prostu ścieżka SPA:
    url = f"{FRONT_BASE_URL.rstrip('/')}/s/{s_id}#token={tkn}"
    return CreateSessionOut(
        session_id=s_id, url=url, token=tkn, expires_idle_seconds=SESSION_IDLE_TIMEOUT
    )

@app.post("/api/sessions/heartbeat")
async def heartbeat(request: Request):
    claims = parse_auth_token(request)
    async with aiosqlite.connect(DB_PATH) as conn:
        # sprawdź status sesji
        cur = await conn.execute(
            "SELECT active, last_active FROM sessions WHERE session_id=? AND jti=?",
            (claims.sid, claims.jti),
        )
        row = await cur.fetchone()
        if not row:
            raise HTTPException(401, "Session not found")
        active, last_active = row
        if not active:
            raise HTTPException(410, "Session ended")

        await conn.execute(
            "UPDATE sessions SET last_active=? WHERE session_id=?",
            (now(), claims.sid),
        )
        await conn.commit()

    return {"ok": True, "remaining_idle_seconds": SESSION_IDLE_TIMEOUT}

@app.post("/api/sessions/end")
async def end_session(request: Request):
    claims = parse_auth_token(request)
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute(
            "UPDATE sessions SET active=0 WHERE session_id=? AND jti=?",
            (claims.sid, claims.jti),
        )
        await conn.commit()
    return {"ok": True}

@app.get("/api/me")
async def me(request: Request):
    claims = parse_auth_token(request)
    async with aiosqlite.connect(DB_PATH) as conn:
        cur = await conn.execute(
            "SELECT active, last_active FROM sessions WHERE session_id=? AND jti=?",
            (claims.sid, claims.jti),
        )
        row = await cur.fetchone()
        if not row:
            raise HTTPException(401, "Session not found")
        active, last_active = row
        if not active:
            raise HTTPException(410, "Session ended")
        # sprawdź time-out
        if now() - last_active > SESSION_IDLE_TIMEOUT:
            await conn.execute("UPDATE sessions SET active=0 WHERE session_id=?", (claims.sid,))
            await conn.commit()
            raise HTTPException(410, "Session expired")

    return {"user_id": claims.sub, "session_id": claims.sid}
