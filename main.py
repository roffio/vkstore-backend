from fastapi import FastAPI, HTTPException, Depends, UploadFile, File
from fastapi.responses import StreamingResponse, FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, constr, validator
from typing import Optional, Dict, Any
import sqlite3
import os
from pathlib import Path
from datetime import datetime, timedelta
import hashlib
import hmac
import base64
import json
import time
import secrets
import smtplib
from email.message import EmailMessage
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials


# ---------------------------------------------------------------------------
# Configuration and constants
# ---------------------------------------------------------------------------

# Secret key for JWT signing
SECRET_KEY = os.environ.get("SECRET_KEY", "super‑secret")

# ---------------------------------------------------------------------------
# Email configuration
#
# The service needs to send verification codes via email.  By default we send
# from the developer's Gmail account.  You can override the sender address
# and password by setting the ``EMAIL_SENDER`` and ``EMAIL_PASSWORD``
# environment variables.  If ``EMAIL_PASSWORD`` is not provided, the hard‑coded
# app password below will be used.  See README for instructions on obtaining
# an app password from Gmail.
#
EMAIL_SENDER = os.environ.get("EMAIL_SENDER", "sergeevnicolas20@gmail.com")
# Use a fallback app password if the environment variable is not set.  This
# is the same password the user provided previously (spaced for readability).
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD", "tjuk hxyy uvys rikv")
SERVER_NAME = os.environ.get("SERVER_NAME", "localhost:8000")

# SQLite database filename
DB_FILENAME = "db.db"

# ---------------------------------------------------------------------------
# Authentication schemes
#
# For endpoints that require authentication (e.g. `/auth/me`), use
# ``token_scheme`` which raises a 401 error automatically when the
# Authorization header is missing or invalid.  For endpoints where
# authentication is optional (e.g. download tracking) but we still want
# to capture a token if present, use ``optional_token_scheme`` with
# ``auto_error=False`` so that missing credentials do not trigger
# an automatic HTTP error.  These are defined here near the top of the
# module so that they exist before being referenced in any route
# definitions.

from fastapi.security import HTTPBearer  # ensure HTTPBearer is in scope

# Bearer authentication scheme (auto_error defaults to True).  This is used
# for protected endpoints such as `/auth/me`, where a missing or
# invalid token should immediately result in a 401.
token_scheme = HTTPBearer()

# Optional bearer scheme for endpoints that do not require
# authentication (like APK downloads) but want to record events if a
# token is provided.  With ``auto_error=False``, FastAPI will not
# automatically raise a 401 if the credentials are missing; instead,
# the dependency returns None and the endpoint can proceed without
# authentication.
optional_token_scheme = HTTPBearer(auto_error=False)

# ---------------------------------------------------------------------------
# Authentication helper functions
# ---------------------------------------------------------------------------

# Define get_current_user early so that it can be referenced in route
# dependencies without triggering a NameError at import time.  This
# function verifies the access token, decodes it and returns the user
# record.  If the token is invalid or expired, it raises HTTP 401.
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(token_scheme),
) -> sqlite3.Row:
    token = credentials.credentials
    payload = decode_jwt(token)
    if payload is None or payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token")
    user_id = payload.get("sub")
    user = get_user_by_id(int(user_id))
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(optional_token_scheme),
) -> Optional[sqlite3.Row]:
    """
    Attempt to retrieve the current user if a valid access token is provided.
    This is used for endpoints where authentication is optional.  Returns
    the user record if the token is valid, otherwise returns None.
    """
    if credentials and credentials.credentials:
        payload = decode_jwt(credentials.credentials)
        if payload and payload.get("type") == "access":
            user = get_user_by_id(int(payload.get("sub")))
            return user
    return None


# ---------------------------------------------------------------------------
# Database initialisation
# ---------------------------------------------------------------------------

def _initialize_user_tables() -> None:
    """
    Ensure all required tables exist in the SQLite database.

    This includes tables for users, email verification tokens,
    view history, download history, and reviews. Existing data is
    preserved.
    """
    with sqlite3.connect(DB_FILENAME) as conn:
        # users table
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                hashed_password TEXT,
                salt TEXT,
                first_name TEXT,
                last_name TEXT,
                is_email_verified INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            """
        )
        # verification tokens table
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS verification_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                expires_at TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            """
        )
        # view history table
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS view_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                app_id INTEGER NOT NULL,
                viewed_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            """
        )
        # download history table
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS download_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                app_id INTEGER NOT NULL,
                downloaded_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            """
        )
        # reviews table
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                app_id INTEGER NOT NULL,
                rating INTEGER NOT NULL,
                comment TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            """
        )
        conn.commit()


# Run table creation at import time
_initialize_user_tables()


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def wrap_responce(responce: Any, code: int) -> Dict[str, Any]:
    """Wrap the API response in a consistent JSON structure."""
    return {"responce_code": code, "data": responce}


def hash_password(password: str, salt: Optional[str] = None) -> (str, str):
    """Hash a password using PBKDF2 with SHA‑256. Returns (hashed, salt)."""
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
    return dk.hex(), salt


def verify_password(password: str, hashed: str, salt: str) -> bool:
    """Verify that the provided password matches the stored hash and salt."""
    computed, _ = hash_password(password, salt)
    return hmac.compare_digest(computed, hashed)


def create_jwt(user_id: int, expires_in: int = 60 * 60) -> str:
    """Generate a signed JWT token with a simple HS256 implementation."""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": user_id, "exp": int(time.time()) + expires_in, "type": "access"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(SECRET_KEY.encode(), signing_input, hashlib.sha256).digest()
    signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
    return f"{header_b64}.{payload_b64}.{signature_b64}"


def create_refresh_jwt(user_id: int, expires_in: int = 60 * 60 * 24 * 7) -> str:
    """Generate a refresh JWT token."""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": user_id, "exp": int(time.time()) + expires_in, "type": "refresh"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(SECRET_KEY.encode(), signing_input, hashlib.sha256).digest()
    signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
    return f"{header_b64}.{payload_b64}.{signature_b64}"


def decode_jwt(token: str) -> Optional[Dict[str, Any]]:
    """Decode and validate a JWT token. Returns payload if valid, else None."""
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
        signing_input = f"{header_b64}.{payload_b64}".encode()
        signature = base64.urlsafe_b64decode(signature_b64 + "==")
        expected_signature = hmac.new(SECRET_KEY.encode(), signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected_signature):
            return None
        payload_json = base64.urlsafe_b64decode(payload_b64 + "==").decode()
        payload = json.loads(payload_json)
        if payload.get("exp", 0) < int(time.time()):
            return None
        return payload
    except Exception:
        return None


def send_verification_email(to_email: str, token: str, expires_in_minutes: int = 10) -> None:
    """
    Send a verification email with the provided token. If SMTP credentials
    are not configured, print the email contents to stdout. Emails include
    both plain text and simple HTML versions with a verification link and
    code. The verification link points to the ``/auth/confirm-email`` endpoint
    on this server.
    """
    verify_url = f"https://{SERVER_NAME}/auth/confirm-email?token={token}"
    msg = EmailMessage()
    msg["Subject"] = "Email verification"
    msg["From"] = EMAIL_SENDER
    msg["To"] = to_email
    # Compose plain text body
    text_body = (
        "Hello,\n\n"
        "Please verify your email address by clicking the link below or use the verification code provided.\n"
        f"Verification link: {verify_url}\n"
        f"Verification code: {token}\n\n"
        f"This code will expire in {expires_in_minutes} minutes.\n"
        "If you did not sign up, please ignore this email.\n"
    )
    msg.set_content(text_body)
    # Compose HTML body
    html_body = f"""
    <html>
      <body style="font-family: Arial, sans-serif; color: #333;">
        <h2>Email Confirmation</h2>
        <p>Please verify your email address by clicking the button below or use the verification code provided.</p>
        <p style="text-align:center; margin: 20px 0;">
          <a href="{verify_url}" style="background-color:#4CAF50;color:white;padding:10px 20px;text-decoration:none;border-radius:4px;">Verify Email</a>
        </p>
        <p>Your verification code:</p>
        <p style="font-size:24px;font-weight:bold;letter-spacing:2px;">{token}</p>
        <p style="margin-top:20px;">This code will expire in {expires_in_minutes} minutes.</p>
        <p>If you did not sign up, please ignore this email.</p>
      </body>
    </html>
    """
    msg.add_alternative(html_body, subtype="html")
    if EMAIL_PASSWORD:
        try:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.login(EMAIL_SENDER, EMAIL_PASSWORD)
                server.send_message(msg)
        except Exception as exc:
            # Log error but do not crash
            print(f"Failed to send email: {exc}")
    else:
        # Print to stdout if not configured
        print("Sending email to", to_email)
        print(msg)


def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    """Retrieve a user row by email from the database."""
    with sqlite3.connect(DB_FILENAME) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.execute("SELECT * FROM users WHERE email = ?", (email,))
        return cur.fetchone()


def get_user_by_id(user_id: int) -> Optional[sqlite3.Row]:
    with sqlite3.connect(DB_FILENAME) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        return cur.fetchone()


def create_user(email: str, hashed_password: str, salt: str, first_name: Optional[str], last_name: Optional[str]) -> sqlite3.Row:
    """Insert a new user into the database and return the row."""
    created_at = datetime.utcnow().isoformat()
    with sqlite3.connect(DB_FILENAME) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.execute(
            """
            INSERT INTO users (email, hashed_password, salt, first_name, last_name, is_email_verified, created_at)
            VALUES (?, ?, ?, ?, ?, 0, ?)
            """,
            (email, hashed_password, salt, first_name, last_name, created_at),
        )
        user_id = cur.lastrowid
        conn.commit()
        return get_user_by_id(user_id)


def create_verification_token(user_id: int, expires_in_minutes: int = 1) -> str:
    """
    Generate and store a verification token for the given user.

    By default the token expires in 1 minute.  You can override the expiry
    by passing ``expires_in_minutes``.  The expiry timestamp is stored as
    ISO‑formatted UTC datetime.
    """
    token = secrets.token_urlsafe(32)
    expires_at = (datetime.utcnow() + timedelta(minutes=expires_in_minutes)).isoformat()
    with sqlite3.connect(DB_FILENAME) as conn:
        conn.execute(
            """
            INSERT INTO verification_tokens (user_id, token, expires_at, used)
            VALUES (?, ?, ?, 0)
            """,
            (user_id, token, expires_at),
        )
        conn.commit()
    return token


def mark_user_verified(token: str) -> bool:
    """Mark the user associated with the token as verified if the token is valid.
    Returns True if successful, False otherwise."""
    with sqlite3.connect(DB_FILENAME) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.execute(
            """
            SELECT vt.id, vt.user_id, vt.expires_at, vt.used, u.is_email_verified
            FROM verification_tokens vt
            JOIN users u ON u.id = vt.user_id
            WHERE vt.token = ?
            """,
            (token,),
        )
        row = cur.fetchone()
        if row is None:
            return False
        if row["used"]:
            return False
        if datetime.fromisoformat(row["expires_at"]) < datetime.utcnow():
            return False
        # Mark token as used and user as verified
        conn.execute(
            "UPDATE verification_tokens SET used = 1 WHERE id = ?",
            (row["id"],),
        )
        conn.execute(
            "UPDATE users SET is_email_verified = 1 WHERE id = ?",
            (row["user_id"],),
        )
        conn.commit()
    return True

# ---------------------------------------------------------------------------
# Verification token helpers
# ---------------------------------------------------------------------------

def get_unexpired_token_for_user(user_id: int) -> Optional[sqlite3.Row]:
    """
    Retrieve the most recent unexpired verification token for a user that has
    not yet been used.  Returns None if no such token exists.
    """
    with sqlite3.connect(DB_FILENAME) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.execute(
            """
            SELECT * FROM verification_tokens
            WHERE user_id = ? AND used = 0
            ORDER BY id DESC
            LIMIT 1
            """,
            (user_id,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        try:
            expires_at = datetime.fromisoformat(row["expires_at"])
        except Exception:
            return None
        if expires_at < datetime.utcnow():
            # Expired, treat as no valid token
            return None
        return row


# ---------------------------------------------------------------------------
# History and review helper functions
# ---------------------------------------------------------------------------

def add_view_history(user_id: int, app_id: int) -> None:
    """
    Record that the specified user has viewed the given application at the
    current UTC time.  The event is stored in the ``view_history`` table.
    """
    timestamp = datetime.utcnow().isoformat()
    with sqlite3.connect(DB_FILENAME) as conn:
        conn.execute(
            "INSERT INTO view_history (user_id, app_id, viewed_at) VALUES (?, ?, ?)",
            (user_id, app_id, timestamp),
        )
        conn.commit()


def add_download_history(user_id: int, app_id: int) -> None:
    """
    Record that the specified user has downloaded the given application at the
    current UTC time.  The event is stored in the ``download_history`` table.
    """
    timestamp = datetime.utcnow().isoformat()
    with sqlite3.connect(DB_FILENAME) as conn:
        conn.execute(
            "INSERT INTO download_history (user_id, app_id, downloaded_at) VALUES (?, ?, ?)",
            (user_id, app_id, timestamp),
        )
        conn.commit()


def create_review(user_id: int, app_id: int, rating: int, comment: Optional[str]) -> None:
    """
    Create a new review for the given app.  If the user has already
    reviewed this app, the existing review will be replaced.  Ratings
    must be between 1 and 5.  Comments are optional.
    """
    if rating < 1 or rating > 5:
        raise ValueError("rating must be between 1 and 5")
    timestamp = datetime.utcnow().isoformat()
    with sqlite3.connect(DB_FILENAME) as conn:
        # Check if review exists
        cur = conn.execute(
            "SELECT id FROM reviews WHERE user_id = ? AND app_id = ?",
            (user_id, app_id),
        )
        row = cur.fetchone()
        if row:
            # update existing
            conn.execute(
                "UPDATE reviews SET rating = ?, comment = ?, created_at = ? WHERE id = ?",
                (rating, comment, timestamp, row[0]),
            )
        else:
            # insert new
            conn.execute(
                "INSERT INTO reviews (user_id, app_id, rating, comment, created_at) VALUES (?, ?, ?, ?, ?)",
                (user_id, app_id, rating, comment, timestamp),
            )
        conn.commit()


def get_reviews_for_app(app_id: int) -> list[dict]:
    """
    Retrieve all reviews for the specified application.  The returned
    list contains dictionaries with the reviewer name (email), rating,
    comment and timestamp.  This function does not perform any
    authentication checks.
    """
    with sqlite3.connect(DB_FILENAME) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.execute(
            """
            SELECT r.rating, r.comment, r.created_at, u.first_name, u.last_name, u.email
            FROM reviews r
            JOIN users u ON u.id = r.user_id
            WHERE r.app_id = ?
            ORDER BY r.created_at DESC
            """,
            (app_id,),
        )
        rows = cur.fetchall()
    result = []
    for row in rows:
        reviewer_name = None
        if row[3] or row[4]:
            reviewer_name = f"{row[3] or ''} {row[4] or ''}".strip()
        data = {
            "rating": row[0],
            "comment": row[1],
            "created_at": row[2],
            "reviewer": reviewer_name if reviewer_name else row[5],
        }
        result.append(data)
    return result


def get_user_view_history(user_id: int) -> list[dict]:
    """
    Fetch the viewing history for a given user.  Returns a list of
    dictionaries containing the AppID and timestamp of each view.
    """
    with sqlite3.connect(DB_FILENAME) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.execute(
            "SELECT app_id, viewed_at FROM view_history WHERE user_id = ? ORDER BY viewed_at DESC",
            (user_id,),
        )
        rows = cur.fetchall()
    return [ {"app_id": row[0], "viewed_at": row[1]} for row in rows ]


def get_user_download_history(user_id: int) -> list[dict]:
    """
    Fetch the download history for a given user.  Returns a list of
    dictionaries containing the AppID and timestamp of each download.
    """
    with sqlite3.connect(DB_FILENAME) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.execute(
            "SELECT app_id, downloaded_at FROM download_history WHERE user_id = ? ORDER BY downloaded_at DESC",
            (user_id,),
        )
        rows = cur.fetchall()
    return [ {"app_id": row[0], "downloaded_at": row[1]} for row in rows ]

# ---------------------------------------------------------------------------
# FastAPI application setup
# ---------------------------------------------------------------------------

app = FastAPI(title="Пример FastAPI приложения с авторизацией")

# Configure CORS
origins = [
    "https://www.commit-store.ru",
    "http://localhost:5173",
    "http://localhost:3000",
    "https://vk-store-admin-panel-cvw1.vercel.app",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Existing catalogue and image endpoints
# ---------------------------------------------------------------------------

# Preload data for similarity calculations
def load_apps_from_db() -> list[tuple]:
    conn = sqlite3.connect(DB_FILENAME)
    cursor = conn.cursor()
    cursor.execute("SELECT AppID, Description, Categories FROM Apps")
    rows = cursor.fetchall()
    conn.close()
    return rows


try:
    apps_data = load_apps_from_db()
except sqlite3.OperationalError:
    # If Apps table does not exist, leave apps_data empty. This prevents startup crash.
    apps_data = []

app_ids = [row[0] for row in apps_data]
descriptions = [row[1] or "" for row in apps_data]
categories = [row[2] or "" for row in apps_data]

# Build TF-IDF and similarity matrix if data exists
if descriptions:
    from sklearn.feature_extraction.text import TfidfVectorizer  # type: ignore
    from sklearn.metrics.pairwise import cosine_similarity  # type: ignore
    import numpy as np  # type: ignore

    tfidf_vectorizer = TfidfVectorizer(stop_words='english')
    tfidf_matrix = tfidf_vectorizer.fit_transform(descriptions)
    similarity_matrix = cosine_similarity(tfidf_matrix)
else:
    similarity_matrix = None


@app.get("/ping")
def look_alive():
    return wrap_responce("Pong", 200)


@app.get("/apps")
def get_apps(
    tag: Optional[str] = None,
    filter: Optional[str] = None,
    search: Optional[str] = None,
    sort: Optional[str] = None,
    order: Optional[str] = None,
):
    result: list[dict] = []
    conn = sqlite3.connect(DB_FILENAME)
    cursor = conn.cursor()
    cursor.execute(
        """SELECT AppID, AppName, SmallIconID, BigIconID, AppCardScreenshotsIDs, Rating, Downloads, Categories,
        DeveloperName, DeveloperID, ReleaseDate, AgeRestriction, Description, EditorChoice, SimilarApps, CommentListID
        FROM Apps"""
    )
    column_names = [
        "AppID",
        "AppName",
        "SmallIconID",
        "BigIconID",
        "AppCardScreenshotsIDs",
        "Rating",
        "Downloads",
        "Categories",
        "DeveloperName",
        "DeveloperID",
        "ReleaseDate",
        "AgeRestriction",
        "Description",
        "EditorChoice",
        "SimilarApps",
    ]
    rows = cursor.fetchall()
    conn.close()

    if tag:
        for row in rows:
            tags = row[7] or ""
            tags_list = tags.split(",")
            if tag in tags_list:
                result.append(dict(zip(column_names, row[0:15])))
    else:
        for row in rows:
            result.append(dict(zip(column_names, row[0:15])))

    if filter:
        filtered: list[dict] = []
        if filter == "new":
            cutoff = datetime.utcnow() - timedelta(days=10)
            for i in result:
                try:
                    dt = datetime.strptime(i["ReleaseDate"], "%Y-%m-%dT%H:%M:%SZ")
                except Exception:
                    continue
                if dt > cutoff:
                    filtered.append(i)
        elif filter == "popular":
            for i in result:
                try:
                    if int(i.get("Downloads") or 0) >= 100000:
                        filtered.append(i)
                except Exception:
                    continue
        elif filter == "redaction":
            for i in result:
                try:
                    if int(i.get("EditorChoice") or 0) == 1:
                        filtered.append(i)
                except Exception:
                    continue
        result = filtered

    if search:
        tmp: list[dict] = []
        for i in result:
            if search.lower() in (i.get("AppName") or "").lower() or search.lower() in (i.get("Description") or "").lower() or search.lower() in (i.get("DeveloperName") or "").lower():
                tmp.append(i)
        result = tmp

    if sort:
        reverse = False if order and order == "asc" else True
        try:
            result = sorted(result, key=lambda x: x.get(sort), reverse=reverse)
        except Exception:
            pass

    if not result:
        return wrap_responce("Not Found", 404)
    return wrap_responce(result, 200)


@app.get("/apps/{app_id}")
def get_app(app_id: int):
    conn = sqlite3.connect(DB_FILENAME)
    cursor = conn.cursor()
    cursor.execute(
        """SELECT AppID, AppName, SmallIconID, BigIconID, AppCardScreenshotsIDs, Rating, Downloads, Categories,
        DeveloperName, DeveloperID, ReleaseDate, AgeRestriction, Description, EditorChoice, SimilarApps, CommentListID
        FROM Apps"""
    )
    column_names = [
        "AppID",
        "AppName",
        "SmallIconID",
        "BigIconID",
        "AppCardScreenshotsIDs",
        "Rating",
        "Downloads",
        "Categories",
        "DeveloperName",
        "DeveloperID",
        "ReleaseDate",
        "AgeRestriction",
        "Description",
        "EditorChoice",
        "SimilarApps",
    ]
    row = None
    for r in cursor.fetchall():
        if int(r[0]) == int(app_id):
            row = r
            break
    conn.close()
    if not row:
        return wrap_responce("Not Found", 404)
    return wrap_responce(dict(zip(column_names, row[0:15])), 200)


@app.get("/apps/{app_id}/download", response_model=None)
def download_app(
    app_id: int,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(optional_token_scheme),
):
    """
    Отдаём APK по app_id. Если передан валидный Bearer-токен,
    пишем запись в историю скачиваний.
    APK-файлы ожидаются в папке `app/` рядом с main.py: app/{app_id}.apk
    """
    # Папка app лежит рядом с main.py
    base = Path(__file__).resolve().parent / "app"
    base = base.resolve()
    file_path = (base / f"{app_id}.apk").resolve()

    # Проверяем, что файл существует и лежит внутри base
    if not file_path.exists() or not file_path.is_file() or base not in file_path.parents:
        raise HTTPException(status_code=404, detail="Not Found")

    # Если есть токен — логируем скачивание
    user = get_current_user_optional(credentials)
    if user is not None:
        try:
            add_download_history(int(user["id"]), int(app_id))
        except Exception:
            # Логирование не должно ломать скачивание
            pass

    return StreamingResponse(
        file_path.open("rb"),
        media_type="application/vnd.android.package-archive",
        headers={"Content-Disposition": f"attachment; filename={file_path.name}"},
    )



@app.get("/tags")
def get_tags():
    # In a real implementation, this should query distinct categories from the database
    return wrap_responce(["sport", "games"], 200)


@app.get("/images/{image_name}")
def get_image(image_name: str):
    # Папка img лежит рядом с main.py
    base = Path(__file__).resolve().parent / "img"
    base = base.resolve()

    for ext in ["png", "jpg", "jpeg"]:
        file_path = (base / f"{image_name}.{ext}").resolve()
        if file_path.exists() and base in file_path.parents:
            return FileResponse(
                file_path,
                media_type=f"image/{ext}",
                filename=file_path.name,
            )

    # Лучше 404 статус, а не 200 с "responce_code": 404
    raise HTTPException(status_code=404, detail="Not Found")



@app.get("/apps/{app_id}/similar")
def get_similar_apps_in_same_category(app_id: int, top_n: int = 5):
    # Ensure similarity matrix exists and there are apps
    if not apps_data or similarity_matrix is None:
        return wrap_responce([], 200)
    # Check that app_id exists
    if app_id not in app_ids:
        raise HTTPException(status_code=404, detail="App not found")
    idx = app_ids.index(app_id)
    this_category = categories[idx]
    if not this_category:
        raise HTTPException(status_code=400, detail="Category unknown for this app")
    # Filter candidates by same category
    same_cat_indices = [i for i, cat in enumerate(categories) if cat == this_category and i != idx]
    if not same_cat_indices:
        return wrap_responce([], 200)
    sims = similarity_matrix[idx, same_cat_indices]
    sorted_idx = np.argsort(-sims)
    result: list[dict] = []
    for rank in sorted_idx[:top_n]:
        i = same_cat_indices[rank]
        result.append({"AppID": app_ids[i], "score": float(sims[rank])})
    return wrap_responce(result, 200)


# ---------------------------------------------------------------------------
# Authentication endpoints
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: str
    password: constr(min_length=6)
    password2: constr(min_length=6)
    first_name: Optional[str] = None
    last_name: Optional[str] = None

    @validator("email")
    def validate_email(cls, v: str) -> str:
        """Basic email validation without external dependencies."""
        if "@" not in v or v.count("@") != 1:
            raise ValueError("Invalid email address")
        local, domain = v.split("@", 1)
        if not local or "." not in domain:
            raise ValueError("Invalid email address")
        return v

    @validator("password2")
    def passwords_match(cls, v: str, values: dict) -> str:
        password = values.get("password")
        if password and v != password:
            raise ValueError("Passwords do not match")
        return v


@app.post("/auth/register")
def register(data: RegisterRequest):
    email = data.email.lower()
    # Check if user exists
    existing = get_user_by_email(email)
    if existing:
        return wrap_responce("Email already registered", 400)
    # Hash password
    hashed_password, salt = hash_password(data.password)
    # Create user
    user = create_user(email, hashed_password, salt, data.first_name, data.last_name)
    # Generate verification token
    # Generate a verification token that expires in 1 minute
    token = create_verification_token(user["id"], expires_in_minutes=1)
    # Send verification email (1 minute expiry)
    send_verification_email(email, token, expires_in_minutes=1)
    return wrap_responce("Registration successful. Please check your email to confirm.", 201)


@app.get("/auth/confirm-email")
def confirm_email(token: str):
    if not token:
        return wrap_responce("Token is required", 400)
    success = mark_user_verified(token)
    if not success:
        return wrap_responce("Invalid or expired token", 400)
    return wrap_responce("Email verified successfully", 200)


class LoginRequest(BaseModel):
    email: str
    password: constr(min_length=6)

    @validator("email")
    def validate_login_email(cls, v: str) -> str:
        """
        Validate that the login email looks like a valid address.  This
        performs a basic check without relying on external libraries.
        """
        if "@" not in v or v.count("@") != 1:
            raise ValueError("Invalid email address")
        local, domain = v.split("@", 1)
        if not local or "." not in domain:
            raise ValueError("Invalid email address")
        return v


@app.post("/auth/login")
def login(data: LoginRequest):
    user = get_user_by_email(data.email.lower())
    if user is None or user["hashed_password"] is None or user["salt"] is None:
        return wrap_responce("Invalid email or password", 401)
    if not user["is_email_verified"]:
        return wrap_responce("Email not verified", 403)
    if not verify_password(data.password, user["hashed_password"], user["salt"]):
        return wrap_responce("Invalid email or password", 401)
    access_token = create_jwt(user["id"], expires_in=60 * 60)  # 1 hour
    refresh_token = create_refresh_jwt(user["id"], expires_in=60 * 60 * 24 * 7)  # 7 days
    return wrap_responce(
        {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "user": {
                "id": user["id"],
                "email": user["email"],
                "first_name": user["first_name"],
                "last_name": user["last_name"],
                "is_email_verified": bool(user["is_email_verified"]),
            },
        },
        200,
    )

# ---------------------------------------------------------------------------
# History and review endpoints
# ---------------------------------------------------------------------------

class ReviewRequest(BaseModel):
    """Model for submitting a review for an application."""
    rating: int
    comment: Optional[str] = None

    @validator("rating")
    def validate_rating(cls, v: int) -> int:
        if v < 1 or v > 5:
            raise ValueError("Rating must be between 1 and 5")
        return v


@app.post("/apps/{app_id}/view")
def record_app_view(
    app_id: int,
    current_user: sqlite3.Row = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Record that the authenticated user has viewed the specified app.  The
    view is timestamped and stored in the ``view_history`` table.  This
    endpoint requires a valid access token.
    """
    try:
        add_view_history(int(current_user["id"]), int(app_id))
    except Exception:
        return wrap_responce("Failed to record view", 500)
    return wrap_responce("View recorded", 200)


@app.get("/auth/history/views")
def get_view_history(current_user: sqlite3.Row = Depends(get_current_user)) -> Dict[str, Any]:
    """
    Return the authenticated user's view history as a list of objects
    containing the app ID and timestamp of each view.  Requires a
    valid access token.
    """
    history = get_user_view_history(int(current_user["id"]))
    return wrap_responce(history, 200)


@app.get("/auth/history/downloads")
def get_download_history(current_user: sqlite3.Row = Depends(get_current_user)) -> Dict[str, Any]:
    """
    Return the authenticated user's download history.  Requires a
    valid access token.
    """
    history = get_user_download_history(int(current_user["id"]))
    return wrap_responce(history, 200)


@app.post("/apps/{app_id}/reviews")
def submit_review(
    app_id: int,
    data: ReviewRequest,
    current_user: sqlite3.Row = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Create or update a review for the specified application.  Requires
    authentication.  The rating must be between 1 and 5.  Comment is
    optional.  If a review by the user already exists, it will be
    replaced.
    """
    try:
        create_review(int(current_user["id"]), int(app_id), data.rating, data.comment)
    except ValueError as e:
        return wrap_responce(str(e), 400)
    except Exception:
        return wrap_responce("Failed to submit review", 500)
    return wrap_responce("Review submitted", 201)


@app.get("/apps/{app_id}/reviews")
def get_app_reviews(app_id: int) -> Dict[str, Any]:
    """
    Retrieve all reviews for the specified app along with the average
    rating.  This endpoint does not require authentication.
    """
    reviews = get_reviews_for_app(int(app_id))
    avg_rating: Optional[float] = None
    if reviews:
        avg_rating = sum(r["rating"] for r in reviews) / len(reviews)
        # Round to one decimal place for readability
        avg_rating = round(avg_rating, 1)
    return wrap_responce({"average_rating": avg_rating, "reviews": reviews}, 200)

# ---------------------------------------------------------------------------
# Resend verification endpoint
# ---------------------------------------------------------------------------

class ResendRequest(BaseModel):
    email: str

    @validator("email")
    def validate_email(cls, v: str) -> str:
        # Simple email validation without external dependencies
        if "@" not in v or v.count("@") != 1:
            raise ValueError("Invalid email address")
        local, domain = v.split("@", 1)
        if not local or "." not in domain:
            raise ValueError("Invalid email address")
        return v


@app.post("/auth/resend-confirmation")
def resend_confirmation(data: ResendRequest):
    """
    Resend a new email verification code for a user who has not yet verified
    their email.  If there is already an unexpired token, instruct the
    caller to wait until it expires.
    """
    email = data.email.lower()
    user = get_user_by_email(email)
    if user is None:
        return wrap_responce("User not found", 404)
    if user["is_email_verified"]:
        return wrap_responce("Email already verified", 400)
    existing = get_unexpired_token_for_user(user["id"])
    if existing:
        # Return how long until expiry
        expires_at = datetime.fromisoformat(existing["expires_at"])
        seconds_left = int((expires_at - datetime.utcnow()).total_seconds())
        minutes, seconds = divmod(max(seconds_left, 0), 60)
        if minutes > 0:
            return wrap_responce(
                f"A code was already sent. Please wait {minutes} minutes and {seconds} seconds until it expires.",
                400,
            )
        else:
            return wrap_responce(
                f"A code was already sent. Please wait {seconds} seconds until it expires.",
                400,
            )
    # Create a new token
    token = create_verification_token(user["id"], expires_in_minutes=1)
    send_verification_email(email, token, expires_in_minutes=1)
    return wrap_responce("Verification email resent. Please check your inbox.", 200)


# (Definitions of token_scheme and optional_token_scheme moved near the top of the file.)


@app.get("/auth/me")
def me(current_user: sqlite3.Row = Depends(get_current_user)):
    """
    Return the currently authenticated user's profile.  Requires a valid
    access token.  The returned data includes the user's id, email,
    first and last name, and whether their email has been verified.
    """
    return wrap_responce(
        {
            "id": current_user["id"],
            "email": current_user["email"],
            "first_name": current_user["first_name"],
            "last_name": current_user["last_name"],
            "is_email_verified": bool(current_user["is_email_verified"]),
        },
        200,
    )


@app.post("/images/upload-sequential") # Бебебе, да, уязвимо, бюджет не дали
async def upload_image_sequential(file: UploadFile = File(...)):
    img_dir = Path(__file__).resolve().parent / "img"
    img_dir.mkdir(parents=True, exist_ok=True)

    existing_files = list(img_dir.glob("*"))
    max_num = 0
    for f in existing_files:
        try:
            num = int(f.stem)
            if num > max_num:
                max_num = num
        except ValueError:
            continue

    ext = Path(file.filename).suffix
    new_num = max_num + 1
    new_name = f"{new_num}{ext}"
    file_path = img_dir / new_name

    with open(file_path, "wb") as f:
        f.write(await file.read())

    return wrap_responce({"id": new_num}, 201)


@app.post("/apk/upload-sequential")
async def upload_apk(file: UploadFile = File(...)):
    apk_dir = Path(__file__).resolve().parent / "app"
    apk_dir.mkdir(parents=True, exist_ok=True)

    existing_files = list(apk_dir.glob("*"))
    max_num = 0
    for f in existing_files:
        try:
            num = int(f.stem)
            if num > max_num:
                max_num = num
        except ValueError:
            continue

    ext = Path(file.filename).suffix
    new_num = max_num + 1
    new_name = f"{new_num}{ext}"
    file_path = apk_dir / new_name

    with open(file_path, "wb") as f:
        f.write(await file.read())

    return wrap_responce({"id": new_num}, 201)



class AppCreate(BaseModel):
    AppName: str
    SmallIconID: Optional[str] = None
    BigIconID: Optional[str] = None
    AppCardScreenshotsIDs: Optional[str] = None
    Rating: Optional[float] = 0
    Downloads: Optional[int] = 0
    Categories: Optional[str] = None
    DeveloperName: Optional[str] = None
    DeveloperID: Optional[int] = None
    ReleaseDate: Optional[str] = None  
    AgeRestriction: Optional[int] = 0
    Description: Optional[str] = None
    EditorChoice: Optional[int] = 0
    SimilarApps: Optional[str] = None
    CommentListID: Optional[int] = None


@app.post("/apps/create")
def create_app(data: AppCreate):

    conn = sqlite3.connect(DB_FILENAME)
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO Apps (
            AppName,
            SmallIconID,
            BigIconID,
            AppCardScreenshotsIDs,
            Rating,
            Downloads,
            Categories,
            DeveloperName,
            DeveloperID,
            ReleaseDate,
            AgeRestriction,
            Description,
            EditorChoice,
            SimilarApps,
            CommentListID
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            data.AppName,
            data.SmallIconID,
            data.BigIconID,
            data.AppCardScreenshotsIDs,
            data.Rating,
            data.Downloads,
            data.Categories,
            data.DeveloperName,
            data.DeveloperID,
            data.ReleaseDate,
            data.AgeRestriction,
            data.Description,
            data.EditorChoice,
            data.SimilarApps,
            data.CommentListID,
        )
    )

    new_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return wrap_responce({"AppID": new_id}, 201)