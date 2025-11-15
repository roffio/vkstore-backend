from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, constr, validator
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



SECRET_KEY = os.environ.get("SECRET_KEY", "super‑secret")


EMAIL_SENDER = "sergeevnicolas20@gmail.com"

EMAIL_PASSWORD = "tjuk hxyy uvys rikv"
SERVER_NAME = "https://commit-store.ru"

# SQLite database filename
DB_FILENAME = "db.db"


def _initialize_user_tables() -> None:
    with sqlite3.connect(DB_FILENAME) as conn:
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
        conn.commit()


# Run table creation at import time
_initialize_user_tables()



def wrap_responce(responce: Any, code: int) -> Dict[str, Any]:
    return {"responce_code": code, "data": responce}


def hash_password(password: str, salt: Optional[str] = None) -> (str, str):
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
    return dk.hex(), salt


def verify_password(password: str, hashed: str, salt: str) -> bool:
    computed, _ = hash_password(password, salt)
    return hmac.compare_digest(computed, hashed)


def create_jwt(user_id: int, expires_in: int = 60 * 60) -> str:
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


def send_verification_email(to_email: str, token: str, expires_in_minutes: int = 1) -> None:

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


@app.get("/apps/{app_id}/download")
def download_app(app_id: int):
    # APK files are expected under ``apk/`` directory relative to project root
    base = Path(__file__).resolve().parent / ".."  # go up to project root
    base = base.resolve() / "apk"
    file_path = (base / f"{app_id}.apk").resolve()
    if not file_path.exists() or not file_path.is_file() or base not in file_path.parents:
        return wrap_responce("Not Found", 404)
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
    # Image files are expected under ``img/`` directory relative to project root
    base = Path(__file__).resolve().parent / ".."
    base = base.resolve() / "img"
    for ext in ["png", "jpg", "jpeg"]:
        file_path = (base / f"{image_name}.{ext}").resolve()
        if file_path.exists() and base in file_path.parents:
            return FileResponse(
                file_path,
                media_type=f"image/{ext}",
                filename=file_path.name,
            )
    return wrap_responce("Not Found", 404)


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
    email: EmailStr
    password: constr(min_length=6)
    password2: constr(min_length=6)
    first_name: Optional[str] = None
    last_name: Optional[str] = None

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
    email: EmailStr
    password: constr(min_length=6)


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


# Bearer authentication scheme
token_scheme = HTTPBearer()


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


@app.get("/auth/me")
def me(current_user: sqlite3.Row = Depends(get_current_user)):
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
