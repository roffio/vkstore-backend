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

SECRET_KEY = os.environ.get("SECRET_KEY", "super‑secret")
EMAIL_SENDER = os.environ.get("EMAIL_SENDER", "sergeevnicolas20@gmail.com")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD", "tjuk hxyy uvys rikv")
SERVER_NAME = os.environ.get("SERVER_NAME", "localhost:8000")
DB_FILENAME = "db.db"

from fastapi.security import HTTPBearer

token_scheme = HTTPBearer()
optional_token_scheme = HTTPBearer(auto_error=False)

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
    if credentials and credentials.credentials:
        payload = decode_jwt(credentials.credentials)
        if payload and payload.get("type") == "access":
            user = get_user_by_id(int(payload.get("sub")))
            return user
    return None

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

def send_verification_email(to_email: str, token: str, expires_in_minutes: int = 10) -> None:
    msg = EmailMessage()
    msg["Subject"] = "Email verification"
    msg["From"] = EMAIL_SENDER
    msg["To"] = to_email
    text_body = (
        "Hello,\n\n"
        "Please verify your email address using the verification code provided.\n"
        f"Verification code: {token}\n\n"
        f"This code will expire in {expires_in_minutes} minutes.\n"
        "If you did not sign up, please ignore this email.\n"
    )
    msg.set_content(text_body)
    html_body = f"""
    <html>
      <body style="font-family: Arial, sans-serif; color: #333;">
        <h2>Email Confirmation</h2>
        <p>Please verify your email address using the verification code provided.</p>
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
            print(f"Failed to send email: {exc}")
    else:
        print("Sending email to", to_email)
        print(msg)


def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
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

def get_unexpired_token_for_user(user_id: int) -> Optional[sqlite3.Row]:
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
            return None
        return row

def add_view_history(user_id: int, app_id: int) -> None:
    timestamp = datetime.utcnow().isoformat()
    with sqlite3.connect(DB_FILENAME) as conn:
        conn.execute(
            "INSERT INTO view_history (user_id, app_id, viewed_at) VALUES (?, ?, ?)",
            (user_id, app_id, timestamp),
        )
        conn.commit()

def create_review(user_id: int, app_id: int, rating: int, comment: Optional[str]) -> None:
    if rating < 1 or rating > 5:
        raise ValueError("rating must be between 1 and 5")
    timestamp = datetime.utcnow().isoformat()
    with sqlite3.connect(DB_FILENAME) as conn:
        cur = conn.execute(
            "SELECT id FROM reviews WHERE user_id = ? AND app_id = ?",
            (user_id, app_id),
        )
        row = cur.fetchone()
        if row:
            conn.execute(
                "UPDATE reviews SET rating = ?, comment = ?, created_at = ? WHERE id = ?",
                (rating, comment, timestamp, row[0]),
            )
        else:
            conn.execute(
                "INSERT INTO reviews (user_id, app_id, rating, comment, created_at) VALUES (?, ?, ?, ?, ?)",
                (user_id, app_id, rating, comment, timestamp),
            )
        conn.commit()

def get_reviews_for_app(app_id: int) -> list[dict]:
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
    with sqlite3.connect(DB_FILENAME) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.execute(
            """
            SELECT
                vh.app_id,
                vh.viewed_at,
                a.AppID,
                a.AppName,
                a.SmallIconID,
                a.BigIconID,
                a.AppCardScreenshotsIDs,
                a.Rating,
                a.Downloads,
                a.Categories,
                a.DeveloperName,
                a.DeveloperID,
                a.ReleaseDate,
                a.AgeRestriction,
                a.Description,
                a.EditorChoice,
                a.SimilarApps
            FROM view_history vh
            JOIN Apps a ON a.AppID = vh.app_id
            WHERE vh.user_id = ?
            ORDER BY vh.viewed_at DESC
            """,
            (user_id,),
        )
        rows = cur.fetchall()
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
    history: list[dict] = []
    for row in rows:
        viewed_at = row[1]
        app_fields = row[2:17]
        app_data = dict(zip(column_names, app_fields))
        app_data["viewed_at"] = viewed_at
        history.append(app_data)
    return history

def get_user_download_history(user_id: int) -> list[dict]:
    with sqlite3.connect(DB_FILENAME) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.execute(
            """
            SELECT
                dh.app_id,
                dh.downloaded_at,
                a.AppID,
                a.AppName,
                a.SmallIconID,
                a.BigIconID,
                a.AppCardScreenshotsIDs,
                a.Rating,
                a.Downloads,
                a.Categories,
                a.DeveloperName,
                a.DeveloperID,
                a.ReleaseDate,
                a.AgeRestriction,
                a.Description,
                a.EditorChoice,
                a.SimilarApps
            FROM download_history dh
            JOIN Apps a ON a.AppID = dh.app_id
            WHERE dh.user_id = ?
            ORDER BY dh.downloaded_at DESC
            """,
            (user_id,),
        )
        rows = cur.fetchall()
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
    history: list[dict] = []
    for row in rows:
        downloaded_at = row[1]
        app_fields = row[2:17]
        app_data = dict(zip(column_names, app_fields))
        app_data["downloaded_at"] = downloaded_at
        history.append(app_data)
    return history

app = FastAPI(title="Пример FastAPI приложения с авторизацией")

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
    apps_data = []

app_ids = [row[0] for row in apps_data]
descriptions = [row[1] or "" for row in apps_data]
categories = [row[2] or "" for row in apps_data]

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

from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.responses import StreamingResponse

@app.get("/apps/{app_id}/download", response_model=None)
def download_app(
    app_id: int,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(optional_token_scheme),
):
    base = Path(__file__).resolve().parent / "app"
    base = base.resolve()
    file_path = (base / f"{app_id}.apk").resolve()
    if not file_path.exists() or not file_path.is_file() or base not in file_path.parents:
        raise HTTPException(status_code=404, detail="Not Found")
    file_size = file_path.stat().st_size
    user = get_current_user_optional(credentials)
    if user is not None:
        try:
            add_download_history(int(user["id"]), int(app_id))
        except Exception:
            pass
    return StreamingResponse(
        file_path.open("rb"),
        media_type="application/vnd.android.package-archive",
        headers={
            "Content-Disposition": f"attachment; filename={file_path.name}",
            "Content-Length": str(file_size),
        },
    )

@app.get("/tags")
def get_tags():
    tags = [
        "Образование",
        "Фитнес",
        "Здоровье",
        "Музыка",
        "Фотография",
        "Социальные сети",
        "Путешествия",
        "Игры",
        "Продуктивность",
        "Наука",
        "Коммуникация",
        "Развлечения",
        "Финансы",
        "Бизнес",
        "Аркады",
        "Пазлы",
        "Многопользовательские",
        "Экшен",
        "Стратегии",
        "MOBA",
        "Спорт",
        "Гонки",
        "AR / Приключения",
        "Приключения",
        "Утилиты",
        "Маркетплейс",
        "Лайфстайл",
        "Навигация",
        "Транспорт",
        "Доставка еды"
    ]
    return wrap_responce(tags, 200)

@app.get("/images/{image_name}")
def get_image(image_name: str):
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
    raise HTTPException(status_code=404, detail="Not Found")

@app.get("/apps/{app_id}/similar")
def get_similar_apps_in_same_category(app_id: int, top_n: int = 5):
    if not apps_data or similarity_matrix is None:
        return wrap_responce([], 200)
    if app_id not in app_ids:
        raise HTTPException(status_code=404, detail="App not found")
    idx = app_ids.index(app_id)
    this_category = categories[idx]
    if not this_category:
        raise HTTPException(status_code=400, detail="Category unknown for this app")
    same_cat_indices = [
        i for i, cat in enumerate(categories)
        if cat == this_category and i != idx
    ]
    if not same_cat_indices:
        return wrap_responce([], 200)
    sims = similarity_matrix[idx, same_cat_indices]
    sorted_idx = np.argsort(-sims)
    recommended_app_ids: list[int] = []
    for rank in sorted_idx[:top_n]:
        i = same_cat_indices[rank]
        recommended_app_ids.append(app_ids[i])
    if not recommended_app_ids:
        return wrap_responce([], 200)
    conn = sqlite3.connect(DB_FILENAME)
    cursor = conn.cursor()
    cursor.execute(
        """SELECT AppID, AppName, SmallIconID, BigIconID, AppCardScreenshotsIDs,
                  Rating, Downloads, Categories, DeveloperName, DeveloperID,
                  ReleaseDate, AgeRestriction, Description, EditorChoice,
                  SimilarApps, CommentListID
           FROM Apps
           WHERE AppID IN ({placeholders})""".format(
            placeholders=",".join("?" for _ in recommended_app_ids)
        ),
        tuple(recommended_app_ids),
    )
    rows = cursor.fetchall()
    conn.close()
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
    rows_by_id = {row[0]: row for row in rows}
    result: list[dict] = []
    for app_id_rec in recommended_app_ids:
        row = rows_by_id.get(app_id_rec)
        if not row:
            continue
        result.append(dict(zip(column_names, row[0:15])))
    return wrap_responce(result, 200)

class RegisterRequest(BaseModel):
    email: str
    password: constr(min_length=6)
    password2: constr(min_length=6)
    first_name: Optional[str] = None
    last_name: Optional[str] = None

    @validator("email")
    def validate_email(cls, v: str) -> str:
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
    existing = get_user_by_email(email)
    if existing:
        return wrap_responce("Email already registered", 400)
    hashed_password, salt = hash_password(data.password)
    user = create_user(email, hashed_password, salt, data.first_name, data.last_name)
    token = create_verification_token(user["id"], expires_in_minutes=1)
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
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user["is_email_verified"]:
        raise HTTPException(status_code=403, detail="Email is not verified")
    if not verify_password(data.password, user["hashed_password"], user["salt"]):
        raise HTTPException(status_code=401, detail="Invalidpassword")
    access_token = create_jwt(user["id"], expires_in=60 * 60)
    refresh_token = create_refresh_jwt(user["id"], expires_in=60 * 60 * 24 * 7)
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

class ReviewRequest(BaseModel):
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
    try:
        add_view_history(int(current_user["id"]), int(app_id))
    except Exception:
        return wrap_responce("Failed to record view", 500)
    return wrap_responce("View recorded", 200)

@app.get("/auth/history/views")
def get_view_history(current_user: sqlite3.Row = Depends(get_current_user)) -> Dict[str, Any]:
    history = get_user_view_history(int(current_user["id"]))
    return wrap_responce(history, 200)

@app.post("/apps/{app_id}/downloaded")
def record_app_download(
    app_id: int,
    current_user: sqlite3.Row = Depends(get_current_user),
) -> Dict[str, Any]:
    try:
        add_download_history(int(current_user["id"]), int(app_id))
    except Exception:
        return wrap_responce("Failed to record download", 500)
    return wrap_responce("Download recorded", 200)

@app.get("/auth/history/downloads")
def get_download_history(current_user: sqlite3.Row = Depends(get_current_user)) -> Dict[str, Any]:
    history = get_user_download_history(int(current_user["id"]))
    return wrap_responce(history, 200)

@app.post("/apps/{app_id}/reviews")
def submit_review(
    app_id: int,
    data: ReviewRequest,
    current_user: sqlite3.Row = Depends(get_current_user),
) -> Dict[str, Any]:
    try:
        create_review(int(current_user["id"]), int(app_id), data.rating, data.comment)
    except ValueError as e:
        return wrap_responce(str(e), 400)
    except Exception:
        return wrap_responce("Failed to submit review", 500)
    return wrap_responce("Review submitted", 201)

@app.get("/apps/{app_id}/reviews")
def get_app_reviews(app_id: int) -> Dict[str, Any]:
    reviews = get_reviews_for_app(int(app_id))
    avg_rating: Optional[float] = None
    if reviews:
        avg_rating = sum(r["rating"] for r in reviews) / len(reviews)
        avg_rating = round(avg_rating, 1)
    return wrap_responce({"average_rating": avg_rating, "reviews": reviews}, 200)

class ResendRequest(BaseModel):
    email: str

    @validator("email")
    def validate_email(cls, v: str) -> str:
        if "@" not in v or v.count("@") != 1:
            raise ValueError("Invalid email address")
        local, domain = v.split("@", 1)
        if not local or "." not in domain:
            raise ValueError("Invalid email address")
        return v

@app.post("/auth/resend-confirmation")
def resend_confirmation(data: ResendRequest):
    email = data.email.lower()
    user = get_user_by_email(email)
    if user is None:
        return wrap_responce("User not found", 404)
    if user["is_email_verified"]:
        return wrap_responce("Email already verified", 400)
    existing = get_unexpired_token_for_user(user["id"])
    if existing:
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
    token = create_verification_token(user["id"], expires_in_minutes=1)
    send_verification_email(email, token, expires_in_minutes=1)
    return wrap_responce("Verification email resent. Please check your inbox.", 200)

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

@app.post("/images/upload-sequential")
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
