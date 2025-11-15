from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse, FileResponse
from pydantic import BaseModel
from typing import Optional
import sqlite3
from datetime import datetime, timedelta
import os
from pathlib import Path
import zipfile
import io
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Пример FastAPI приложения")

origins = [
    "https://www.commit-store.ru",
    "http://localhost:5173",
    "http://localhost:3000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def wrap_responce(responce, code):
    return {
        "responce_code": code,
        "data":responce
    }

@app.get("/ping")
def look_alive():
    return wrap_responce("Pong", 200)

# GET эндпоинт с параметром
# @app.get("/items/{item_id}")
# def read_item(item_id: int, q: Optional[str] = None):
#     return {"item_id": item_id, "q": q}

# POST эндпоинт
# @app.post("/items/")
# def create_item(item: Item):
#     total_price = item.price + (item.tax if item.tax else 0)
#     return {"name": item.name, "total_price": total_price, "description": item.description}


@app.get("/apps")
def get_apps(
    tag: Optional[str] = None,
    filter: Optional[str] = None,
    search:Optional[str] = None,
    sort: Optional[str] = None,
    order: Optional[str] = None):
    result = []
    conn = sqlite3.connect("db.db")
    cursor = conn.cursor()
    cursor.execute("SELECT AppID, AppName, SmallIconID, BigIconID, AppCardScreenshotsIDs, Rating, Downloads, Categories," \
    " DeveloperName, DeveloperID, ReleaseDate, AgeRestriction, Description, EditorChoice, SimilarApps, CommentListID FROM Apps")
    column_names = [
        "AppID", "AppName", "SmallIconID", "BigIconID", "AppCardScreenshotsIDs", 
        "Rating", "Downloads", "Categories", "DeveloperName", "DeveloperID", 
        "ReleaseDate", "AgeRestriction", "Description", "EditorChoice", "SimilarApps"
    ]
    if tag:
        for row in cursor.fetchall():
            tags = row[7]
            tags_list = tags.split(",")
            #result.append(app_id)
            if tag in tags_list:
                result.append(dict(zip(column_names, row[0:15])))
    else:
        for row in cursor.fetchall():
            result.append(dict(zip(column_names, row[0:15])))
    if filter:
        match filter:
            case "new":
                t = list()
                for i in result:
                    if datetime.strptime(i["ReleaseDate"], "%Y-%m-%dT%H:%M:%SZ") > datetime.now() - timedelta(days=10):
                        t.append(i)
                result = t
            case "popular":
                t = list()
                for i in result:
                    if int(i["Downloads"]) >= 100000:
                        t.append(i)
                result = t
            case "redaction":
                t = list()
                for i in result:
                    if int(i["EditorChoice"]) == 1:
                        t.append(i)
                result = t
    if search:
        t = list()
        for i in result:
            if search in i["AppName"] or search in i["Description"] or search in i["DeveloperName"]:
                t.append(i)
            result = t
    if sort:
        r = False if not order or order == "desc" else True
        result = sorted(result, key=lambda x: x[sort], reverse=r)


    
    if result == []: return wrap_responce("Not Found", 404)
    return wrap_responce(result, 200)


@app.get("/apps/{app_id}")
def get_app(app_id):
    result = dict()
    conn = sqlite3.connect("db.db")
    cursor = conn.cursor()
    cursor.execute("SELECT AppID, AppName, SmallIconID, BigIconID, AppCardScreenshotsIDs, Rating, Downloads, Categories," \
    " DeveloperName, DeveloperID, ReleaseDate, AgeRestriction, Description, EditorChoice, SimilarApps, CommentListID FROM Apps")
    column_names = [
        "AppID", "AppName", "SmallIconID", "BigIconID", "AppCardScreenshotsIDs", 
        "Rating", "Downloads", "Categories", "DeveloperName", "DeveloperID", 
        "ReleaseDate", "AgeRestriction", "Description", "EditorChoice", "SimilarApps"
    ]
    for row in cursor.fetchall():
        t = dict(zip(column_names, row[0:15]))
        if int(t["AppID"]) == int(app_id):
            result=t
    return wrap_responce(result, 200) if result else wrap_responce("Not Found", 404)


@app.get("/apps/{app_id}/download")
def download_app(app_id):
    base = Path("app").resolve()
    file_path = (base / f"{app_id}.apk").resolve()
    if not file_path.exists() or not file_path.is_file() or base not in file_path.parents:
        return wrap_responce("Not Found", 404)

    return StreamingResponse(
        file_path.open("rb"),
        media_type="application/vnd.android.package-archive",
        headers={
            "Content-Disposition": f"attachment; filename={file_path.name}"
        }
    )


@app.get("/tags") # Да, вот так вот, проще писать тут, чем лишний раз парсить бд
def get_tags():
    return wrap_responce(["sport", "games"], 200)


@app.get("/images/{image_name}")
def get_image(image_name: str):
    base = Path("img").resolve()
    for ext in ["png", "jpg", "jpeg"]:
        file_path = (base / f"{image_name}.{ext}").resolve()
        if file_path.exists() and base in file_path.parents:
            return FileResponse(
                file_path,
                media_type=f"image/{ext}",
                filename=file_path.name 
            )
    return wrap_responce("Not Found", 404)

    

# TODO: 2.1, 6(6.1-6.5.2)