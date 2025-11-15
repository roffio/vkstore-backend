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
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np

app = FastAPI(title="Пример FastAPI приложения")

origins = [
    "https://www.commit-store.ru",
    "http://localhost:5173",
    "http://localhost:3000",
    "https://vk-store-admin-panel-cvw1.vercel.app"
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

def load_apps_from_db():
    conn = sqlite3.connect("db.db")
    cursor = conn.cursor()
    cursor.execute("SELECT AppID, Description, Categories FROM Apps")
    rows = cursor.fetchall()
    conn.close()
    # возвращаем список кортежей (id, описание, категории)
    return rows

apps_data = load_apps_from_db()
# apps_data = [(id1, desc1, cat1), (id2, desc2, cat2), ...]

app_ids = [row[0] for row in apps_data]
descriptions = [row[1] or "" for row in apps_data]
categories = [row[2] or "" for row in apps_data]

# Строим TF‑IDF по всем описаниям
tfidf_vectorizer = TfidfVectorizer(stop_words='english')
tfidf_matrix = tfidf_vectorizer.fit_transform(descriptions)
similarity_matrix = cosine_similarity(tfidf_matrix)

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


@app.get("/apps/{app_id}/similar")
def get_similar_apps_in_same_category(app_id: int, top_n: int = 5):
    # проверка, что такой app_id есть
    if app_id not in app_ids:
        raise HTTPException(status_code=404, detail="App not found")
    # индекс в списке
    idx = app_ids.index(app_id)
    this_category = categories[idx]

    # если категория пустая — можно вернуть ошибку или игнорировать фильтр
    if not this_category:
        raise HTTPException(status_code=400, detail="Category unknown for this app")

    # фильтруем кандидатов: только приложения с той же категорией
    same_cat_indices = [i for i, cat in enumerate(categories) if cat == this_category and i != idx]

    # если нет других в категории
    if not same_cat_indices:
        return wrap_responce([], 200)

    # вычисляем похожесть только с теми, кто в same_cat_indices
    sims = similarity_matrix[idx, same_cat_indices]

    # сортируем кандидатов по похожести
    sorted_idx = np.argsort(-sims)
    result = []
    for rank in sorted_idx[:top_n]:
        i = same_cat_indices[rank]
        result.append({"AppID": app_ids[i], "score": float(sims[rank])})

    return wrap_responce(result, 200)
    

# TODO: 2.1, 6(6.1-6.5.2)