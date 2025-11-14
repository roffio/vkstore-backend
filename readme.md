## RuStore MVP API - Эндпоинты (Refined + Full Comments)

Реализованы все эндпоинты, кроме 2.1, 6(6.1-6.5.2)

Результаты всех запросов обернуты в объект:

```json
{
  "response_code": 200,
  "data": {}
}
```

Сервер жив, если по запросу
```
GET /ping
```
вовращается
```
{
    "responce_code":200,
    "data":"Pong"
}
```
---

## 1. Список приложений с фильтрацией и поиском

```
GET /apps
```

**Query-параметры (опционально):**

* `tag` - категория приложения
* `filter` - фильтры: `new`, `popular`, `redaction`
* `search` - строка поиска по названию
* `sort` - сортировка по `downloads`, `rating`
* `order` - по возрастанию/убыванию: `asc`/`desc`

**Пример:**

```
GET  /apps?tag=games&filter=popular&search=roffio
```

**Ответ JSON:**

```json
{
  "responce_code": 200,
  "data": [
    {
      "AppID": 1,
      "AppName": "Generic App 1",
      "SmallIconID": 1,
      "BigIconID": 1,
      "AppCardScreenshotsIDs": null,
      "Rating": 4,
      "Downloads": 100000,
      "Categories": "games",
      "DeveloperName": "roffio",
      "DeveloperID": 1,
      "ReleaseDate": "2025-11-14T18:30:00Z",
      "AgeRestriction": "0+",
      "Description": "A very VERY good app not a test at all don't mind the LORES IPSUM\r\n",
      "EditorChoice": 0,
      "SimilarApps": ""
    }
  ]
}
```

---

## 2. Карточка конкретного приложения

```
GET /apps/{app_id}
Authorization: Bearer <VK_ACCESS_TOKEN> (опционально)
```

**Ответ JSON:**

```json
{
  "responce_code": 200,
  "data": {
    "AppID": 2,
    "AppName": "Generic App 2",
    "SmallIconID": 1,
    "BigIconID": 1,
    "AppCardScreenshotsIDs": null,
    "Rating": 3.9,
    "Downloads": 500,
    "Categories": "sport",
    "DeveloperName": "roffio",
    "DeveloperID": 1,
    "ReleaseDate": "2025-11-14T18:30:00Z",
    "AgeRestriction": "0+",
    "Description": "The ORIGINAL\t\t\t\tstarwalker",
    "EditorChoice": 0,
    "SimilarApps": ""
  }
}
```
(Коментарии пока не делал)
---

## 2.1. Полная загрузка комментариев (WIP)

```
GET /apps/{app_id}/load-comments?page=2&limit=20
Authorization: Bearer <VK_ACCESS_TOKEN>
```

**Ответ JSON:**

```json
{
  "response_code": 200,
  "data": {
    "page": 2,
    "limit": 20,
    "total": 125,
    "comments": [
      {
        "comment_id": 110,
        "vk_id": "vk777",
        "text": "Не понравилось обновление.",
        "likes": 2,
        "dislikes": 5,
        "created_at": "2025-11-15T12:00:00Z"
      }
    ]
  }
}
```

---

## 3. Загрузка APK приложения

```
GET /apps/{app_id}/download
```

Возвращает APK через поток (`StreamingResponse`).

## 4. Список категорий (тэгов)

```
GET /tags
```

**Ответ JSON:**

```json
{
  "responce_code": 200,
  "data": [
    "sport",
    "games"
  ]
}
```

---

## 5. Изображения

```
GET /images/{image_id}
```

Возвращает бинарный поток изображения. Не забывайте проверять формат

## 6. Пользовательский модуль (VK OAuth) (WIP)

Все защищённые действия требуют токен в заголовке `Authorization: Bearer <VK_ACCESS_TOKEN>`.

### 6.1. Регистрация пользователя

```
POST /users
```

**Тело запроса:**

```json
{ "username": "Ivan" }
```

**Ответ:**

```json
{
  "response_code": 201,
  "data": {
    "id": 1,
    "vk_id": "vk123456",
    "username": "Ivan",
    "level": 1,
    "points": 0,
    "created_at": "2025-11-14T18:30:00Z"
  }
}
```

---

### 6.2. Профиль текущего пользователя

```
GET /users/me
```

---

### 6.3. История посещений и скачиваний

* `POST /apps/{app_id}/visited` — фиксация открытия приложения.
* `POST /apps/{app_id}/download` — фиксация скачивания.
  **Ответ JSON:**

```json
{ "response_code": 200, "data": { "status": "ok", "message": "Visit/Download recorded" } }
```

---

### 6.4. Статистика пользователя

```
GET /users/me/stats
```

**Ответ JSON:**

```json
{
  "response_code": 200,
  "data": {
    "visited_apps_count": 25,
    "downloaded_apps_count": 5,
    "visited_apps_ids": [12, 34, 56, 78],
    "downloaded_apps_ids": [12, 56],
    "favorite_categories": ["Игры", "Финансы", "Инструменты"],
    "badges": ["Исследователь игр", "Гуру финансов"],
    "level": 2,
    "points": 150
  }
}
```

---

### 6.5. Комментарии к приложениям

#### 6.5.1. Добавление комментария

```
POST /apps/{app_id}/comment
```

**Тело запроса:**

```json
{ "text": "Отличное приложение!" }
```

**Ответ:**

```json
{ "response_code": 201, "data": { "comment_id": 101, "status": "ok", "message": "Comment added" } }
```

#### 6.5.2. Получение комментариев

```
GET /apps/{app_id}/comments
```

**Ответ JSON:**

```json
{
  "response_code": 200,
  "data": [
    {
      "comment_id": 101,
      "vk_id": "vk123456",
      "text": "Отличное приложение, очень удобное!",
      "likes": 5,
      "dislikes": 0,
      "created_at": "2025-11-14T18:30:00Z"
    },
    {
      "comment_id": 102,
      "vk_id": "vk654321",
      "text": "Можно улучшить интерфейс",
      "likes": 2,
      "dislikes": 1,
      "created_at": "2025-11-14T19:10:00Z"
    }
  ]
}
```

#### 6.5.3. Лайк/дизлайк комментария

```
POST /comments/{comment_id}/vote
```

**Тело запроса:**

```json
{ "vote": "like" } // или "dislike"
```

**Ответ JSON:**

```json
{ "response_code": 200, "data": { "status": "ok", "message": "Vote recorded", "likes": 6, "dislikes": 0 } }
```

---

## 7. Ошибки и коды

```json
{
  "response_code": 400,
  "data": {"error": "Bad Request"}
}
{
  "response_code": 401,
  "data": {"error": "Unauthorized - Invalid or missing VK token"}
}
{
  "response_code": 403,
  "data": {"error": "Forbidden - Action not allowed"}
}
{
  "response_code": 404,
  "data": {"error": "Not Found"}
}
{
  "response_code": 500,
  "data": {"error": "Internal Server Error"}
}
```
