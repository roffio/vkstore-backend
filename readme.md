# RuStore MVP API

Эта документация описывает текущие эндпоинты FastAPI приложения для управления каталогом приложений, пользователями и их действиями (регистрация, авторизация, просмотр приложений, загрузка APK и т.д.).

Все ответы обернуты в JSON следующего формата:

```json
{
  "responce_code": <HTTP code>,
  "data": {}
}
```

---

## 1. Пинг сервера

```
GET /ping
```

**Ответ:**

```json
{
  "responce_code": 200,
  "data": "Pong"
}
```

---

## 2. Приложения

### 2.1. Список приложений

```
GET /apps
```

**Параметры (опционально):**

* `tag` - фильтр по категории
* `filter` - `new`, `popular`, `redaction`
* `search` - поиск по названию/описанию/разработчику
* `sort` - поле для сортировки (`Downloads`, `Rating`)
* `order` - `asc` или `desc`

**Пример:**

```
GET /apps?tag=Игры&filter=popular&search=roffio
```

### 2.2. Карточка приложения

```
GET /apps/{app_id}
```

**Ответ:**

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
    "Description": "The ORIGINAL starwalker",
    "EditorChoice": 0,
    "SimilarApps": ""
  }
}
```

### 2.3. Скачивание APK

```
GET /apps/{app_id}/download
```

Возвращает APK через поток. Если передан токен, записывает событие в историю загрузок.

### 2.4. Список категорий (тэгов)

```
GET /tags
```

**Ответ:**

```json
{
  "responce_code": 200,
  "data": ["Игры", "Финансы", "Социальные сети", ...]
}
```

### 2.5. Изображения

```
GET /images/{image_name}
```

Возвращает файл изображения. Поддерживаются форматы PNG, JPG, JPEG.

### 2.6. Похожие приложения

```
GET /apps/{app_id}/similar?top_n=5
```

Возвращает список приложений с похожим описанием в той же категории, сортированных по схожести.

**Ответ:**

```json
{
  "responce_code": 200,
  "data": [
    {"AppID": 10, "score": 0.85},
    {"AppID": 15, "score": 0.80}
  ]
}
```

### 2.7. Рецензии на приложение

#### 2.7.1. Получение рецензий

```
GET /apps/{app_id}/reviews
```

**Ответ:**

```json
{
  "responce_code": 200,
  "data": {
    "average_rating": 4.2,
    "reviews": [
      {
        "rating": 5,
        "comment": "Отличное приложение!",
        "created_at": "2025-11-14T18:30:00Z",
        "reviewer": "Ivan Ivanov"
      }
    ]
  }
}
```

#### 2.7.2. Создание/обновление рецензии

```
POST /apps/{app_id}/reviews
```

**Тело запроса:**

```json
{
  "rating": 5,
  "comment": "Очень удобное приложение"
}
```

**Требуется токен**. Ответ с кодом 201 при успешной отправке.

### 2.8. Фиксация просмотра

```
POST /apps/{app_id}/view
```

Записывает событие просмотра приложения текущим пользователем.

---

## 3. Аутентификация

### 3.1. Регистрация

```
POST /auth/register
```

**Тело запроса:**

```json
{
  "email": "user@example.com",
  "password": "password123",
  "password2": "password123",
  "first_name": "Ivan",
  "last_name": "Ivanov"
}
```

После регистрации отправляется email для подтверждения.

### 3.2. Подтверждение email

```
GET /auth/confirm-email?token=<token>
```

### 3.3. Повторная отправка кода

```
POST /auth/resend-confirmation
```

**Тело запроса:**

```json
{
  "email": "user@example.com"
}
```

### 3.4. Вход в систему

```
POST /auth/login
```

**Тело запроса:**

```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

**Ответ:**

```json
{
  "responce_code": 200,
  "data": {
    "access_token": "<token>",
    "refresh_token": "<refresh_token>",
    "token_type": "bearer",
    "user": {
      "id": 1,
      "email": "user@example.com",
      "first_name": "Ivan",
      "last_name": "Ivanov",
      "is_email_verified": true
    }
  }
}
```

### 3.5. Получение профиля

```
GET /auth/me
```

**Требуется токен.**

### 3.6. История пользователя

```
GET /auth/history/views
GET /auth/history/downloads
```

Возвращает просмотренные и загруженные приложения текущего пользователя.

---

## 4. Загрузка файлов (для администратора)

### 4.1. Изображения

```
POST /images/upload-sequential
```

Загружает изображение с автоматической последовательной нумерацией.

### 4.2. APK

```
POST /apk/upload-sequential
```

Загружает APK с автоматической последовательной нумерацией.

### 4.3. Создание приложения

```
POST /apps/create
```

**Тело запроса:**

```json
{
  "AppName": "My App",
  "SmallIconID": "1",
  "BigIconID": "2",
  "Categories": "Игры",
  "DeveloperName": "Dev",
  "Rating": 4.5
}
```

**Ответ:**

```json
{
  "responce_code": 201,
  "data": {"AppID": 101}
}
```

---

## 5. Ошибки

```json
{
  "responce_code": 400,
  "data": {"error": "Bad Request"}
}
{
  "responce_code": 401,
  "data": {"error": "Unauthorized - Invalid or missing token"}
}
{
  "responce_code": 403,
  "data": {"error": "Forbidden - Action not allowed"}
}
{
  "responce_code": 404,
  "data": {"error": "Not Found"}
}
{
  "responce_code": 500,
  "data": {"error": "Internal Server Error"}
}

```
