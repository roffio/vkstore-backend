# RuStore MVP API - Эндпоинты

## Общая структура

Все эндпоинты используют метод **GET**, так как они только читают данные.

### 1. Список приложений с фильтрацией и поиском

```
GET /apps
```

**Query-параметры (опционально):**

* `tag` - категория приложения
* `filter` - фильтры: `new`, `popular`, `redaction`
* `search` - строка поиска по названию

**Примеры:**

```
GET /apps?tag=Игры&filter=popular&search=Battle
GET /apps?filter=new
GET /apps?search=Calculator
```

**Ответ JSON (пример одного приложения):**

```json
{
    "AppName": "Example Name",
    "SmallIconID": 12345,
    "BigIconID": 12345,
    "AppCardScreenshotsIDs": [12345, 12345],
    "Rating": 5,
    "Downloads": 5000000,
    "Categories": ["Игры", "Развлечения"],
    "DeveloperName": "Bob",
    "DeveloperID": 12345,
    "ReleaseDate": "2025-11-14T18:30:00Z", // iso8601
    "AgeRestriction": "0+",
    "Description": "Lorem Ipsum",
    "EditorChoice": true
}
```

### 2. Карточка конкретного приложения

```
GET /apps/{app_id}
```

**Параметры:**

* `app_id` - ID приложения

**Ответ JSON:** как выше.

### 3. Загрузка конкретного приложения
```
GET /apps/{app_id}/download
```
**Параметры:**

* `app_id` - ID приложения

Так же возвращает апк потоком

### 4. Список категорий (тэгов)

```
GET /tags
```

**Ответ JSON:**

```json
["Финансы", "Игры", "Инструменты", "Транспорт", "Государственные"]
```

### 5. Изображения

```
GET /images?ids=123,456,789
```

Возвращает изображение напрямую через биинарный поток


### Примеры URL

```
GET /apps?tag=Игры&filter=popular
GET /apps?search=Calculator
GET /apps/42
GET /tags
GET /images?ids=123,456
```
