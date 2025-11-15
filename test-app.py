import requests

payload = {
    "AppName": "Test App",
    "SmallIconID": "2",
    "BigIconID": "2",
    "AppCardScreenshotsIDs": "0",
    "Rating": 4.3,
    "Downloads": 5000,
    "Categories": "games,arcade",
    "DeveloperName": "aaa",
    "DeveloperID": 7,
    "ReleaseDate": "2025-11-13T00:00:00Z",
    "AgeRestriction": 10,
    "Description": "Test description",
    "EditorChoice": 0,
    "SimilarApps": "3,4,7",
    "CommentListID": 1
}

res = requests.post("https://commit-store.ru/api/apps/create", json=payload)
print(res.json())
