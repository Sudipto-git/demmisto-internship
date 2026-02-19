import requests

r = requests.post(
    "http://192.168.0.10:5678/webhook/scan", json={"url": "https://google.com"}
)

print(r.json())
