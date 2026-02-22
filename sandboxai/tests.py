import os
import requests

from config import load_env_file

load_env_file()

WEBHOOK_URL_TEST = os.getenv(
    "N8N_WEBHOOK_URL_TEST", "http://192.168.0.10:5678/webhook-test/scan"
)

r = requests.post(WEBHOOK_URL_TEST, json={"url": "https://google.com"})

print(r.json())
