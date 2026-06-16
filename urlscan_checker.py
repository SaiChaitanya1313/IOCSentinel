import requests
from config import URLSCAN_API_KEY


def scan_url(url):
    headers = {
        "API-Key": URLSCAN_API_KEY,
        "Content-Type": "application/json"
    }

    data = {"url": url}

    response = requests.post(
        "https://urlscan.io/api/v1/scan/",
        headers=headers,
        json=data
    )

    if response.status_code == 200:
        return response.json()
    return {"error": "URLScan failed"}