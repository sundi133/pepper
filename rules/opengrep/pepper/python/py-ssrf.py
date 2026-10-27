import requests
import httpx
from urllib.request import urlopen
from flask import Flask, request

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    # ruleid: pepper.py.ssrf
    r = requests.get(url, timeout=5)
    # ruleid: pepper.py.ssrf
    urlopen(request.json["callback"])
    # ruleid: pepper.py.ssrf
    httpx.post(f"{url}/hook", json={})
    session = requests.Session()
    # ruleid: pepper.py.ssrf
    session.get(url)

    # ok: pepper.py.ssrf
    requests.get(f"https://api.github.com/users/{url}")
    # ok: pepper.py.ssrf
    requests.get("https://api.example.com/items/" + url)
    # ok: pepper.py.ssrf
    requests.get("https://api.example.com/search", params={"q": url})
    # ok: pepper.py.ssrf
    db.session.delete(request.args["id"])
    return r.text


@app.route("/items/<item_id>", methods=["DELETE"])
def delete_item(item_id):
    item = session.get(Item, item_id)
    # ok: pepper.py.ssrf
    session.delete(item)
    async with httpx.AsyncClient() as client:
        # ruleid: pepper.py.ssrf
        await client.get(item_id)
