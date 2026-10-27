import base64
import json
import pickle
import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/session", methods=["POST"])
def session():
    blob = request.cookies.get("state")
    # ruleid: pepper.py.insecure-deserialization
    state = pickle.loads(base64.b64decode(blob))
    # ruleid: pepper.py.insecure-deserialization
    cfg = yaml.load(request.data, Loader=yaml.Loader)
    # ruleid: pepper.py.insecure-deserialization
    yaml.unsafe_load(request.form["doc"])

    # ok: pepper.py.insecure-deserialization
    cfg2 = yaml.safe_load(request.data)
    # ok: pepper.py.insecure-deserialization
    cfg3 = yaml.load(request.data, Loader=yaml.SafeLoader)
    # ok: pepper.py.insecure-deserialization
    obj = json.loads(request.data)
    # ok: pepper.py.insecure-deserialization
    cached = pickle.loads(redis_client.get("k"))
    return "ok"
