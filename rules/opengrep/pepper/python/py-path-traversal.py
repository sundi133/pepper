import os
from pathlib import Path
from flask import Flask, request, send_file, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)
BASE = "/srv/files"


@app.route("/download")
def download():
    name = request.args.get("file")
    # ruleid: pepper.py.path-traversal
    with open(os.path.join(BASE, name)) as fh:
        data = fh.read()
    # ruleid: pepper.py.path-traversal
    send_file(BASE + "/" + name)
    # ruleid: pepper.py.path-traversal
    os.remove(request.form["path"])
    # ruleid: pepper.py.path-traversal
    Path(BASE, name).read_text()
    # ruleid: pepper.py.path-traversal
    (Path(BASE) / name).write_bytes(b"")

    # ok: pepper.py.path-traversal
    send_from_directory(BASE, name)
    # ok: pepper.py.path-traversal
    open(os.path.join(BASE, os.path.basename(name)))
    # ok: pepper.py.path-traversal
    open(os.path.join(BASE, secure_filename(name)))
    # ok: pepper.py.path-traversal
    open("/etc/app.conf")
    return data


@app.route("/view")
def view():
    full = os.path.realpath(os.path.join(BASE, request.args["f"]))
    if not full.startswith(BASE + os.sep):
        return "forbidden", 403
    # ok: pepper.py.path-traversal
    return send_file(full)


@app.route("/upload", methods=["POST"])
def upload():
    f = request.files["doc"]
    # ruleid: pepper.py.path-traversal
    open(os.path.join(BASE, f.filename), "wb").write(f.read())
    # ruleid: pepper.py.path-traversal
    f.save(os.path.join(BASE, f.filename))
    # ok: pepper.py.path-traversal
    f.save(os.path.join(BASE, secure_filename(f.filename)))
