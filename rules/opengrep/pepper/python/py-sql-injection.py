import sqlite3
from flask import Flask, request
from sqlalchemy import text
from fastapi import FastAPI, Depends

app = Flask(__name__)
api = FastAPI()


@app.route("/users")
def users():
    name = request.args.get("name")
    cur = sqlite3.connect("x.db").cursor()
    # ruleid: pepper.py.sql-injection
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    # ruleid: pepper.py.sql-injection
    cur.execute("SELECT * FROM users WHERE name = '%s'" % request.form["name"])
    # ruleid: pepper.py.sql-injection
    cur.execute("SELECT * FROM users WHERE name = '{}'".format(name))
    # ruleid: pepper.py.sql-injection
    db.session.execute(text("DELETE FROM t WHERE owner = '" + name + "'"))

    # ok: pepper.py.sql-injection
    cur.execute("SELECT * FROM users WHERE name = %s", (name,))
    # ok: pepper.py.sql-injection
    cur.execute("SELECT * FROM users WHERE name = ?", [request.args["name"]])
    # ok: pepper.py.sql-injection
    cur.execute("SELECT * FROM users WHERE id = %d" % int(request.args["id"]))
    # ok: pepper.py.sql-injection
    db.session.execute(text("SELECT * FROM t WHERE owner = :o"), {"o": name})
    return "ok"


def django_view(request):
    q = request.GET["q"]
    # ruleid: pepper.py.sql-injection
    User.objects.raw("SELECT * FROM auth_user WHERE username = '%s'" % q)
    # ruleid: pepper.py.sql-injection
    User.objects.extra(where=["username = '" + q + "'"])
    # ok: pepper.py.sql-injection
    User.objects.raw("SELECT * FROM auth_user WHERE username = %s", [q])
    # ok: pepper.py.sql-injection
    User.objects.filter(username=q)


@api.get("/items/{item_id}")
async def read_item(item_id: str, db=Depends(get_db)):
    # ruleid: pepper.py.sql-injection
    db.execute(f"SELECT * FROM items WHERE id = '{item_id}'")
    # ok: pepper.py.sql-injection
    db.execute("SELECT * FROM items WHERE id = :id", {"id": item_id})


def not_a_handler(name):
    # ok: pepper.py.sql-injection
    cursor.execute(f"SELECT * FROM t WHERE n = '{name}'")
