from flask import Flask, request, escape
import sqlite3

app = Flask(__name__)


@app.route("/user")
def user():
    uid = request.args.get("id", "")
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("SELECT name FROM users WHERE id = ?", (uid,))
    row = cur.fetchone()
    return escape(row[0] if row else "")
