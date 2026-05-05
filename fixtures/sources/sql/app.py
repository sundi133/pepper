import sqlite3

conn = sqlite3.connect(":memory:")
uid = input()
cur = conn.cursor()
cur.execute("SELECT * FROM users WHERE id = " + uid)
