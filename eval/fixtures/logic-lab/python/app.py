from flask import Flask

from views import admin, documents

app = Flask(__name__)
app.register_blueprint(documents.bp)
app.register_blueprint(admin.bp)


@app.route("/healthz")
def healthz():
    return "ok"
