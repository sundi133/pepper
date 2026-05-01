from flask import Flask, request
import subprocess

app = Flask(__name__)


@app.route("/run", methods=["POST"])
def run_cmd():
    cmd = request.form["cmd"]
    subprocess.run(cmd, shell=True)
    return "ok"
