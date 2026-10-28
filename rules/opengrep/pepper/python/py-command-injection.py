import os
import shlex
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    # ruleid: pepper.py.command-injection
    os.system("ping -c 1 " + host)
    # ruleid: pepper.py.command-injection
    subprocess.run(f"nslookup {host}", shell=True)
    # ruleid: pepper.py.command-injection
    subprocess.check_output("dig %s" % request.form["d"], shell=True)
    # ruleid: pepper.py.command-injection
    os.popen("whois " + host).read()
    # ruleid: pepper.py.command-injection
    subprocess.call(["bash", "-c", "tar xf " + host])

    # ok: pepper.py.command-injection
    subprocess.run(["ping", "-c", "1", host])
    # ok: pepper.py.command-injection
    subprocess.run("ping -c 1 " + shlex.quote(host), shell=True)
    # ok: pepper.py.command-injection
    os.system("uptime")
    return "ok"


@app.route("/kill/<pid>")
def kill(pid):
    # ruleid: pepper.py.command-injection
    os.system("kill " + pid)
    # ok: pepper.py.command-injection
    os.system("kill %d" % int(pid))
