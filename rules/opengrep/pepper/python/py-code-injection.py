import ast
import json
from flask import Flask, request

app = Flask(__name__)


@app.route("/calc")
def calc():
    expr = request.args.get("expr")
    # ruleid: pepper.py.code-injection
    result = eval(expr)
    # ruleid: pepper.py.code-injection
    exec("x = " + request.form["v"])
    # ruleid: pepper.py.code-injection
    mod = importlib.import_module(request.args["plugin"])

    # ok: pepper.py.code-injection
    safe = ast.literal_eval(expr)
    # ok: pepper.py.code-injection
    data = json.loads(request.data)
    # ok: pepper.py.code-injection
    total = eval("1 + 2")
    return str(result)
