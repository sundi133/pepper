from flask import Flask, request, render_template, render_template_string
from jinja2 import Environment, Template

app = Flask(__name__)
TEMPLATE = "<p>Hello {{ name }}</p>"


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    # ruleid: pepper.py.server-side-template-injection
    render_template_string("<p>Hello " + name + "</p>")
    # ruleid: pepper.py.server-side-template-injection
    Template(f"Hi {name}").render()
    # ruleid: pepper.py.server-side-template-injection
    Environment().from_string(request.form["tpl"]).render()

    env = Environment()
    # ruleid: pepper.py.server-side-template-injection
    env.from_string("Dear " + name).render()

    # ok: pepper.py.server-side-template-injection
    render_template_string(TEMPLATE, name=name)
    # ok: pepper.py.server-side-template-injection
    string.Template("Hi " + name)
    # ok: pepper.py.server-side-template-injection
    Version.from_string(name)
    # ok: pepper.py.server-side-template-injection
    return render_template("hello.html", name=name)
