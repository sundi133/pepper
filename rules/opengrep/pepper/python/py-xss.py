import html
from django.http import HttpResponse, JsonResponse
from django.utils.safestring import mark_safe
from flask import Flask, request, render_template
from markupsafe import Markup

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    # ruleid: pepper.py.xss-escaping-disabled
    banner = Markup("<b>Hello " + name + "</b>")
    # ok: pepper.py.xss-escaping-disabled
    safe = Markup("<b>Hello %s</b>") % name
    # ok: pepper.py.xss-escaping-disabled
    other = Markup("<b>Hello " + html.escape(name) + "</b>")
    return render_template("g.html", banner=banner, name=name)


def search(request):
    q = request.GET.get("q", "")
    # ruleid: pepper.py.xss-escaping-disabled
    return HttpResponse("<h1>Results for " + q + "</h1>")


def comment(request):
    # ruleid: pepper.py.xss-escaping-disabled
    body = mark_safe(request.POST["body"])
    # ok: pepper.py.xss-escaping-disabled
    return JsonResponse({"q": request.GET.get("q")})
