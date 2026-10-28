from django.http import HttpResponseRedirect
from django.utils.http import url_has_allowed_host_and_scheme
from flask import Flask, redirect, request, url_for

app = Flask(__name__)


@app.route("/login", methods=["POST"])
def login():
    nxt = request.args.get("next")
    # ruleid: pepper.py.open-redirect
    return redirect(nxt)


@app.route("/go")
def go():
    # ruleid: pepper.py.open-redirect
    return redirect(request.args["url"] or "/")


@app.route("/profile")
def profile():
    tab = request.args.get("tab", "")
    # ok: pepper.py.open-redirect
    return redirect("/profile/" + tab)


@app.route("/home")
def home():
    # ok: pepper.py.open-redirect
    return redirect(url_for("index", page=request.args.get("p")))


def django_login(request):
    target = request.GET.get("next", "/")
    if not url_has_allowed_host_and_scheme(target, allowed_hosts={request.get_host()}):
        target = "/"
    # ok: pepper.py.open-redirect
    return HttpResponseRedirect(target)


def django_bad(request):
    # ruleid: pepper.py.open-redirect
    return HttpResponseRedirect(request.POST["return_to"])


@app.route("/out/<link_id>")
def outbound(link_id):
    link = Link.query.get_or_404(link_id)
    # ok: pepper.py.open-redirect
    return redirect(link.target_url)
