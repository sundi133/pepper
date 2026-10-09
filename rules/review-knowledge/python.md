## Python security review guide
**Sources:** Flask `request.args/form/json/data/values/headers/cookies/files`; Django `request.GET/POST/body/FILES/META`, URL kwargs; FastAPI path/query/body/header params and Pydantic models; Celery task args; CLI/env in services.
**Sinks:** `cursor.execute` with f-string/`%`/concat, Django `raw()`/`extra()`/`RawSQL`, SQLAlchemy `text()` with interpolation; `os.system`, `os.popen`, `subprocess(..., shell=True)`; `eval`/`exec`/`compile`; `pickle.loads`, `marshal.loads`, `dill`, `yaml.load` without SafeLoader, `jsonpickle`; `open()`/`send_file` with input paths, `zipfile/tarfile.extractall` (zip slip); Jinja2 `|safe`, `Markup`, `mark_safe`, `render_template_string`; `redirect(next)`; `requests.get(user_url)` (SSRF); `xml.etree`/`lxml` with entities (XXE).
**Guards:** parameterised `%s`/`?`, ORM querysets, `html.escape`, autoescape on, `SafeLoader`, `defusedxml`, `@login_required`/`@permission_required`, DRF `permission_classes`, FastAPI `Depends(get_current_user)`, `secure_filename` + allowlist.

**Review checklist**
- Django: `Model.objects.get(pk=...)` from URL without filtering by `request.user`/tenant (IDOR); views missing the decorator/mixin siblings have; `@csrf_exempt` on state-changing views; `DEBUG=True`, wildcard `ALLOWED_HOSTS`, `SECRET_KEY` in code.
- DRF: `permission_classes = [AllowAny]` or missing, serializers with `fields='__all__'` exposing/accepting privileged fields (mass assignment), `get_queryset` not scoped to the user.
- FastAPI: routes without the auth dependency used by the router; Pydantic models reused for input that include `is_admin`/`owner_id`; `response_model` missing so internal fields leak.
- Bare `except:`/`except Exception: pass` around auth, signature or payment checks (fail-open).
- Mutable default args / shared class attributes holding per-request or per-user state (cross-user data leak).
- `is` vs `==` on strings/ints in security comparisons; non-constant-time token compare (`==` instead of `hmac.compare_digest`).
- `random` module for tokens (use `secrets`); `hashlib.md5/sha1` for passwords.
- asyncio: blocking calls in async views; check-then-act on shared state without locks/transactions (`select_for_update`).
