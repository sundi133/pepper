import hashlib
from werkzeug.security import generate_password_hash


def register(username, password):
    # ruleid: pepper.py.weak-password-hash
    digest = hashlib.md5(password.encode()).hexdigest()
    # ruleid: pepper.py.weak-password-hash
    h = hashlib.sha256(user.password.encode("utf-8")).hexdigest()
    # ok: pepper.py.weak-password-hash
    pw = generate_password_hash(password)
    # ok: pepper.py.weak-password-hash
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
    # ok: pepper.py.weak-password-hash
    etag = hashlib.md5(body).hexdigest()
    # ok: pepper.py.weak-password-hash
    hashlib.sha256(password_reset_url_template.encode())
