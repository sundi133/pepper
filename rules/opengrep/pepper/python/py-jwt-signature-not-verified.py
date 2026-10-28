import jwt


def current_user(token):
    # ruleid: pepper.py.jwt-signature-not-verified
    claims = jwt.decode(token, options={"verify_signature": False})
    return claims["sub"]


def legacy(token):
    # ruleid: pepper.py.jwt-signature-not-verified
    return jwt.decode(token, verify=False)


def none_alg(token, key):
    # ruleid: pepper.py.jwt-signature-not-verified
    return jwt.decode(token, key, algorithms=["HS256", "none"])


def verified(token, jwks):
    # ok: pepper.py.jwt-signature-not-verified
    unverified = jwt.decode(token, options={"verify_signature": False})
    key = jwks[unverified["iss"]]
    return jwt.decode(token, key, algorithms=["RS256"], audience="api")


def good(token, key):
    # ok: pepper.py.jwt-signature-not-verified
    return jwt.decode(token, key, algorithms=["HS256"])
