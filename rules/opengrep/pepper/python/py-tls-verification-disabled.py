import ssl
import requests
import httpx

# ruleid: pepper.py.tls-verification-disabled
requests.get("https://internal.example.com", verify=False)
# ruleid: pepper.py.tls-verification-disabled
client = httpx.Client(verify=False)
s = requests.Session()
# ruleid: pepper.py.tls-verification-disabled
s.verify = False
# ruleid: pepper.py.tls-verification-disabled
ctx = ssl._create_unverified_context()
ctx2 = ssl.create_default_context()
# ruleid: pepper.py.tls-verification-disabled
ctx2.verify_mode = ssl.CERT_NONE

# ok: pepper.py.tls-verification-disabled
requests.get("https://internal.example.com", verify="/etc/ssl/internal-ca.pem")
# ok: pepper.py.tls-verification-disabled
requests.get("https://example.com")
