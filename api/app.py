from flask import Flask, request, abort
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import escape
import os
import ipaddress
import subprocess

app = Flask(__name__)

# Stocker un hash fort, pas un mot de passe en clair
# Exemple: export ADMIN_PASSWORD="un_secret_long"
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")
if not ADMIN_PASSWORD:
    raise RuntimeError("Missing ADMIN_PASSWORD env var")

ADMIN_PASSWORD_HASH = generate_password_hash(ADMIN_PASSWORD)  # PBKDF2 par défaut

@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    if username == "admin" and check_password_hash(ADMIN_PASSWORD_HASH, password):
        return {"status": "ok"}, 200

    return {"status": "invalid_credentials"}, 401


def validate_host(host: str) -> str:
    """
    Autorise uniquement:
    - une IP valide (IPv4/IPv6)
    - ou 'localhost'
    (Tu peux élargir à une allowlist de domaines si besoin)
    """
    host = host.strip()
    if host == "localhost":
        return host
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        abort(400, description="Invalid host")


@app.get("/ping")
def ping():
    host = validate_host(request.args.get("host", "127.0.0.1"))

    # Pas de shell=True, arguments séparés
    # Timeout pour éviter le blocage
    result = subprocess.run(
        ["ping", "-c", "1", host],
        capture_output=True,
        text=True,
        timeout=3,
        check=False,
    )

    # Ne renvoie pas brut de brut si tu veux éviter de leak trop d’infos,
    # mais pour une démo, OK.
    return (result.stdout or result.stderr), 200


@app.get("/hello")
def hello():
    name = request.args.get("name", "user")
    return f"<h1>Hello {escape(name)}</h1>"


if __name__ == "__main__":
    # Debug uniquement en dev via env (FLASK_DEBUG=1), pas en dur
    app.run(host="127.0.0.1", port=5000, debug=False)
