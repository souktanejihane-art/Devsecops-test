from flask import Flask, request, jsonify
import sqlite3
import subprocess
import os
import ipaddress
import ast
import operator as op
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-me")

DB_PATH = os.environ.get("DB_PATH", "users.db")
SAFE_FILES_DIR = os.path.abspath(os.environ.get("SAFE_FILES_DIR", "./files"))
ENABLE_DEBUG_ENDPOINT = os.environ.get("ENABLE_DEBUG_ENDPOINT", "false").lower() == "true"


# ---------- DB helpers ----------
def get_user(username: str):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT username, password_hash FROM users WHERE username = ?", (username,))
        return cur.fetchone()


# ---------- /login ----------
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"status": "error", "message": "Missing username or password"}), 400

    row = get_user(username)
    if row and check_password_hash(row["password_hash"], password):
        return jsonify({"status": "success", "user": username})

    return jsonify({"status": "error", "message": "Invalid credentials"}), 401


# ---------- /ping ----------
def validate_ip(host: str) -> str:
    # Tightest approach: only allow literal IPs
    return str(ipaddress.ip_address(host))

@app.route("/ping", methods=["POST"])
def ping():
    data = request.get_json(silent=True) or {}
    host = (data.get("host") or "").strip()

    if not host:
        return jsonify({"status": "error", "message": "Missing host"}), 400

    try:
        host_ip = validate_ip(host)
    except ValueError:
        return jsonify({"status": "error", "message": "Host must be a valid IP address"}), 400

    try:
        result = subprocess.run(
            ["ping", "-c", "1", host_ip],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        output = (result.stdout or "") + (result.stderr or "")
        return jsonify({"output": output, "returncode": result.returncode})
    except subprocess.TimeoutExpired:
        return jsonify({"status": "error", "message": "Ping timed out"}), 504


# ---------- /compute (safe calculator) ----------
_ALLOWED_OPS = {
    ast.Add: op.add,
    ast.Sub: op.sub,
    ast.Mult: op.mul,
    ast.Div: op.truediv,
    ast.FloorDiv: op.floordiv,
    ast.Mod: op.mod,
    ast.Pow: op.pow,
    ast.USub: op.neg,
    ast.UAdd: op.pos,
}

def safe_eval_expr(expr: str) -> float:
    node = ast.parse(expr, mode="eval")

    def _eval(n):
        if isinstance(n, ast.Expression):
            return _eval(n.body)
        if isinstance(n, ast.Constant) and isinstance(n.value, (int, float)):
            return n.value
        if isinstance(n, ast.UnaryOp) and type(n.op) in _ALLOWED_OPS:
            return _ALLOWED_OPS[type(n.op)](_eval(n.operand))
        if isinstance(n, ast.BinOp) and type(n.op) in _ALLOWED_OPS:
            return _ALLOWED_OPS[type(n.op)](_eval(n.left), _eval(n.right))
        raise ValueError("Unsupported expression")

    return _eval(node)

@app.route("/compute", methods=["POST"])
def compute():
    data = request.get_json(silent=True) or {}
    expression = (data.get("expression") or "1+1").strip()

    try:
        result = safe_eval_expr(expression)
    except Exception:
        return jsonify({"status": "error", "message": "Invalid expression"}), 400

    return jsonify({"result": result})


# ---------- /hash (stronger hashing) ----------
@app.route("/hash", methods=["POST"])
def hash_password():
    data = request.get_json(silent=True) or {}
    pwd = data.get("password")
    if not pwd:
        return jsonify({"status": "error", "message": "Missing password"}), 400

    # PBKDF2-SHA256 via Werkzeug
    hashed = generate_password_hash(pwd)
    return jsonify({"hash": hashed})


# ---------- /readfile (restricted) ----------
def safe_join(base_dir: str, user_path: str) -> str:
    base_dir = os.path.abspath(base_dir)
    target = os.path.abspath(os.path.join(base_dir, user_path))
    if not target.startswith(base_dir + os.sep):
        raise ValueError("Invalid path")
    return target

@app.route("/readfile", methods=["POST"])
def readfile():
    data = request.get_json(silent=True) or {}
    filename = (data.get("filename") or "").strip()
    if not filename:
        return jsonify({"status": "error", "message": "Missing filename"}), 400

    try:
        path = safe_join(SAFE_FILES_DIR, filename)
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        return jsonify({"content": content})
    except FileNotFoundError:
        return jsonify({"status": "error", "message": "File not found"}), 404
    except Exception:
        return jsonify({"status": "error", "message": "Invalid filename"}), 400


# ---------- /debug (disabled by default) ----------
@app.route("/debug", methods=["GET"])
def debug():
    if not ENABLE_DEBUG_ENDPOINT:
        return jsonify({"status": "error", "message": "Not found"}), 404
    # Still: do NOT leak secrets in real systems. Keep minimal even in dev.
    return jsonify({
        "debug": True,
        "environment_keys": sorted(list(os.environ.keys()))
    })


@app.route("/hello", methods=["GET"])
def hello():
    return jsonify({"message": "Welcome to the DevSecOps API"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
