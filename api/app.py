from flask import Flask, request, jsonify
import sqlite3
import subprocess
import bcrypt
import os
import re

app = Flask(_name_)

# -------------------------------------------
# SECURE LOGIN (no SQL injection)
# -------------------------------------------
@app.route("/login", methods=["POST"])
def login():
    data = request.json

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Missing fields"}), 400

    try:
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()

        cursor.execute("SELECT password FROM users WHERE username=?", (username,))
        row = cursor.fetchone()

        if row and bcrypt.checkpw(password.encode(), row[0].encode()):
            return jsonify({"status": "success", "user": username})

        return jsonify({"error": "Invalid credentials"}), 401

    except Exception:
        return jsonify({"error": "Server error"}), 500


# -------------------------------------------
# SECURE PING (no command injection)
# -------------------------------------------
@app.route("/ping", methods=["POST"])
def ping():
    host = request.json.get("host", "")

    # Accept only valid hostname/IP
    if not re.match(r"^[a-zA-Z0-9\.\-]+$", host):
        return jsonify({"error": "Invalid host"}), 400

    try:
        output = subprocess.check_output(["ping", "-c", "1", host])
        return jsonify({"output": output.decode()})
    except Exception:
        return jsonify({"error": "Ping failed"}), 400


# -------------------------------------------
# SECURE COMPUTE (remove eval)
# -------------------------------------------
@app.route("/compute", methods=["POST"])
def compute():
    return jsonify({"error": "This endpoint is disabled for security reasons"}), 403


# -------------------------------------------
# SECURE HASH (use bcrypt, not MD5)
# -------------------------------------------
@app.route("/hash", methods=["POST"])
def hash_password():
    pwd = request.json.get("password")

    if not pwd:
        return jsonify({"error": "Missing password"}), 400

    hashed = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt()).decode()

    return jsonify({"hash": hashed})


# -------------------------------------------
# SECURE FILE READING
# -------------------------------------------
@app.route("/readfile", methods=["POST"])
def readfile():
    filename = request.json.get("filename")

    # Validation stricte : uniquement lettres, chiffres, _, -, extension .txt
    if not filename or not re.match(r"^[a-zA-Z0-9_\-]+\.txt$", filename):
        return jsonify({"error": "Invalid filename"}), 400

    # Construire le chemin absolu sécurisé
    safe_dir = os.path.abspath("safe")
    safe_path = os.path.abspath(os.path.join(safe_dir, filename))

    # Vérifier que le fichier reste dans ./safe
    if not safe_path.startswith(safe_dir):
        return jsonify({"error": "Invalid filename"}), 400

    if not os.path.exists(safe_path):
        return jsonify({"error": "File not found"}), 404

    with open(safe_path, "r") as f:
        content = f.read()

    return jsonify({"content": content})


# -------------------------------------------
# REMOVE DEBUG ENDPOINT (dangerous)
# -------------------------------------------
@app.route("/debug", methods=["GET"])
def debug():
    return jsonify({"error": "Debug disabled for security"}), 403


# -------------------------------------------
# HELLO ENDPOINT
# -------------------------------------------
@app.route("/hello", methods=["GET"])
def hello():
    return jsonify({"message": "API secured successfully"})


# -------------------------------------------
# RUN APP
# -------------------------------------------
if _name_ == "_main_":
    app.run(host="0.0.0.0", port=5000)