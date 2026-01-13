from flask import Flask, request
import hashlib
import subprocess
app = Flask(__name__)
# Mot de passe en dur (mauvaise pratique)
ADMIN_PASSWORD = "123456"
# Cryptographie faible (MD5)
def hash_password(password):
return hashlib.md5(password.encode()).hexdigest()
@app.route("/login")
def login():
username = request.args.get("username")
password = request.args.get("password")
# Authentification faible
if username == "admin" and hash_password(password) ==
hash_password(ADMIN_PASSWORD):
return "Logged in"
return "Invalid credentials"
@app.route("/ping")
def ping():
host = request.args.get("host", "localhost")
# Injection de commande (shell=True)
result = subprocess.check_output(
f"ping -c 1 {host}",
shell=True
)
return result
@app.route("/hello")
def hello():
name = request.args.get("name", "user")
# XSS potentiel
return f"<h1>Hello {name}</h1>"
if __name__ == "__main__":

# Debug activé
app.run(debug=True)