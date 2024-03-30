from flask import Flask, render_template, request, abort, jsonify
from functools import wraps
from authmodule import AuthModule
import os
import jwt
import logging


app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
auth_module = AuthModule(app.config["SECRET_KEY"])

logging.basicConfig(level=logging.INFO)


def requires_role(role):
    def decorator(f):
        @wraps(f)
        def decorated_function():
            token = request.headers.get("Authorization")
            if not token:
                abort(403)  # No token provided
            try:
                payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS512"])
                user_id = payload.get("user_id")
                if not auth_module.validate_token(token, user_id, role):
                    abort(401)  # Invalid or expired token
            except jwt.ExpiredSignatureError:
                abort(401)  # Token has expired
            except jwt.InvalidTokenError:
                abort(401)
            return f()
        return decorated_function
    return decorator


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/create", methods=["GET", "POST"])
def create():
    if request.method == "POST":
        user_id = request.form.get("user_id")
        roles_str = request.form.get("roles")
        if user_id and roles_str:
            roles = [role.strip() for role in roles_str.split(",")]
            token = auth_module.create_token(user_id, roles)
            return render_template("create.html", token=token.decode())
    return render_template("create.html")


@app.route("/createandadd", methods=["POST"])
def createandadd():
    if request.method == "POST":
        user_id = request.form.get("user_id")
        roles_str = request.form.get("roles")
        if user_id and roles_str:
            roles = [role.strip() for role in roles_str.split(",")]
            token = auth_module.create_token(user_id, roles)
            # Add token to localStorage
            return jsonify(token.decode())
    return jsonify(message="Failed to add token to localStorage")


@app.route("/validate", methods=["GET", "POST"])
def validate():
    is_valid = None
    if request.method == "POST":
        token = request.form.get("token")
        user_id = request.form.get("user_id")
        role = request.form.get("role")
        if token and user_id and role:
            is_valid = auth_module.validate_token(token.encode(), user_id, role)
    return render_template("validate.html", is_valid=is_valid)


@app.route("/admin", methods=["GET"])
@requires_role("admin")
def admin():
    return render_template("admin.html")


if __name__ == "__main__":
    app.run(debug=False, port=8080)
