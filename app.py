from flask import Flask, render_template, request, abort, jsonify, make_response
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
            token = request.cookies.get("session")
            if not token:
                abort(403)  # No token provided
            try:
                if not auth_module.validate_token_role(token, role):
                    abort(401)  # Invalid or expired token
            except jwt.ExpiredSignatureError:
                abort(401)
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
            response = make_response(render_template("create.html", token=token))
            response.set_cookie("session", token, httponly=True)
            return response
    return render_template("create.html")


@app.route("/validate", methods=["GET", "POST"])
def validate():
    is_valid = None
    if request.method == "POST":
        token = request.form.get("token")
        user_id = request.form.get("user_id")
        role = request.form.get("role")
        if token and user_id and role:
            is_valid = auth_module.validate_token(token.encode())
    return render_template("validate.html", is_valid=is_valid)


@app.route("/admin", methods=["GET"])
@requires_role("admin")
def admin():
    return render_template("admin.html")


if __name__ == "__main__":
    app.run(debug=False, port=8080)
