from flask import Flask, render_template, request, abort, jsonify, make_response, redirect, url_for
from functools import wraps
from authmodule import AuthModule
from authmodule_asym import AuthModuleAsym
import os
import jwt
import logging


app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
auth_module = AuthModule(app.config["SECRET_KEY"])
auth_module_asym = AuthModuleAsym()

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


def requires_role_asym(role):
    def decorator(f):
        @wraps(f)
        def decorated_function():
            token = request.cookies.get("session")
            if not token:
                abort(403)  # No token provided
            try:
                if not auth_module_asym.validate_token_role(token, role):
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
            response.set_cookie("session", token, httponly=True, samesite='Strict')
            return response
    return render_template("create.html")


@app.route("/validate", methods=["GET"])
def validate():
    return render_template("validate.html")

@app.route("/validate_sym", methods=["GET", "POST"])
def validate_sym():
    is_valid = None
    if request.method == "GET":
        return redirect(url_for('validate'))
    if request.method == "POST":
        token = request.form.get("token")
        if token:
            is_valid = auth_module.validate_token(token.encode())
    return render_template("validate.html", is_valid=is_valid)

@app.route("/create_asym", methods=["GET", "POST"])
def create_asym():
    if request.method == "GET":
        return redirect(url_for('create'))
    if request.method == "POST":
        user_id = request.form.get("user_id_asym")
        roles_str = request.form.get("roles_asym")
        if user_id and roles_str:
            roles = [role.strip() for role in roles_str.split(",")]
            token_asym = auth_module_asym.create_token(user_id, roles)
            response = make_response(render_template("create.html", token_asym=token_asym))
            response.set_cookie("session", token_asym, httponly=True, samesite='Strict')
            return response
    return render_template("create.html")

@app.route("/validate_asym", methods=["GET", "POST"])
def validate_asym():
    is_valid = None
    if request.method == "GET":
        return redirect(url_for('validate'))
    if request.method == "POST":
        token = request.form.get("token_asym")
        if token:
            is_valid_asym = auth_module_asym.validate_token(token.encode())
    return render_template("validate.html", is_valid_asym=is_valid_asym)

@app.route("/admin", methods=["GET"])
@requires_role("admin")
def admin():
    return render_template("admin.html")

@app.route("/admin_asym", methods=["GET"])
@requires_role_asym("admin")
def admin_asym():
    return render_template("admin.html")


if __name__ == "__main__":
    app.run(debug=False, port=8080)
