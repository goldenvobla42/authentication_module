from flask import Flask, render_template, request
from authmodule import AuthModule
import os

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
auth_module = AuthModule(app.config["SECRET_KEY"])


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


if __name__ == "__main__":
    app.run(debug=False, port=8080)
