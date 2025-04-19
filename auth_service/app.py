from flask import Flask, request, render_template, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import jwt
import datetime
import json
import os
from otp_handler import create_otp, validate_otp, send_otp_email

# Initialize Flask app
app = Flask(__name__)
app.secret_key = "a_very_secret_random_key_12345"

# JWT Secret Key
SECRET_KEY = "your_jwt_secret_key"

# Path to users.json
USERS_FILE = os.path.join(os.path.dirname(__file__), "users.json")

# Load and Save User Functions
def load_users():
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, "w") as file:
            json.dump({}, file)
    with open(USERS_FILE, "r") as file:
        users = json.load(file)
        print("Loaded users:", users)  # Debugging line to check the loaded users
        return users

def save_users(users):
    with open(USERS_FILE, "w") as file:
        json.dump(users, file, indent=4)

# Load users from JSON
users = load_users()

# JWT Decorator
def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("token")
        if not token:
            flash("Unauthorized access. Please log in.", "error")
            return redirect(url_for("login"))

        try:
            decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.user = decoded_token["username"]
        except jwt.ExpiredSignatureError:
            flash("Session expired. Please log in again.", "error")
            return redirect(url_for("login"))
        except jwt.InvalidTokenError:
            flash("Invalid token. Please log in again.", "error")
            return redirect(url_for("login"))

        return f(*args, **kwargs)
    return decorated

# Routes

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")
        role = request.form.get("role")

        if not username or not password or not email or not role:
            flash("All fields are required!", "error")
            return render_template("register.html")

        if username in users:
            flash("User already exists!", "error")
            return render_template("register.html")

        hashed_password = generate_password_hash(password)
        users[username] = {"password": hashed_password, "email": email, "role": role}
        save_users(users)
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/", methods=["GET", "POST"])
def login():
    if request.args.get('session_timeout'):
        flash("Your session has expired due to inactivity. Please log in again.", "error")
        
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            flash("Username and password are required!", "error")
            return render_template("login.html")

        if username not in users:
            flash("User not registered!", "error")
            return render_template("login.html")

        if not check_password_hash(users[username]["password"], password):
            flash("Invalid username or password!", "error")
            return render_template("login.html")

        otp = create_otp(username)
        if send_otp_email(users[username]["email"], otp):
            flash("OTP sent to your email.", "success")
            return render_template("login.html", username=username, otp_form=True)
        else:
            flash("Failed to send OTP. Please try again.", "error")
            return render_template("login.html")

    return render_template("login.html")

@app.route("/validate-otp", methods=["POST"])
def validate_otp_route():
    username = request.form.get("username")
    entered_otp = request.form.get("otp")

    if not username or not entered_otp:
        flash("OTP and username are required!", "error")
        return render_template("login.html")

    valid, message = validate_otp(username, entered_otp)
    if valid:
        try:
            role = users[username].get("role", "user")  # Default to 'user' if role not set
            token = jwt.encode(
                {
                    "username": username,
                    "role": role,
                    "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=10)
                },
                SECRET_KEY,
                algorithm="HS256"
            )
            if isinstance(token, bytes):
                token = token.decode('utf-8')

            flash("Login successful!", "success")
            response = redirect(url_for("dashboard"))
            response.set_cookie("token", token, httponly=True, secure=False)
            return response
        except Exception as e:
            flash(f"Error generating token: {e}", "error")
            return render_template("login.html", username=username, otp_form=True)
    else:
        flash(message, "error")
        return render_template("login.html", username=username, otp_form=True)


@app.route("/dashboard")
@jwt_required
def dashboard():
    username = request.user
    token = request.cookies.get("token")
    decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    role = decoded_token.get("role", "user")
    return render_template("dashboard.html", username=username, role=role)


@app.route("/logout")
def logout():
    response = redirect(url_for("login"))
    response.delete_cookie("token")  # Remove JWT Token
    flash("You have been logged out.", "success")
    return response

@app.route("/manage-users", methods=["GET", "POST"])
@jwt_required
def manage_users():
    username = request.user
    token = request.cookies.get("token")
    decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    role = decoded_token.get("role", "user")

    # Ensure the logged-in user is an admin
    if role != "admin":
        flash("Unauthorized access.", "error")
        return redirect(url_for("dashboard"))

    # Handle user deletion
    if request.method == "POST":
        user_to_delete = request.form.get("username")
        if user_to_delete in users and users[user_to_delete]["role"] == "user":
            del users[user_to_delete]
            save_users(users)
            flash(f"User '{user_to_delete}' deleted successfully.", "success")
        else:
            flash("User not found or cannot delete an admin user.", "error")

    # Fetch all users with the role 'user'
    user_list = [
        {"username": u, "email": details["email"]}
        for u, details in users.items()
        if details.get("role") == "user"
    ]

    # Add debugging to check if the user list is populated
    flash(f"User List: {user_list}", "info")

    return render_template("dashboard.html", username=username, role=role, user_list=user_list)



if __name__ == "__main__":
    # Print PyJWT library path for debugging
    try:
        import jwt
        print("JWT module path:", jwt.__file__)
    except ImportError:
        print("Error: PyJWT module not found!")
    
    app.run(debug=True, host="0.0.0.0", port=5003)
