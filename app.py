"""
Employee Management System - a Flask + SQLite app for an admin to manage employee records.

How this file is organised:
  1. Setup     - create the Flask app and the SQLite database
  2. Login     - first-time admin setup, login, logout
  3. Dashboard - total employees, average salary, department-wise counts
  4. Employees - add, search, update and delete records
"""
import os
import sqlite3
from functools import wraps

from flask import (Flask, flash, g, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------- 1. Setup
app = Flask(__name__)
# The secret key signs the login cookie. On a real server set your own:
#   export SECRET_KEY="some-long-random-text"
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-me")

DB_PATH = os.path.join(os.path.dirname(__file__), "employees.db")


def get_db():
    """Open one database connection per request."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create the two tables if they do not exist yet."""
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            department TEXT NOT NULL,
            designation TEXT NOT NULL,
            salary REAL NOT NULL
        );
        """
    )
    db.commit()
    db.close()


def admin_exists():
    return get_db().execute("SELECT 1 FROM admins LIMIT 1").fetchone() is not None


def login_required(view):
    """Send people to the login page if they are not logged in."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "admin_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------- 2. Login
@app.route("/setup", methods=["GET", "POST"])
def setup():
    """Create the admin account. Only works while no admin exists."""
    if admin_exists():
        return redirect(url_for("login"))

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        if len(username) < 3:
            flash("Username must be at least 3 characters.")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.")
        else:
            db = get_db()
            db.execute(
                "INSERT INTO admins (username, password_hash) VALUES (?, ?)",
                (username, generate_password_hash(password)),  # never store the plain password
            )
            db.commit()
            flash("Admin account created. Please log in.")
            return redirect(url_for("login"))
    return render_template("setup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if not admin_exists():
        return redirect(url_for("setup"))

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        admin = get_db().execute(
            "SELECT * FROM admins WHERE username = ?", (username,)
        ).fetchone()

        if admin and check_password_hash(admin["password_hash"], password):
            session.clear()
            session["admin_id"] = admin["id"]
            session["username"] = admin["username"]
            return redirect(url_for("dashboard"))
        flash("Wrong username or password.")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ------------------------------------------------------------ 3. Dashboard
@app.route("/")
@login_required
def home():
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    totals = db.execute(
        "SELECT COUNT(*) AS total, AVG(salary) AS average FROM employees"
    ).fetchone()
    departments = db.execute(
        "SELECT department, COUNT(*) AS count FROM employees "
        "GROUP BY department ORDER BY count DESC, department"
    ).fetchall()
    return render_template(
        "dashboard.html",
        total=totals["total"],
        average=totals["average"] or 0,
        departments=departments,
    )


# ------------------------------------------------------------ 4. Employees
def read_form():
    """Read and check the employee form. Returns (data, error_message)."""
    data = {
        "name": request.form["name"].strip(),
        "email": request.form["email"].strip(),
        "department": request.form["department"].strip(),
        "designation": request.form["designation"].strip(),
        "salary": request.form["salary"].strip(),
    }
    if not all(data.values()):
        return data, "Please fill in every field."
    if "@" not in data["email"] or "." not in data["email"]:
        return data, "Please enter a valid email address."
    try:
        data["salary"] = float(data["salary"])
    except ValueError:
        return data, "Salary must be a number."
    if data["salary"] < 0:
        return data, "Salary cannot be negative."
    return data, None


@app.route("/employees")
@login_required
def employees():
    q = request.args.get("q", "").strip()
    db = get_db()
    if q:
        like = f"%{q}%"  # the % signs mean "anything before or after"
        rows = db.execute(
            "SELECT * FROM employees WHERE name LIKE ? OR email LIKE ? "
            "OR department LIKE ? OR designation LIKE ? ORDER BY name",
            (like, like, like, like),
        ).fetchall()
    else:
        rows = db.execute("SELECT * FROM employees ORDER BY name").fetchall()
    return render_template("employees.html", employees=rows, q=q)


@app.route("/employees/add", methods=["GET", "POST"])
@login_required
def add_employee():
    emp = None
    if request.method == "POST":
        emp, error = read_form()
        if error:
            flash(error)
        else:
            db = get_db()
            db.execute(
                "INSERT INTO employees (name, email, department, designation, salary) "
                "VALUES (?, ?, ?, ?, ?)",
                (emp["name"], emp["email"], emp["department"], emp["designation"], emp["salary"]),
            )
            db.commit()
            flash("Employee added.")
            return redirect(url_for("employees"))
    return render_template("form.html", emp=emp, title="Add employee")


@app.route("/employees/<int:emp_id>/edit", methods=["GET", "POST"])
@login_required
def edit_employee(emp_id):
    db = get_db()
    emp = db.execute("SELECT * FROM employees WHERE id = ?", (emp_id,)).fetchone()
    if emp is None:
        flash("Employee not found.")
        return redirect(url_for("employees"))

    if request.method == "POST":
        emp, error = read_form()
        if error:
            flash(error)
        else:
            db.execute(
                "UPDATE employees SET name=?, email=?, department=?, designation=?, salary=? "
                "WHERE id=?",
                (emp["name"], emp["email"], emp["department"], emp["designation"], emp["salary"], emp_id),
            )
            db.commit()
            flash("Employee updated.")
            return redirect(url_for("employees"))
    return render_template("form.html", emp=emp, title="Edit employee")


@app.route("/employees/<int:emp_id>/delete", methods=["POST"])
@login_required
def delete_employee(emp_id):
    db = get_db()
    db.execute("DELETE FROM employees WHERE id = ?", (emp_id,))
    db.commit()
    flash("Employee deleted.")
    return redirect(url_for("employees"))


init_db()

if __na
