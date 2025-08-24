from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = "supersecretkey"
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///todo.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)


# ----------------- MODELS -----------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)   # store hashed password
    tasks = db.relationship('Task', backref='owner', lazy=True)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ----------------- ROUTES -----------------
@app.route('/')
def home():
    return redirect(url_for('login'))


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        # password match check
        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for("register"))

        # unique username check
        user = User.query.filter_by(username=username).first()
        if user:
            flash("Username already exists, try another one!", "danger")
            return redirect(url_for("register"))

        # hash with pbkdf2:sha256
        hashed_password = generate_password_hash(password, method="pbkdf2:sha256", salt_length=8)

        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("Account created successfully! Please login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", title="Register")


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()

        if not user or not check_password_hash(user.password, password):
            flash("Invalid username or password!", "danger")
            return redirect(url_for("login"))

        login_user(user)
        flash(f"Welcome back, {user.username} 🌻", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html", title="Login")


@app.route('/dashboard', methods=["GET", "POST"])
@login_required
def dashboard():
    if request.method == "POST":
        task_content = request.form.get("content")
        if task_content.strip():
            new_task = Task(content=task_content, owner=current_user)
            db.session.add(new_task)
            db.session.commit()
            flash("Task added successfully!", "success")
    tasks = Task.query.filter_by(user_id=current_user.id).all()
    return render_template("dashboard.html", tasks=tasks, title="Dashboard")


@app.route('/edit/<int:id>', methods=["GET", "POST"])
@login_required
def edit(id):
    task = Task.query.get_or_404(id)
    if task.owner != current_user:
        flash("Not authorized!", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        task.content = request.form.get("content")
        db.session.commit()
        flash("Task updated!", "success")
        return redirect(url_for("dashboard"))

    return render_template("edit.html", task=task, title="Edit Task")


@app.route('/delete/<int:id>')
@login_required
def delete(id):
    task = Task.query.get_or_404(id)
    if task.owner != current_user:
        flash("Not authorized!", "danger")
        return redirect(url_for("dashboard"))

    db.session.delete(task)
    db.session.commit()
    flash("Task deleted!", "success")
    return redirect(url_for("dashboard"))


@app.route('/complete/<int:id>')
@login_required
def complete(id):
    task = Task.query.get_or_404(id)
    if task.owner != current_user:
        flash("Not authorized!", "danger")
        return redirect(url_for("dashboard"))

    task.completed = not task.completed
    db.session.commit()
    flash("Task status updated!", "success")
    return redirect(url_for("dashboard"))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# ----------------- DB INIT -----------------
if __name__ == "__main__":
    if not os.path.exists("todo.db"):
        with app.app_context():
            db.create_all()
    app.run(debug=True)
