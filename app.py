from flask import Flask, render_template, redirect, url_for, session, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import logging
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///nursing_portal.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    username = db.Column(db.String(150), nullable=True)
    student_number = db.Column(db.String(100), nullable=True, unique=True)
    full_name = db.Column(db.String(150), nullable=False)
    faculty = db.Column(db.String(100), nullable=True)
    year = db.Column(db.String(10), nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    module = db.Column(db.String(100), nullable=True)
    role = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    pending = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        role = request.form.get('role')
        password = request.form.get('password')
        if not role:
            flash("Please select a role.", "danger")
            return redirect(url_for('login'))

        if role == 'student':
            student_number = request.form.get('student_number')
            if not student_number:
                flash("Please enter your student number.", "danger")
                return redirect(url_for('login'))
            user = User.query.filter_by(student_number=student_number, role='student').first()
        elif role in ['lecturer', 'admin']:
            email = request.form.get('email')
            if not email:
                flash("Please enter your email.", "danger")
                return redirect(url_for('login'))
            user = User.query.filter_by(email=email, role=role).first()
        else:
            flash("Invalid role selected.", "danger")
            return redirect(url_for('login'))

        if user and user.check_password(password):
            if user.role != 'admin' and user.pending:
                flash("Your account is awaiting admin approval.", "warning")
                return redirect(url_for('login'))
            session['username'] = user.username or user.email or user.student_number
            session['role'] = user.role
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials. Please try again.", "danger")
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/register/student', methods=['GET', 'POST'])
def register_student():
    if request.method == 'POST':
        student_number = request.form['student_number']
        email = request.form['email']
        full_name = request.form['full_name']
        faculty = request.form['faculty']
        year = request.form['year']
        password = request.form['password']

        if User.query.filter((User.email == email) | (User.student_number == student_number)).first():
            flash("Student number or email already registered.", "danger")
            return redirect(url_for('register_student'))

        user = User(email=email, student_number=student_number, full_name=full_name,
                    faculty=faculty, year=year, role='student', pending=True)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("Student registered. Awaiting admin approval.", "success")
        return redirect(url_for('login'))
    return render_template('register_student.html')

@app.route('/register/lecturer', methods=['GET', 'POST'])
def register_lecturer():
    if request.method == 'POST':
        full_name = request.form['full_name']
        module = request.form['module']
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']

        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "danger")
            return redirect(url_for('register_lecturer'))

        user = User(email=email, full_name=full_name, module=module,
                    phone=phone, role='lecturer', pending=True)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("Lecturer registered. Awaiting admin approval.", "success")
        return redirect(url_for('login'))
    return render_template('register_lecturer.html')

@app.route('/admin/approvals', methods=['GET', 'POST'])
def admin_approvals():
    if 'role' not in session or session['role'] != 'admin':
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for('login'))

    pending_users = User.query.filter_by(pending=True).all()
    if request.method == 'POST':
        approved_ids = request.form.getlist('approve')
        for user_id in approved_ids:
            user = User.query.get(int(user_id))
            if user:
                user.pending = False
        db.session.commit()
        flash("Selected users approved successfully.", "success")
        return redirect(url_for('admin_approvals'))

    return render_template('admin_approvals.html', pending_users=pending_users)

@app.route('/dashboard')
def dashboard():
    try:
        username = session['username']
        role = session['role']
    except KeyError:
        flash('Please log in first.', 'warning')
        return redirect(url_for('login'))

    return render_template('dashboard.html', username=username, role=role)

@app.route('/assignments')
def assignments():
    return render_template('assignments.html')

@app.route('/grades')
def grades():
    return render_template('grades.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/error')
def error():
    return render_template('error.html', message="An unexpected error occurred.")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
