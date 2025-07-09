from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import os
import secrets
import re
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
DB_NAME = "users.db"

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    if not os.path.exists(DB_NAME):
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL
            )
        ''')
        admin_email = "admin@neurona.com"
        admin_password = "admin@123"
        hashed_pw = generate_password_hash(admin_password)
        c.execute("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                  ("Admin", admin_email, hashed_pw, "admin"))
        conn.commit()
        conn.close()
        print(f" Admin created: {admin_email} / {admin_password}")


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password'].strip()
        confirm_password = request.form['confirm_password'].strip()
        role = request.form['role']

        if not username or not email or not password or not confirm_password or not role:
            flash('Please fill all fields.', 'danger')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))

        allowed_domains = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "neurona.com"]
        email_domain = email.split('@')[-1].lower()
        if email_domain not in allowed_domains:
            flash(f"Email domain must be one of: {', '.join(allowed_domains)}", 'danger')
            return redirect(url_for('register'))

        if len(password) < 8 or not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            flash('Password must be at least 8 characters and include a special character.', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users(username, email, password, role) VALUES (?, ?, ?, ?)",
                      (username, email, hashed_password, role))
            conn.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already exists.', 'danger')
            return redirect(url_for('register'))
        finally:
            conn.close()

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password'].strip()

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email=?", (email,))
        user = c.fetchone()
        conn.close()

        if user:
            stored_hash = user['password']
            if check_password_hash(stored_hash, password):
                session['username'] = user['username']
                session['email'] = user['email']
                session['role'] = user['role']
                flash('Login successful!', 'success')
                return redirect(url_for(f"{user['role']}_dashboard"))
            else:
                flash('Incorrect password.', 'danger')
        else:
            flash('Invalid email.', 'danger')

        return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/creator_dashboard')
def creator_dashboard():
    if 'username' in session and session.get('role') == 'creator':
        return render_template('creator_dashboard.html', username=session['username'])
    flash('Access denied. Please login as Creator.', 'danger')
    return redirect(url_for('login'))


@app.route('/investor_dashboard')
def investor_dashboard():
    if 'username' in session and session.get('role') == 'investor':
        return render_template('investor_dashboard.html', username=session['username'])
    flash('Access denied. Please login as Investor.', 'danger')
    return redirect(url_for('login'))


@app.route('/admin_dashboard')
def admin_dashboard():
    if 'role' not in session or session['role'] != 'admin':
        flash('Access denied. Please login as Admin.', 'danger')
        return redirect(url_for('login'))
    return render_template('admin_dashboard.html', username=session.get('username'))


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
