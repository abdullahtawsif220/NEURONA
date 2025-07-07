from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this to something secure
DB_NAME = "users.db"

# Create DB if it doesn't exist
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
        conn.commit()
        conn.close()

# Homepage
@app.route('/')
def home():
    return render_template('index.html')

# Register new users
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        raw_password = request.form['password'].strip()
        role = request.form['role']

        if not username or not email or not raw_password or not role:
            flash('Please fill all fields', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(raw_password)

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
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

# Login existing users
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password'].strip()
        role = request.form['role']

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email=? AND role=?", (email, role))
        user = c.fetchone()
        conn.close()

        if user:
            stored_hash = user[3]
            if check_password_hash(stored_hash, password):
                session['username'] = user[1]
                session['email'] = email
                session['role'] = role
                flash('Login successful!', 'success')
                return redirect(url_for(f"{role}_dashboard"))
            else:
                flash('Incorrect Password.', 'danger')
        else:
            flash('Invalid Email or Role.', 'danger')

        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/creator_dashboard')
def creator_dashboard():
    if 'username' in session and session.get('role') == 'creator':
        return render_template('creator_dashboard.html', username=session['username'])
    flash('Access denied. Please log in as Creator.', 'danger')
    return redirect(url_for('login'))

@app.route('/investor_dashboard')
def investor_dashboard():
    if 'username' in session and session.get('role') == 'investor':
        return render_template('investor_dashboard.html', username=session['username'])
    flash('Access denied. Please log in as Investor.', 'danger')
    return redirect(url_for('login'))

# Admin Dashboard
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'username' in session and session.get('role') == 'admin':
        return f"Welcome Admin {session['username']}"
    flash('Access denied. Please log in as Admin.', 'danger')
    return redirect(url_for('login'))

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# Run app
if __name__ == '__main__':
    init_db()
    app.run(debug=True)
