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
                role TEXT NOT NULL,
                verified INTEGER DEFAULT 0,
                full_name TEXT,
                phone TEXT,
                gov_id TEXT,
                verification_reason TEXT
            )
        ''')
        admin_email = "admin@neurona.com"
        admin_password = "admin@123"
        hashed_pw = generate_password_hash(admin_password)
        c.execute("INSERT INTO users (username, email, password, role, verified) VALUES (?, ?, ?, ?, ?)",
                  ("Admin", admin_email, hashed_pw, "admin", 1))
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
                session['verified'] = user['verified']
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
        conn = get_db_connection()
        user = conn.execute("SELECT verified FROM users WHERE email = ?", (session['email'],)).fetchone()
        conn.close()
        verified = user['verified'] if user else 0
        # Update session so you keep the verified status too
        session['verified'] = verified
        return render_template('creator_dashboard.html', username=session['username'], verified=verified)
    #flash('Access denied. Please login as Creator.', 'danger')
    return redirect(url_for('login'))


@app.route('/creator/verify', methods=['GET', 'POST'])
def verify_creator():
    if 'role' not in session or session['role'] != 'creator':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        full_name = request.form['full_name'].strip()
        phone = request.form['phone'].strip()
        gov_id = request.form['gov_id'].strip()
        reason = request.form['reason'].strip()

        conn = get_db_connection()
        conn.execute('''
            UPDATE users SET full_name=?, phone=?, gov_id=?, verification_reason=?
            WHERE email=?
        ''', (full_name, phone, gov_id, reason, session['email']))
        conn.commit()
        conn.close()

        flash('Verification request submitted. Wait for admin approval.', 'info')
        return redirect(url_for('creator_dashboard'))

    return render_template('verify_creator.html', email=session['email'])

@app.route('/creator/upload_idea')
def upload_idea():
    if 'role' not in session or session['role'] != 'creator':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    user = conn.execute('SELECT verified FROM users WHERE email = ?', (session['email'],)).fetchone()
    conn.close()

    if user and user['verified'] == 1:
        return redirect(url_for('submit_idea'))  # your actual submission route
    else:
        flash('Please verify yourself before uploading an idea.', 'warning')
        return redirect(url_for('verify_creator'))


@app.route('/investor/verify', methods=['GET', 'POST'])
def verify_investor():
    if 'role' not in session or session['role'] != 'investor':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        full_name = request.form['full_name'].strip()
        phone = request.form['phone'].strip()
        gov_id = request.form['gov_id'].strip()
        reason = request.form['reason'].strip()

        conn = get_db_connection()
        conn.execute('''
            UPDATE users SET full_name=?, phone=?, gov_id=?, verification_reason=?
            WHERE email=?
        ''', (full_name, phone, gov_id, reason, session['email']))
        conn.commit()
        conn.close()

        flash('Verification request submitted. Wait for admin approval.', 'info')
        return redirect(url_for('investor_dashboard'))

    return render_template('verify_investor.html', email=session['email'])

@app.route('/investor_dashboard')
def investor_dashboard():
    if 'username' in session and session.get('role') == 'investor':
        conn = get_db_connection()
        user = conn.execute("SELECT verified FROM users WHERE email = ?", (session['email'],)).fetchone()
        conn.close()
        verified = user['verified'] if user else 0
        # Update session so you keep the verified status too
        session['verified'] = verified
        return render_template('investor_dashboard.html', username=session['username'], verified=verified)
    #flash('Access denied. Please login as Investor.', 'danger')
    return redirect(url_for('login'))


@app.route('/admin_dashboard')
def admin_dashboard():
    if session.get('role') != 'admin':
        #flash('Access denied. Please login as Admin.', 'danger')
        return redirect(url_for('login'))
    return render_template('admin_dashboard.html', username=session.get('username'))


@app.route('/admin/verify_creators')
def verify_creators():
    if session.get('role') != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    creators = conn.execute(
        "SELECT id, username, email, full_name, phone, gov_id, verification_reason FROM users WHERE role='creator' AND verified=0"
    ).fetchall()
    conn.close()
    return render_template('admin_verify_creator.html', creators=creators)

@app.route('/admin/verify_investors')
def verify_investors():
    if session.get('role') != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    investors = conn.execute(
        "SELECT id, username, email, full_name, phone, gov_id, verification_reason FROM users WHERE role='investor' AND verified=0"
    ).fetchall()
    conn.close()
    return render_template('admin_verify_investor.html', investors=investors)



@app.route('/admin/approve_creator/<int:user_id>')
def approve_creator(user_id):
    if session.get('role') != 'admin':
       # flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    conn.execute("UPDATE users SET verified=1 WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
   # flash('Creator approved and verified.', 'success')
    return redirect(url_for('verify_creators'))

@app.route('/admin/approve_investor/<int:user_id>')
def approve_investor(user_id):
    if session.get('role') != 'admin':
        #flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    conn.execute("UPDATE users SET verified=1 WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    #flash('Investor approved and verified.', 'success')
    return redirect(url_for('verify_investors'))


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/submit_idea', methods=['GET', 'POST'])
def submit_idea():
    if 'username' not in session or session['role'] != 'creator':
        flash('Only creators can submit ideas.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        category = request.form['category']
        industry = request.form.get('industry')
        summary = request.form.get('summary')
        description = request.form.get('description')
        funding = request.form.get('funding_needed', type=float)
        equity = request.form.get('equity_offered', type=float)
        contact_email = request.form.get('contact_email')

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE email = ?", (session['email'],))
        creator = c.fetchone()

        if creator:
            creator_id = creator['id']
            c.execute('''
                INSERT INTO ideas (
                    creator_id, title, category, industry, summary, description,
                    funding_needed, equity_offered, contact_email
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (creator_id, title, category, industry, summary, description, funding, equity, contact_email))
            conn.commit()
            conn.close()
            flash('Idea submitted successfully!', 'success')
            return redirect(url_for('creator_dashboard'))
        else:
            conn.close()
            flash('Creator not found.', 'danger')
            return redirect(url_for('submit_idea'))

    return render_template('submit_idea.html')


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
