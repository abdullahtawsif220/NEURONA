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


# Creation of tables(users, ideas) if not already present in project file
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
                linkedin_id TEXT,
                present_address TEXT
            )
        ''')
        c.execute('''
                   CREATE TABLE ideas (
                       id INTEGER PRIMARY KEY AUTOINCREMENT,
                       creator_id INTEGER NOT NULL,
                       title TEXT NOT NULL,
                       category TEXT NOT NULL,
                       industry TEXT,
                       summary TEXT,
                       description TEXT,
                       funding_needed REAL,
                       equity_offered REAL,
                       pitch_deck TEXT,
                       contact_email TEXT,
                       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                       FOREIGN KEY (creator_id) REFERENCES users(id)
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


# Registration logic
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

# Login logic
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
                session['user_id'] = user['id'] # <--- ADD THIS LINE!
                return redirect(url_for(f"{user['role']}_dashboard"))
            else:
                flash('Incorrect password.', 'danger')
        else:
            flash('Invalid email.', 'danger')

        return redirect(url_for('login'))

    return render_template('login.html')


##  --------------------------------------- CREATOR LOGIC STARTS FROM HERE ----------------------------------------- ##

# main creator dashboard
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

    return redirect(url_for('login'))


#verification request sent by creator
@app.route('/creator/verify', methods=['GET', 'POST'])
def verify_creator():
    if 'role' not in session or session['role'] != 'creator':
        return redirect(url_for('login'))

    if request.method == 'POST':
        full_name = request.form['full_name'].strip()
        phone = request.form['phone'].strip()
        gov_id = request.form['gov_id'].strip()
        linkedin_id = request.form['linkedin_id'].strip()
        present_address = request.form['present_address'].strip()

        conn = get_db_connection()

        # --- NEW LOGIC START ---
        # Fetch the current verified status of the user
        current_user = conn.execute("SELECT verified FROM users WHERE email = ?", (session['email'],)).fetchone()

        # If the user was previously declined (verified = 2),
        # set their status back to pending (0) upon re-submission.
        # Otherwise, keep it as it was (likely 0 if initial submission).
        new_verified_status = 0  # Default to pending upon submission
        if current_user and current_user['verified'] == 1:
            # If they were already verified, don't change it to pending
            new_verified_status = 1
        # --- NEW LOGIC END ---

        conn.execute('''
            UPDATE users SET full_name=?, phone=?, gov_id=?, linkedin_id=?, present_address=?, verified=?
            WHERE email=?
        ''', (full_name, phone, gov_id, linkedin_id, present_address, new_verified_status, session['email']))
        conn.commit()
        conn.close()

        flash('Verification request submitted. Wait for admin approval.', 'info')
        # Update the session with the new status immediately
        session['verified'] = new_verified_status
        return redirect(url_for('creator_dashboard'))

    return render_template('verify_creator.html', email=session['email'])



#logic of uploading ideas by a creator
@app.route('/creator/upload_idea')
def upload_idea():
    if 'role' not in session or session['role'] != 'creator':
        return redirect(url_for('login'))

    conn = get_db_connection()
    user = conn.execute('SELECT verified FROM users WHERE email = ?', (session['email'],)).fetchone()
    conn.close()

    if user and user['verified'] == 1:
        return redirect(url_for('submit_idea'))  # your actual submission route
    else:
        flash('Please verify yourself before uploading an idea.', 'warning')
        return redirect(url_for('verify_creator'))


# creator submit ideas logic
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




## ---------------------------------- INVESTOR LOGIC STARTS FROM HERE ------------------------------------------- ##


# main investor dashboard logic
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
    return redirect(url_for('login'))



# verification request sent by investor
@app.route('/investor/verify', methods=['GET', 'POST'])
def verify_investor():
    if 'role' not in session or session['role'] != 'investor':
        return redirect(url_for('login'))

    if request.method == 'POST':
        full_name = request.form['full_name'].strip()
        phone = request.form['phone'].strip()
        gov_id = request.form['gov_id'].strip()
        linkedin_id = request.form['linkedin_id'].strip()
        present_address = request.form['present_address'].strip()

        conn = get_db_connection()

        # Fetch the current verified status of the user
        current_user = conn.execute("SELECT verified FROM users WHERE email = ?", (session['email'],)).fetchone()

        # If the user was previously declined (verified = 2),
        # set their status back to pending (0) upon re-submission.
        # Otherwise, keep it as it was (likely 0 if initial submission).
        new_verified_status = 0  # Default to pending upon submission
        if current_user and current_user['verified'] == 1:
            # If they were already verified, don't change it to pending
            new_verified_status = 1
        # --- NEW LOGIC END ---

        conn.execute('''
           UPDATE users SET full_name=?, phone=?, gov_id=?, linkedin_id=?, present_address=?, verified=?
           WHERE email=?
            ''', (full_name, phone, gov_id, linkedin_id, present_address, new_verified_status, session['email']))
        conn.commit()
        conn.close()

        flash('Verification request submitted. Wait for admin approval.', 'info')
        # Update the session with the new status immediately
        session['verified'] = new_verified_status
        return redirect(url_for('investor_dashboard'))

    return render_template('verify_investor.html', email=session['email'])




## ----------------------------------- ADMIN LOGIC STARTS FROM HERE ------------------------------------------------------------##

# main ADMIN dashboard
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    total_users = conn.execute("SELECT COUNT(*) FROM users WHERE role IN ('creator', 'investor')").fetchone()[0]
    total_ideas = conn.execute("SELECT COUNT(*) FROM ideas").fetchone()[0]
    conn.close()

    return render_template('admin_dashboard.html', username=session.get('username'), total_users=total_users,
                           total_ideas=total_ideas)


# user management inside admin_dashboard.html
@app.route('/user_management')
def user_management():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'creator'")
    total_creators = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'investor'")
    total_investors = cursor.fetchone()[0]
    cursor.execute("SELECT id, username, email, role, verified, full_name, phone, gov_id, linkedin_id, present_address FROM users WHERE role IN ('creator', 'investor')")
    all_users = cursor.fetchall()
    conn.close()

    return render_template('user_management.html', username=session.get('username'), total_creators=total_creators,
                           total_investors=total_investors, all_users=all_users)


#admin deletes a user from user_management
@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    # Prevent admin from deleting other admins or themselves
    cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    user_to_delete_role = cursor.fetchone()
    if user_to_delete_role and user_to_delete_role['role'] == 'admin':
        flash("Cannot delete an admin user.", "danger")
        conn.close()
        return redirect(url_for('user_management'))

    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    flash("User deleted successfully.", "success")
    return redirect(url_for('user_management'))



# verification request from creator is shown in admin panel (verify creator button)
@app.route('/admin/verify_creators')
def verify_creators():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    creators = conn.execute(
        "SELECT id, username, email, full_name, phone, gov_id, linkedin_id, present_address FROM users WHERE role='creator' AND verified=0 AND full_name IS NOT NULL AND full_name != ''"
    ).fetchall()
    conn.close()
    return render_template('admin_verify_creator.html', creators=creators)


# verification request from investor is shown in admin panel (verify investor button)
@app.route('/admin/verify_investors')
def verify_investors():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    investors = conn.execute(
        "SELECT id, username, email, full_name, phone, gov_id, linkedin_id, present_address FROM users WHERE role='investor' AND verified=0 AND full_name IS NOT NULL AND full_name != ''"
    ).fetchall()
    conn.close()
    return render_template('admin_verify_investor.html', investors=investors)


# Admin unverifies a verified user by setting status to 2(declined/unverified)
@app.route('/unverify_user/<int:user_id>/<role>')
def unverify_user(user_id, role):
    # Ensure only admins can perform this action
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()

    # Prevent un-verifying an admin
    if role.lower() == 'admin':
        flash("Cannot unverify an admin user.", "danger")
        conn.close()
        return redirect(url_for('user_management'))

    # Update the user's status to 2 (Declined/Unverified)
    cursor.execute("UPDATE users SET verified = 2 WHERE id = ?", (user_id,))
    conn.commit()

    if cursor.rowcount > 0:
        flash(f"User has been successfully unverified.", "info")
    else:
        flash("Failed to unverify user. User not found.", "warning")

    conn.close()
    return redirect(url_for('user_management'))


#admin approves a creator request in admin_verify_creator.html
@app.route('/admin/approve_creator/<int:user_id>')
def approve_creator(user_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    conn.execute("UPDATE users SET verified=1 WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('admin_dashboard'))


#admin approves an investor request in admin_verify_investor.html
@app.route('/admin/approve_investor/<int:user_id>')
def approve_investor(user_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    conn.execute("UPDATE users SET verified=1 WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('admin_dashboard'))


#admin declines a creator request by setting verified status to 2
@app.route('/decline_creator/<int:user_id>')
def decline_creator(user_id):
    # Ensure only admins can perform this action
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    # Set verified to 2 to indicate a declined status, so it no longer appears as 'pending' (0)
    conn.execute('UPDATE users SET verified = 2 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    flash('Verification request declined.', 'info')
    return redirect(url_for('verify_creators'))


#admin declines an investor request by setting verified status to 2
@app.route('/decline_investor/<int:user_id>')
def decline_investor(user_id):
    # Ensure only admins can perform this action
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    # Set verified to 2 to indicate a declined status, so it no longer appears as 'pending' (0)
    conn.execute('UPDATE users SET verified = 2 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    flash('Verification request declined.', 'info')
    return redirect(url_for('verify_investors'))


#Show ideas info in manage ideas(admin dashboard)
@app.route('/admin_ideas')
def admin_ideas():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    ideas = conn.execute('''
        SELECT 
            i.id, 
            i.title, 
            i.category, 
            i.summary, 
            i.industry,
            i.funding_needed,
            i.equity_offered,
            i.contact_email,
            u.username 
        FROM ideas i 
        JOIN users u ON i.creator_id = u.id
    ''').fetchall()
    conn.close()

    return render_template('admin_ideas.html', ideas=ideas)


# Remove ideas from ideas management(admin dashboard)
@app.route('/remove_idea/<int:idea_id>')
def remove_idea(idea_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    conn.execute('DELETE FROM ideas WHERE id = ?', (idea_id,))
    conn.commit()
    conn.close()
    flash("Idea removed successfully.", "success")
    return redirect(url_for('admin_ideas'))


##  ----------------------------------- ADMIN LOGIC ENDS ----------------------------------------------------------- ##

@app.route("/privacy-policy")
def privacy_policy():
    return render_template("privacy_policy.html")

@app.route("/terms-of-service")
def terms_of_service():
    return render_template("terms_of_service.html")

@app.route("/about_us")
def about_us():
    return render_template("about_us.html")


@app.route("/contact-us")
def contact_us():
    return render_template("contact_us.html")


# logout logic
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


# Runs the app from here
if __name__ == '__main__':
    init_db()
    app.run(debug=True)
