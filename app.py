import os
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import secrets
import threading

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Make datetime.now available in all Jinja templates
@app.context_processor
def inject_now():
    return {'now': datetime.now}

# Configuration
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Database connection lock
db_lock = threading.Lock()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db_connection():
    """Get database connection with proper timeout and WAL mode for better concurrency"""
    conn = sqlite3.connect(
        'neurona.db', 
        timeout=30,  # Increased timeout
        check_same_thread=False,
        isolation_level=None  # Autocommit mode
    )
    conn.row_factory = sqlite3.Row
    # Enable WAL mode for better concurrency
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA synchronous=NORMAL')
    conn.execute('PRAGMA cache_size=10000')
    conn.execute('PRAGMA temp_store=MEMORY')
    return conn

def execute_db_operation(operation_func, *args, **kwargs):
    """Execute database operations with proper locking and error handling"""
    with db_lock:
        conn = None
        try:
            conn = get_db_connection()
            result = operation_func(conn, *args, **kwargs)
            return result
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                conn.close()

def init_db():
    def _init_db(conn):
        try:
            # Users table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK (role IN ('creator', 'investor', 'admin')),
                    full_name TEXT,
                    phone TEXT,
                    gov_id TEXT,
                    linkedin_id TEXT,
                    present_address TEXT,
                    verified INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
    
            # Ideas table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS ideas (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    username TEXT NOT NULL,
                    title TEXT NOT NULL,
                    category TEXT NOT NULL,
                    tags TEXT,
                    summary TEXT NOT NULL,
                    problem_statement TEXT,
                    solution TEXT,
                    founders TEXT,
                    team_members TEXT,
                    contact_email TEXT NOT NULL,
                    funding_needed REAL NOT NULL,
                    stage TEXT,
                    equity_offered REAL NOT NULL,
                    business_plan TEXT,
                    product_image TEXT,
                    patent TEXT,
                    other_files TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
        
            # Investment requests table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS investment_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investor_id INTEGER NOT NULL,
                    creator_id INTEGER NOT NULL,
                    idea_id INTEGER NOT NULL,
                    investment_amount REAL NOT NULL,
                    message TEXT,
                    status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'declined', 'completed')),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (investor_id) REFERENCES users (id),
                    FOREIGN KEY (creator_id) REFERENCES users (id),
                    FOREIGN KEY (idea_id) REFERENCES ideas (id)
                )
            ''')
        
            # Notifications table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    message TEXT NOT NULL,
                    type TEXT DEFAULT 'info',
                    is_read INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
        
            # Wallet transactions table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS wallet_transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    type TEXT NOT NULL CHECK (type IN ('deposit', 'withdrawal', 'investment', 'funding_received')),
                    amount REAL NOT NULL,
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')

            # Add new table for investments if it doesn't exist
            conn.execute('''
                CREATE TABLE IF NOT EXISTS investments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investor_id INTEGER NOT NULL,
                    creator_id INTEGER NOT NULL,
                    idea_id INTEGER NOT NULL,
                    amount REAL NOT NULL,
                    equity_percentage REAL NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (investor_id) REFERENCES users (id),
                    FOREIGN KEY (creator_id) REFERENCES users (id),
                    FOREIGN KEY (idea_id) REFERENCES ideas (id)
                )
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS wallets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    balance REAL DEFAULT 0,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')

            # Add funded_amount column to ideas table if it doesn't exist
            try:
                conn.execute('ALTER TABLE ideas ADD COLUMN funded_amount REAL DEFAULT 0')
            except sqlite3.OperationalError:
                pass  # Column already exists

            # Add equity_percentage column to wallet_transactions if needed
            try:
                conn.execute('ALTER TABLE wallet_transactions ADD COLUMN equity_percentage REAL')
            except sqlite3.OperationalError:
                pass  # Column already exists
        
            # Check if admin user exists
            admin_exists = conn.execute('SELECT id FROM users WHERE role = "admin"').fetchone()
            if not admin_exists:
                admin_password = generate_password_hash('admin@123')
                cursor = conn.execute('''
                    INSERT INTO users (username, email, password_hash, role, verified)
                    VALUES (?, ?, ?, ?, ?)
                ''', ('admin', 'admin@neurona.com', admin_password, 'admin', 1))
            
                # Create wallet for the admin user
                admin_id = cursor.lastrowid
                conn.execute('''
                    INSERT INTO wallets (user_id, balance)
                    VALUES (?, 0)
                ''', (admin_id,))
        except sqlite3.Error as e:
            print(f"Database initialization error: {e}")
            raise
    
    execute_db_operation(_init_db)

# Initialize database on startup
init_db()

# Helper functions
def login_required(f):
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def admin_required(f):
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash('Admin access required.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def creator_required(f):
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'creator':
            flash('Creator access required.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def investor_required(f):
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'investor':
            flash('Investor access required.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def create_notification(user_id, title, message, notification_type='info'):
    def _create_notification(conn, user_id, title, message, notification_type):
        conn.execute('''
            INSERT INTO notifications (user_id, title, message, type)
            VALUES (?, ?, ?, ?)
        ''', (user_id, title, message, notification_type))
    
    execute_db_operation(_create_notification, user_id, title, message, notification_type)

def get_wallet_balance(user_id):
    """Get current wallet balance for a user"""
    def _get_balance(conn, user_id):
        balance_row = conn.execute('''
            SELECT COALESCE(SUM(
                CASE 
                    WHEN type IN ('deposit', 'funding_received') THEN amount
                    WHEN type IN ('withdrawal', 'investment') THEN -amount
                    ELSE 0
                END
            ), 0) as balance
            FROM wallet_transactions WHERE user_id = ?
        ''', (user_id,)).fetchone()
        return balance_row['balance'] if balance_row else 0
    
    return execute_db_operation(_get_balance, user_id)

def add_wallet_transaction(user_id, transaction_type, amount, description):
    """Add a wallet transaction"""
    def _add_transaction(conn, user_id, transaction_type, amount, description):
        # Insert the transaction
        conn.execute('''
            INSERT INTO wallet_transactions (user_id, type, amount, description)
            VALUES (?, ?, ?, ?)
        ''', (user_id, transaction_type, amount, description))
        
        # Update the wallet balance
        if transaction_type in ('deposit', 'funding_received'):
            # Add to balance
            conn.execute('''
                UPDATE wallets
                SET balance = balance + ?
                WHERE user_id = ?
            ''', (amount, user_id))
        elif transaction_type in ('withdrawal', 'investment'):
            # Subtract from balance
            conn.execute('''
                UPDATE wallets
                SET balance = balance - ?
                WHERE user_id = ?
            ''', (amount, user_id))
    
    execute_db_operation(_add_transaction, user_id, transaction_type, amount, description)

@app.route('/process_investment_payment', methods=['POST'])
def process_investment_payment():
    if 'user_id' not in session or session.get('role') != 'investor':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        data = request.get_json()
        request_id = data.get('request_id')
        idea_id = data.get('idea_id')
        investment_amount = float(data.get('investment_amount'))
        
        investor_id = session['user_id']
        
        # Get investor's wallet balance
        investor_balance = get_wallet_balance(investor_id)
        
        if investor_balance < investment_amount:
            return jsonify({'success': False, 'message': 'Insufficient wallet balance'})
        
        def _process_investment(conn, request_id, investor_id, idea_id, investment_amount):
            # Get investment request details
            investment_request = conn.execute("""
                SELECT ir.*, i.title, i.funding_needed, i.equity_offered, i.user_id as creator_id 
                FROM investment_requests ir 
                JOIN ideas i ON ir.idea_id = i.id 
                WHERE ir.id = ? AND ir.investor_id = ? AND ir.status = 'approved'
            """, (request_id, investor_id)).fetchone()
            
            if not investment_request:
                return {'success': False, 'message': 'Investment request not found or not approved'}
            
            creator_id = investment_request['creator_id']
            funding_needed = investment_request['funding_needed']
            equity_offered = investment_request['equity_offered']
            
            # Calculate equity percentage for this investment
            equity_percentage = (investment_amount / funding_needed) * equity_offered
            
            # Deduct from investor's wallet
            conn.execute("""
                INSERT INTO wallet_transactions (user_id, type, amount, description)
                VALUES (?, 'investment', ?, ?)
            """, (investor_id, investment_amount, f"Investment in {investment_request['title']}"))
            
            # Update investor's wallet balance
            conn.execute("""
                UPDATE wallets
                SET balance = balance - ?
                WHERE user_id = ?
            """, (investment_amount, investor_id))
            
            # Credit to creator's wallet
            conn.execute("""
                INSERT INTO wallet_transactions (user_id, type, amount, description)
                VALUES (?, 'funding_received', ?, ?)
            """, (creator_id, investment_amount, f"Investment received from investor for {investment_request['title']}"))
            
            # Update creator's wallet balance
            conn.execute("""
                UPDATE wallets
                SET balance = balance + ?
                WHERE user_id = ?
            """, (investment_amount, creator_id))
            
            # Update investment request status to 'completed'
            conn.execute("""
                UPDATE investment_requests 
                SET status = 'completed', updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (request_id,))
            
            # Record the investment with equity percentage
            conn.execute("""
                INSERT INTO investments (investor_id, creator_id, idea_id, amount, equity_percentage, created_at)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (investor_id, creator_id, idea_id, investment_amount, equity_percentage))
            
            # Update idea's funded amount
            conn.execute("""
                UPDATE ideas 
                SET funded_amount = COALESCE(funded_amount, 0) + ?
                WHERE id = ?
            """, (investment_amount, idea_id))
            
            # Add notifications
            conn.execute("""
                INSERT INTO notifications (user_id, type, title, message)
                VALUES (?, 'success', 'Investment Completed', ?)
            """, (investor_id, f"Successfully invested BDT {investment_amount:,.0f} in {investment_request['title']}"))
            
            conn.execute("""
                INSERT INTO notifications (user_id, type, title, message)
                VALUES (?, 'success', 'Investment Received', ?)
            """, (creator_id, f"Received BDT {investment_amount:,.0f} investment for {investment_request['title']}"))
            
            return {'success': True, 'message': 'Investment completed successfully'}
        
        result = execute_db_operation(_process_investment, request_id, investor_id, idea_id, investment_amount)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error processing payment: {str(e)}'})

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about_us')
def about_us():
    return render_template('about_us.html')

@app.route('/contact_us')
def contact_us():
    return render_template('contact_us.html')

@app.route('/terms_of_service')
def terms_of_service():
    return render_template('terms_of_service.html')

@app.route('/privacy_policy')
def privacy_policy():
    return render_template('privacy_policy.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = request.form['role']
        
        # Validation
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return render_template('register.html')
        
        if len(password) < 8:
            flash('Password must be at least 8 characters long!', 'danger')
            return render_template('register.html')
        
        def _register_user(conn, username, email, password_hash, role):
            # Check if user already exists
            existing_user = conn.execute(
                'SELECT id FROM users WHERE username = ? OR email = ?',
                (username, email)
            ).fetchone()
            
            if existing_user:
                return False
            
            # Create new user
            cursor = conn.execute('''
                INSERT INTO users (username, email, password_hash, role)
                VALUES (?, ?, ?, ?)
            ''', (username, email, password_hash, role))
            
            # Create wallet for the new user
            user_id = cursor.lastrowid
            conn.execute('''
                INSERT INTO wallets (user_id, balance)
                VALUES (?, 0)
            ''', (user_id,))
            
            return True
        
        try:
            password_hash = generate_password_hash(password)
            success = execute_db_operation(_register_user, username, email, password_hash, role)
            
            if success:
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Username or email already exists!', 'danger')
                return render_template('register.html')
        except Exception as e:
            flash('Registration failed. Please try again.', 'danger')
            return render_template('register.html')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        def _login_user(conn, email):
            return conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
        user = execute_db_operation(_login_user, email)
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['verified'] = user['verified']
            
            flash(f'Welcome back, {user["username"]}!', 'success')
            
            # Redirect based on role
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user['role'] == 'creator':
                return redirect(url_for('creator_dashboard'))
            elif user['role'] == 'investor':
                return redirect(url_for('investor_dashboard'))
        else:
            flash('Invalid email or password!', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# Profile routes
@app.route('/profile')
@login_required
def profile():
    def _get_profile_data(conn, user_id, role):
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        
        stats = {}
        if role == 'creator':
            ideas_count = conn.execute('SELECT COUNT(*) as count FROM ideas WHERE user_id = ?', (user_id,)).fetchone()
            investments_count = conn.execute('''
                SELECT COUNT(*) as count FROM investment_requests 
                WHERE creator_id = ? AND status = 'approved'
            ''', (user_id,)).fetchone()
            
            total_funding = conn.execute('''
                SELECT COALESCE(SUM(ir.investment_amount), 0) as total
                FROM investment_requests ir
                WHERE ir.creator_id = ? AND ir.status = 'approved'
            ''', (user_id,)).fetchone()
            
            stats = {
                'total_ideas': ideas_count['count'] if ideas_count else 0,
                'total_investments': investments_count['count'] if investments_count else 0,
                'total_funding': total_funding['total'] if total_funding else 0
            }
        else:  # investor
            active_investments = conn.execute('''
                SELECT COUNT(*) as count FROM investment_requests 
                WHERE investor_id = ? AND status = 'approved'
            ''', (user_id,)).fetchone()
            
            total_invested = conn.execute('''
                SELECT COALESCE(SUM(investment_amount), 0) as total
                FROM investment_requests
                WHERE investor_id = ? AND status = 'approved'
            ''', (user_id,)).fetchone()
            
            stats = {
                'active_investments': active_investments['count'] if active_investments else 0,
                'success_rate': 85,  # Mock data
                'total_invested': total_invested['total'] if total_invested else 0
            }
        
        return user, stats
    
    user, stats = execute_db_operation(_get_profile_data, session['user_id'], session['role'])
    return render_template('profile.html', user=user, stats=stats)

# Creator routes
@app.route('/creator_dashboard')
@creator_required
def creator_dashboard():
    def _get_creator_dashboard_data(conn, user_id):
        creator_ideas = conn.execute('''
            SELECT * FROM ideas WHERE user_id = ? ORDER BY created_at DESC
        ''', (user_id,)).fetchall()
        
        creator = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        
        return creator_ideas, creator
    
    creator_ideas, creator = execute_db_operation(_get_creator_dashboard_data, session['user_id'])
    
    # Convert to list of dicts and calculate funding progress for each idea
    ideas_list = []
    for idea in creator_ideas:
        idea_dict = dict(idea)
        idea_dict['funding_progress'] = ((idea_dict['funded_amount'] or 0) / idea_dict['funding_needed'] * 100) if idea_dict['funding_needed'] > 0 else 0
        ideas_list.append(idea_dict)

    return render_template('creator_dashboard.html',
                         creator_ideas=ideas_list,
                         creator_name=creator['full_name'],
                         username=session['username'],
                         verified=session.get('verified', 0))

@app.route('/upload_idea', methods=['GET', 'POST'])
@creator_required
def upload_idea():
    # Check if user is verified
    if session.get('verified') != 1:
        flash('You must be verified to upload ideas. Please complete your verification first.', 'warning')
        return redirect(url_for('verify_creator'))
    
    return render_template('submit_idea.html', 
                         username=session['username'],
                         verified=session.get('verified', 0))

@app.route('/submit_idea', methods=['POST'])
@creator_required
def submit_idea():
    if session.get('verified') != 1:
        flash('You must be verified to submit ideas.', 'danger')
        return redirect(url_for('verify_creator'))
    
    try:
        # Get form data
        title = request.form['title']
        category = request.form['category']
        tags = request.form['tags']
        summary = request.form['summary']
        problem_statement = request.form.get('problem_statement', '')
        solution = request.form.get('solution', '')
        founders = ','.join(request.form.getlist('founders[]'))
        team_members = ','.join(request.form.getlist('team_members[]'))
        contact_email = request.form['contact_email']
        funding_needed = float(request.form['funding_needed'])
        stage = request.form['stage']
        equity_offered = float(request.form['equity_offered'])
        
        # Handle file uploads
        business_plan = None
        product_image = None
        patent = None
        other_files = []
        
        if 'business_plan' in request.files:
            file = request.files['business_plan']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                business_plan = filename
        
        if 'product_image' in request.files:
            file = request.files['product_image']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                product_image = filename
        
        if 'patent' in request.files:
            file = request.files['patent']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                patent = filename
        
        for file in request.files.getlist('other_files[]'):
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                other_files.append(filename)
        
        # Save to database
        def _submit_idea(conn, user_id, username, title, category, tags, summary,
                        problem_statement, solution, founders, team_members,
                        contact_email, funding_needed, stage, equity_offered,
                        business_plan, product_image, patent, other_files):
            conn.execute('''
                INSERT INTO ideas (
                    user_id, username, title, category, tags, summary, 
                    problem_statement, solution, founders, team_members,
                    contact_email, funding_needed, stage, equity_offered,
                    business_plan, product_image, patent, other_files
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                user_id, username, title, category, tags, summary,
                problem_statement, solution, founders, team_members,
                contact_email, funding_needed, stage, equity_offered,
                business_plan, product_image, patent, ','.join(other_files)
            ))
        
        execute_db_operation(_submit_idea, session['user_id'], session['username'], title, category, tags, summary,
                           problem_statement, solution, founders, team_members,
                           contact_email, funding_needed, stage, equity_offered,
                           business_plan, product_image, patent, other_files)
        
        flash('Your idea has been submitted successfully!', 'success')
        return redirect(url_for('creator_dashboard'))
        
    except Exception as e:
        flash(f'Error submitting idea: {str(e)}', 'danger')
        return redirect(url_for('upload_idea'))

@app.route('/creator/idea/<int:idea_id>')
@creator_required
def creator_idea_details(idea_id):
    def _get_idea_details(conn, idea_id, user_id):
        idea = conn.execute('''
            SELECT * FROM ideas WHERE id = ? AND user_id = ?
        ''', (idea_id, user_id)).fetchone()
        
        if not idea:
            return None, None, None, None
        
        # Get investment details for this idea
        investments = conn.execute("""
            SELECT i.amount, i.equity_percentage, i.created_at,
                   u.username, u.full_name
            FROM investments i
            JOIN users u ON i.investor_id = u.id
            WHERE i.idea_id = ?
            ORDER BY i.created_at DESC
        """, (idea_id,)).fetchall()
        
        # Calculate totals
        total_raised = sum(inv['amount'] for inv in investments) if investments else 0
        total_equity_allocated = sum(inv['equity_percentage'] for inv in investments) if investments else 0
        
        return idea, investments, total_raised, total_equity_allocated
    
    idea, investments, total_raised, total_equity_allocated = execute_db_operation(_get_idea_details, idea_id, session['user_id'])
    
    if not idea:
        flash('Idea not found.', 'danger')
        return redirect(url_for('creator_dashboard'))
    
    return render_template('creator_idea_details.html', 
                         idea=idea, 
                         username=session['username'],
                         investments=investments,
                         total_raised=total_raised,
                         total_equity_allocated=total_equity_allocated)

@app.route('/creator/idea/<int:idea_id>/delete', methods=['POST'])
@creator_required
def delete_creator_idea(idea_id):
    def _delete_idea(conn, idea_id, user_id):
        # Check if idea belongs to current user
        idea = conn.execute('''
            SELECT * FROM ideas WHERE id = ? AND user_id = ?
        ''', (idea_id, user_id)).fetchone()
        
        if not idea:
            return False
        
        # Delete the idea
        conn.execute('DELETE FROM ideas WHERE id = ?', (idea_id,))
        return True
    
    success = execute_db_operation(_delete_idea, idea_id, session['user_id'])
    
    if success:
        flash('Idea deleted successfully.', 'success')
    else:
        flash('Idea not found.', 'danger')
    
    return redirect(url_for('creator_dashboard'))

@app.route('/creator/investment_requests')
@creator_required
def creator_investment_requests():
    def _get_investment_requests(conn, user_id):
        return conn.execute('''
            SELECT ir.*, i.title, i.summary, u.username as investor_name, u.email as investor_email
            FROM investment_requests ir
            JOIN ideas i ON ir.idea_id = i.id
            JOIN users u ON ir.investor_id = u.id
            WHERE ir.creator_id = ? AND ir.status = 'pending'
            ORDER BY ir.created_at DESC
        ''', (user_id,)).fetchall()
    
    pending_requests = execute_db_operation(_get_investment_requests, session['user_id'])
    
    return render_template('creator_investment_requests.html', 
                         pending_requests=pending_requests,
                         username=session['username'],
                         verified=session.get('verified', 0))


@app.route('/creator/investment_request/<int:request_id>/<action>')
@creator_required
def handle_investment_request(request_id, action):
    if action not in ['approve', 'decline']:
        flash('Invalid action.', 'danger')
        return redirect(url_for('creator_investment_requests'))
    
    def _handle_request(conn, request_id, user_id, action):
        # Get the request
        investment_request = conn.execute('''
            SELECT ir.*, i.title, u.username as investor_name
            FROM investment_requests ir
            JOIN ideas i ON ir.idea_id = i.id
            JOIN users u ON ir.investor_id = u.id
            WHERE ir.id = ? AND ir.creator_id = ?
        ''', (request_id, user_id)).fetchone()
        
        if not investment_request:
            return None
        
        # Update request status
        new_status = 'approved' if action == 'approve' else 'declined'
        conn.execute('''
            UPDATE investment_requests 
            SET status = ?, updated_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        ''', (new_status, request_id))
        
        # If approved, do not add funding to creator's wallet immediately
        # The transfer will happen when investor confirms payment
        if action == 'approve':
            pass  # No immediate funding transfer
        
        return investment_request
    
    investment_request = execute_db_operation(_handle_request, request_id, session['user_id'], action)
    
    if investment_request:
        # Create notification for investor
        notification_title = f"Investment Request {action.title()}"
        notification_message = f"Your investment request for '{investment_request['title']}' has been {action}."
        create_notification(investment_request['investor_id'], notification_title, notification_message, 
                          'success' if action == 'approve' else 'warning')
        
        flash(f'Investment request {action} successfully.', 'success')
    else:
        flash('Investment request not found.', 'danger')
    
    return redirect(url_for('creator_investment_requests'))

@app.route('/creator/wallet')
@creator_required
def creator_wallet():
    def _get_wallet_data(conn, user_id):
        # Get wallet transactions
        transactions = conn.execute('''
            SELECT * FROM wallet_transactions 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT 10
        ''', (user_id,)).fetchall()
        
        return transactions
    
    transactions = execute_db_operation(_get_wallet_data, session['user_id'])
    balance = get_wallet_balance(session['user_id'])
    
    return render_template('creator_wallet.html', 
                         transactions=transactions,
                         balance=balance,
                         username=session['username'],
                         verified=session.get('verified', 0))

@app.route('/creator/add_funds', methods=['GET', 'POST'])
@creator_required
def creator_add_funds():
    if request.method == 'GET':
        amount = request.args.get('amount', 1000)
        return render_template('payment_gateway.html', 
                             step='method', 
                             amount=int(amount))
    
    current_step = request.form.get('current_step')
    
    if current_step == 'method':
        payment_method = request.form.get('payment_method')
        amount = int(request.form.get('amount'))
        
        if payment_method == 'bkash':
            return render_template('payment_gateway.html', 
                                 step='number', 
                                 payment_method=payment_method,
                                 amount=amount)
        elif payment_method == 'bank':
            return render_template('payment_gateway.html', 
                                 step='bank_details', 
                                 payment_method=payment_method,
                                 amount=amount)
    
    elif current_step == 'number':
        bkash_number = request.form.get('bkash_number')
        amount = int(request.form.get('amount'))
        
        return render_template('payment_gateway.html', 
                             step='otp', 
                             payment_method='bkash',
                             bkash_number=bkash_number,
                             amount=amount)
    
    elif current_step == 'bank_details':
        bank_details = {
            'holder_name': request.form.get('holder_name'),
            'bank_name': request.form.get('bank_name'),
            'account_number': request.form.get('account_number'),
            'branch_name': request.form.get('branch_name')
        }
        amount = int(request.form.get('amount'))
        
        return render_template('payment_gateway.html', 
                             step='pin', 
                             payment_method='bank',
                             bank_details=bank_details,
                             amount=amount)
    
    elif current_step == 'otp':
        otp = request.form.get('otp')
        bkash_number = request.form.get('bkash_number')
        amount = int(request.form.get('amount'))
        
        # Verify OTP (mock verification)
        if otp == '456721':
            return render_template('payment_gateway.html', 
                                 step='pin', 
                                 payment_method='bkash',
                                 bkash_number=bkash_number,
                                 amount=amount)
        else:
            flash('Invalid OTP. Please try again.', 'danger')
            return render_template('payment_gateway.html', 
                                 step='otp', 
                                 payment_method='bkash',
                                 bkash_number=bkash_number,
                                 amount=amount)
    
    elif current_step == 'pin':
        pin = request.form.get('pin')
        payment_method = request.form.get('payment_method')
        amount = int(request.form.get('amount'))
        
        # Verify PIN (mock verification)
        pin_valid = (payment_method == 'bank' and pin == '1234') or (payment_method == 'bkash')
        
        if pin_valid:
            add_wallet_transaction(session['user_id'], 'deposit', amount, f'Funds added via {payment_method}')
            flash(f'BDT {amount:,.0f} has been successfully added to your wallet!', 'success')
            return redirect(url_for('creator_wallet'))
        else:
            flash('Invalid PIN. Please try again.', 'danger')
            return render_template('payment_gateway.html', 
                                 step='pin', 
                                 payment_method=payment_method,
                                 amount=amount)
    
    return redirect(url_for('creator_wallet'))

@app.route('/creator/withdraw_funds', methods=['GET', 'POST'])
@creator_required
def creator_withdraw_funds():
    if request.method == 'POST':
        amount = float(request.form['amount'])
        payment_method = request.form.get('payment_method')
        pin = request.form.get('pin')

        current_balance = get_wallet_balance(session['user_id'])
        
        if amount > current_balance:
            flash('Insufficient balance for this withdrawal.', 'danger')
            return redirect(url_for('creator_withdraw_funds'))

        # Enforce bKash PIN
        if payment_method == 'bkash' and pin != '1234':
            flash('Invalid bKash PIN. Withdrawal failed.', 'danger')
            return redirect(url_for('creator_withdraw_funds'))
        
        # Record withdrawal
        add_wallet_transaction(session['user_id'], 'withdrawal', amount, f"Funds withdrawn via {payment_method}")
        
        flash('Withdrawal request submitted successfully!', 'success')
        return redirect(url_for('creator_wallet'))
        
    return render_template('creator_withdraw_funds.html', 
                         username=session['username'], 
                         verified=session.get('verified', 0),
                         balance=get_wallet_balance(session['user_id']))

@app.route('/creator/portfolio')
@creator_required
def creator_portfolio():
    def _get_portfolio_data(conn, user_id):
        # Get creator's ideas with additional stats
        ideas = conn.execute('''
            SELECT * FROM ideas WHERE user_id = ? ORDER BY created_at DESC
        ''', (user_id,)).fetchall()
        
        # Get portfolio statistics
        portfolio_stats = {
            'total_ideas': len(ideas),
            'total_views': 0,  # Mock data
            'investment_requests': conn.execute('''
                SELECT COUNT(*) as count FROM investment_requests 
                WHERE creator_id = ?
            ''', (user_id,)).fetchone()['count'],
            'total_funding': conn.execute('''
                SELECT COALESCE(SUM(investment_amount), 0) as total
                FROM investment_requests
                WHERE creator_id = ? AND status = 'approved'
            ''', (user_id,)).fetchone()['total']
        }
        
        return ideas, portfolio_stats
    
    ideas, portfolio_stats = execute_db_operation(_get_portfolio_data, session['user_id'])
    
    return render_template('creator_portfolio.html', 
                         ideas=ideas,
                         portfolio_stats=portfolio_stats,
                         username=session['username'],
                         verified=session.get('verified', 0))

# Investor routes
@app.route('/investor_dashboard')
@investor_required
def investor_dashboard():
    def _get_investor_dashboard_data(conn, user_id):
        # Get all ideas for investors to browse
        ideas = conn.execute('''
            SELECT i.*, u.full_name
            FROM ideas i
            JOIN users u ON i.user_id = u.id
            WHERE u.verified = 1
            ORDER BY i.created_at DESC
        ''').fetchall()
        
        # Convert to list of dicts and calculate funding progress for each idea
        ideas_list = []
        for idea in ideas:
            idea_dict = dict(idea)
            idea_dict['funding_progress'] = ((idea_dict['funded_amount'] or 0) / idea_dict['funding_needed'] * 100) if idea_dict['funding_needed'] > 0 else 0
            ideas_list.append(idea_dict)
        
        # Get categories and stages for filtering
        categories = conn.execute('SELECT DISTINCT category FROM ideas').fetchall()
        stages = conn.execute('SELECT DISTINCT stage FROM ideas WHERE stage IS NOT NULL').fetchall()
        
        # Count pending investment requests
        pending_count = conn.execute('''
            SELECT COUNT(*) as count 
            FROM investment_requests 
            WHERE investor_id = ? AND status = 'pending'
        ''', (user_id,)).fetchone()['count']
        
        # Calculate portfolio metrics
        portfolio_stats = conn.execute("""
            SELECT
                COUNT(*) as active_investments,
                COALESCE(SUM(amount), 0) as total_invested,
                COALESCE(AVG(CASE WHEN amount > 0 THEN 1.0 ELSE 0.0 END) * 100, 0) as success_rate
            FROM investments
            WHERE investor_id = ?
        """, (user_id,)).fetchone()
        
        # Calculate total portfolio value (for demo, using invested amount * 1.2 as growth)
        total_portfolio_value = (portfolio_stats['total_invested'] or 0) * 1.2
        
        return ideas_list, categories, stages, pending_count, {
            'total_portfolio_value': total_portfolio_value,
            'active_investments': portfolio_stats['active_investments'] or 0,
            'total_invested': portfolio_stats['total_invested'] or 0,
            'success_rate': portfolio_stats['success_rate'] or 89.2
        }
    
    ideas, categories, stages, pending_count, portfolio_stats = execute_db_operation(_get_investor_dashboard_data, session['user_id'])
    
    return render_template('investor_dashboard.html', 
                         ideas=ideas,
                         categories=categories,
                         stages=stages,
                         pending_count=pending_count,
                         portfolio_stats=portfolio_stats,
                         username=session['username'],
                         verified=session.get('verified', 0))
@app.route('/idea/<int:idea_id>')
@investor_required
def idea_details(idea_id):
    if session.get('verified') != 1:
        flash('You must be verified to view idea details.', 'warning')
        return redirect(url_for('verify_investor'))

    def _get_idea_details(conn, idea_id):
        return conn.execute('''
            SELECT i.*, u.full_name, u.email as creator_email
            FROM ideas i
            JOIN users u ON i.user_id = u.id
            WHERE i.id = ?
        ''', (idea_id,)).fetchone()

    idea = execute_db_operation(_get_idea_details, idea_id)
    if not idea:
        flash('Idea not found.', 'danger')
        return redirect(url_for('investor_dashboard'))

    # ✅ Use same method as wallet page to get balance
    wallet_balance = get_wallet_balance(session['user_id'])

    return render_template(
        'idea_details.html',
        idea=idea,
        wallet_balance=wallet_balance,   # now matches wallet page
        username=session['username'],
        verified=session.get('verified', 0)
    )





@app.route('/submit_investment_request/<int:idea_id>', methods=['POST'])
@investor_required
def submit_investment_request(idea_id):
    if session.get('verified') != 1:
        flash('You must be verified to submit investment requests.', 'danger')
        return redirect(url_for('verify_investor'))
    
    try:
        investment_amount = float(request.form['investment_amount'])
    except (ValueError, KeyError):
        flash('Invalid investment amount.', 'danger')
        return redirect(url_for('idea_details', idea_id=idea_id))

    message = request.form.get('message', '')
    investor_id = session['user_id']

    def _submit_investment_request(conn, investor_id, idea_id, investment_amount, message):
        # --- Fetch wallet balance ---
        wallet = conn.execute(
            'SELECT balance FROM wallets WHERE user_id = ?',
            (investor_id,)
        ).fetchone()

        if not wallet:
            return 'no_wallet'
        
        wallet_balance = wallet['balance']

        # --- Validate balance ---
        if investment_amount > wallet_balance:
            return 'insufficient_balance'
        if investment_amount < 1000:
            return 'too_small'

        # --- Fetch idea info ---
        idea = conn.execute('''
            SELECT i.*, u.id as creator_id
            FROM ideas i
            JOIN users u ON i.user_id = u.id
            WHERE i.id = ?
        ''', (idea_id,)).fetchone()
        
        if not idea:
            return None
        
        if investment_amount > idea['funding_needed']:
            return 'exceeds_funding'

        # --- Prevent duplicate pending requests ---
        existing_request = conn.execute('''
            SELECT id FROM investment_requests 
            WHERE investor_id = ? AND idea_id = ? AND status = 'pending'
        ''', (investor_id, idea_id)).fetchone()
        
        if existing_request:
            return 'exists'
        
        # --- Create investment request ---
        conn.execute('''
            INSERT INTO investment_requests (investor_id, creator_id, idea_id, investment_amount, message)
            VALUES (?, ?, ?, ?, ?)
        ''', (investor_id, idea['creator_id'], idea_id, investment_amount, message))
        
        # --- Deduct balance immediately ---
        conn.execute('''
            UPDATE wallets SET balance = balance - ? WHERE user_id = ?
        ''', (investment_amount, investor_id))

        return idea
    
    result = execute_db_operation(_submit_investment_request, investor_id, idea_id, investment_amount, message)
    
    # --- Handle results ---
    if result is None:
        flash('Idea not found.', 'danger')
        return redirect(url_for('investor_dashboard'))
    elif result == 'exists':
        flash('You already have a pending request for this idea.', 'warning')
        return redirect(url_for('idea_details', idea_id=idea_id))
    elif result == 'insufficient_balance':
        flash('You do not have enough balance in your wallet.', 'danger')
        return redirect(url_for('idea_details', idea_id=idea_id))

    elif result == 'too_small':
        flash('Minimum investment amount is BDT 1,000.', 'danger')
        return redirect(url_for('idea_details', idea_id=idea_id))
    elif result == 'exceeds_funding':
        flash('Investment exceeds funding requirement.', 'danger')
        return redirect(url_for('idea_details', idea_id=idea_id))
    elif result == 'no_wallet':
        flash('No wallet found. Please set up your wallet first.', 'danger')
        return redirect(url_for('investor_wallet'))
    else:
        # --- Notify creator ---
        create_notification(
            result['creator_id'],
            'New Investment Request',
            f'You have received a new investment request for "{result["title"]}" worth BDT {investment_amount:,.0f}.',
            'investment_request'
        )
        
        flash('Investment request submitted successfully!', 'success')
        return redirect(url_for('investor_pending_investments'))

@app.route('/investor/pending_investments')
@investor_required
def investor_pending_investments():
    def _get_pending_investments(conn, user_id):
        # Get pending requests
        pending_requests = conn.execute('''
            SELECT ir.*, i.title, i.summary, i.product_image, u.username as creator_name
            FROM investment_requests ir
            JOIN ideas i ON ir.idea_id = i.id
            JOIN users u ON ir.creator_id = u.id
            WHERE ir.investor_id = ? AND ir.status = 'pending'
            ORDER BY ir.created_at DESC
        ''', (user_id,)).fetchall()
        
        # Get approved requests
        approved_requests = conn.execute('''
            SELECT ir.*, i.title, i.summary, i.product_image, u.username as creator_name
            FROM investment_requests ir
            JOIN ideas i ON ir.idea_id = i.id
            JOIN users u ON ir.creator_id = u.id
            WHERE ir.investor_id = ? AND ir.status = 'approved'
            ORDER BY ir.updated_at DESC
        ''', (user_id,)).fetchall()
        
        return pending_requests, approved_requests
    
    pending_requests, approved_requests = execute_db_operation(_get_pending_investments, session['user_id'])
    
    return render_template('investor_pending_investments.html',
                         pending_requests=pending_requests,
                         approved_requests=approved_requests)

@app.route('/investment_details/<int:request_id>')
@investor_required
def investment_details(request_id):
    def _get_investment_details(conn, request_id, user_id):
        return conn.execute('''
            SELECT ir.*, i.title, i.summary, i.product_image, i.funding_needed, i.equity_offered
            FROM investment_requests ir
            JOIN ideas i ON ir.idea_id = i.id
            WHERE ir.id = ? AND ir.investor_id = ?
        ''', (request_id, user_id)).fetchone()
    
    request_data = execute_db_operation(_get_investment_details, request_id, session['user_id'])
    
    if not request_data:
        flash('Investment request not found.', 'danger')
        return redirect(url_for('investor_pending_investments'))
    
    # Get wallet balance
    wallet_balance = get_wallet_balance(session['user_id'])
    
    return render_template('investment_details.html',
                         idea=request_data,
                         investment_amount=request_data['investment_amount'],
                         request_id=request_id,
                         wallet_balance=wallet_balance)

# Investor wallet routes
@app.route('/investor_wallet')
@investor_required
def investor_wallet():
    def _get_investor_wallet_data(conn, user_id):
        transactions = conn.execute('''
            SELECT * FROM wallet_transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 10
        ''', (user_id,)).fetchall()
        
        return transactions
    
    transactions = execute_db_operation(_get_investor_wallet_data, session['user_id'])
    balance = get_wallet_balance(session['user_id'])
    
    return render_template('investor_wallet.html', 
                         balance=balance, 
                         transactions=transactions, 
                         username=session['username'], 
                         verified=session.get('verified', 0))

@app.route('/investor/add_funds', methods=['GET', 'POST'])
@investor_required
def investor_add_funds():
    if request.method == 'GET':
        amount = request.args.get('amount', 1000)
        return render_template('payment_gateway.html', 
                             step='method', 
                             amount=int(amount))
    
    current_step = request.form.get('current_step')
    
    if current_step == 'method':
        payment_method = request.form.get('payment_method')
        amount = int(request.form.get('amount'))
        
        if payment_method == 'bkash':
            return render_template('payment_gateway.html', 
                                 step='number', 
                                 payment_method=payment_method,
                                 amount=amount)
        elif payment_method == 'bank':
            return render_template('payment_gateway.html', 
                                 step='bank_details', 
                                 payment_method=payment_method,
                                 amount=amount)
    
    elif current_step == 'number':
        bkash_number = request.form.get('bkash_number')
        amount = int(request.form.get('amount'))
        
        return render_template('payment_gateway.html', 
                             step='otp', 
                             payment_method='bkash',
                             bkash_number=bkash_number,
                             amount=amount)
    
    elif current_step == 'bank_details':
        bank_details = {
            'holder_name': request.form.get('holder_name'),
            'bank_name': request.form.get('bank_name'),
            'account_number': request.form.get('account_number'),
            'branch_name': request.form.get('branch_name')
        }
        amount = int(request.form.get('amount'))
        
        return render_template('payment_gateway.html', 
                             step='pin', 
                             payment_method='bank',
                             bank_details=bank_details,
                             amount=amount)
    
    elif current_step == 'otp':
        otp = request.form.get('otp')
        bkash_number = request.form.get('bkash_number')
        amount = int(request.form.get('amount'))
        
        # Verify OTP (mock verification)
        if otp == '456721':
            return render_template('payment_gateway.html', 
                                 step='pin', 
                                 payment_method='bkash',
                                 bkash_number=bkash_number,
                                 amount=amount)
        else:
            flash('Invalid OTP. Please try again.', 'danger')
            return render_template('payment_gateway.html', 
                                 step='otp', 
                                 payment_method='bkash',
                                 bkash_number=bkash_number,
                                 amount=amount)
    
    elif current_step == 'pin':
        pin = request.form.get('pin')
        payment_method = request.form.get('payment_method')
        amount = int(request.form.get('amount'))
        
        # Verify PIN (mock verification)
        pin_valid = (payment_method == 'bank' and pin == '1234') or (payment_method == 'bkash')
        
        if pin_valid:
            add_wallet_transaction(session['user_id'], 'deposit', amount, f'Funds added via {payment_method}')
            flash(f'BDT {amount:,.0f} has been successfully added to your wallet!', 'success')
            return redirect(url_for('investor_wallet'))
        else:
            flash('Invalid PIN. Please try again.', 'danger')
            return render_template('payment_gateway.html', 
                                 step='pin', 
                                 payment_method=payment_method,
                                 amount=amount)
    
    return redirect(url_for('investor_wallet'))

@app.route('/investor_withdraw_funds', methods=['GET', 'POST'])
@investor_required
def investor_withdraw_funds():
    if request.method == 'POST':
        amount = float(request.form['amount'])
        payment_method = request.form.get('payment_method')
        pin = request.form.get('pin')

        current_balance = get_wallet_balance(session['user_id'])
        
        if amount > current_balance:
            flash('Insufficient balance for this withdrawal.', 'danger')
            return redirect(url_for('investor_withdraw_funds'))

        # Enforce bKash PIN
        if payment_method == 'bkash' and pin != '1234':
            flash('Invalid bKash PIN. Withdrawal failed.', 'danger')
            return redirect(url_for('investor_withdraw_funds'))
        
        # Record withdrawal
        add_wallet_transaction(session['user_id'], 'withdrawal', amount, f"Funds withdrawn via {payment_method}")
        
        flash('Withdrawal request submitted successfully!', 'success')
        return redirect(url_for('investor_wallet'))
        
    return render_template('withdraw_funds.html', 
                         username=session['username'], 
                         verified=session.get('verified', 0),
                         balance=get_wallet_balance(session['user_id']))

# Verification routes
@app.route('/verify_creator', methods=['GET', 'POST'])
@creator_required
def verify_creator():
    if request.method == 'POST':
        full_name = request.form['full_name']
        phone = request.form['phone']
        gov_id = request.form['gov_id']
        linkedin_id = request.form['linkedin_id']
        present_address = request.form['present_address']
        
        def _update_creator_verification(conn, user_id, full_name, phone, gov_id, linkedin_id, present_address):
            conn.execute('''
                UPDATE users SET 
                    full_name = ?, phone = ?, gov_id = ?, 
                    linkedin_id = ?, present_address = ?, verified = 0
                WHERE id = ?
            ''', (full_name, phone, gov_id, linkedin_id, present_address, user_id))
        
        execute_db_operation(_update_creator_verification, session['user_id'], full_name, phone, gov_id, linkedin_id, present_address)
        
        session['verified'] = 0
        flash('Verification request submitted! Please wait for admin approval.', 'info')
        return redirect(url_for('creator_dashboard'))
    
    def _get_user_email(conn, user_id):
        return conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    
    user = execute_db_operation(_get_user_email, session['user_id'])
    
    return render_template('verify_creator.html', email=user['email'])

@app.route('/verify_investor', methods=['GET', 'POST'])
@investor_required
def verify_investor():
    if request.method == 'POST':
        full_name = request.form['full_name']
        phone = request.form['phone']
        gov_id = request.form['gov_id']
        linkedin_id = request.form['linkedin_id']
        present_address = request.form['present_address']
        
        # Handle file uploads (mock - in real app, save files)
        mandatory_doc = request.files.get('mandatory_doc')
        optional_doc = request.files.get('optional_doc')
        
        def _update_investor_verification(conn, user_id, full_name, phone, gov_id, linkedin_id, present_address):
            conn.execute('''
                UPDATE users SET 
                    full_name = ?, phone = ?, gov_id = ?, 
                    linkedin_id = ?, present_address = ?, verified = 0
                WHERE id = ?
            ''', (full_name, phone, gov_id, linkedin_id, present_address, user_id))
        
        execute_db_operation(_update_investor_verification, session['user_id'], full_name, phone, gov_id, linkedin_id, present_address)
        
        session['verified'] = 0
        flash('Verification request submitted! Please wait for admin approval.', 'info')
        return redirect(url_for('investor_dashboard'))
    
    def _get_user_email(conn, user_id):
        return conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    
    user = execute_db_operation(_get_user_email, session['user_id'])
    
    return render_template('verify_investor.html', email=user['email'])

# Notifications route
@app.route('/notifications')
@login_required
def notifications():
    def _get_notifications(conn, user_id):
        notifications = conn.execute('''
            SELECT * FROM notifications 
            WHERE user_id = ? 
            ORDER BY created_at DESC
        ''', (user_id,)).fetchall()
        
        # Mark notifications as read
        conn.execute('UPDATE notifications SET is_read = 1 WHERE user_id = ?', (user_id,))
        
        return notifications
    
    notifications = execute_db_operation(_get_notifications, session['user_id'])
    
    return render_template('notifications.html', 
                         notifications=notifications,
                         role=session.get('role'))

# Admin routes
@app.route('/admin_dashboard')
@admin_required
def admin_dashboard():
    def _get_admin_stats(conn):
        total_users = conn.execute('SELECT COUNT(*) as count FROM users WHERE role != "admin"').fetchone()['count']
        total_ideas = conn.execute('SELECT COUNT(*) as count FROM ideas').fetchone()['count']
        return total_users, total_ideas
    
    total_users, total_ideas = execute_db_operation(_get_admin_stats)
    
    return render_template('admin_dashboard.html', 
                         total_users=total_users,
                         total_ideas=total_ideas,
                         username=session['username'])

@app.route('/user_management')
@admin_required
def user_management():
    def _get_user_management_data(conn):
        all_users = conn.execute('SELECT * FROM users WHERE role != "admin" ORDER BY created_at DESC').fetchall()
        total_creators = conn.execute('SELECT COUNT(*) as count FROM users WHERE role = "creator"').fetchone()['count']
        total_investors = conn.execute('SELECT COUNT(*) as count FROM users WHERE role = "investor"').fetchone()['count']
        return all_users, total_creators, total_investors
    
    all_users, total_creators, total_investors = execute_db_operation(_get_user_management_data)
    
    return render_template('user_management.html', 
                         all_users=all_users,
                         total_creators=total_creators,
                         total_investors=total_investors)

@app.route('/verify_creators')
@admin_required
def verify_creators():
    def _get_unverified_creators(conn):
        return conn.execute('''
            SELECT * FROM users 
            WHERE role = "creator" AND verified = 0
            ORDER BY created_at DESC
        ''').fetchall()
    
    creators = execute_db_operation(_get_unverified_creators)
    return render_template('admin_verify_creator.html', creators=creators)

@app.route('/verify_investors')
@admin_required
def verify_investors():
    def _get_unverified_investors(conn):
        return conn.execute('''
            SELECT * FROM users 
            WHERE role = "investor" AND verified = 0
            ORDER BY created_at DESC
        ''').fetchall()
    
    investors = execute_db_operation(_get_unverified_investors)
    return render_template('admin_verify_investor.html', investors=investors)

@app.route('/approve_creator/<int:user_id>')
@admin_required
def approve_creator(user_id):
    def _approve_creator(conn, user_id):
        conn.execute('UPDATE users SET verified = 1 WHERE id = ?', (user_id,))
    
    execute_db_operation(_approve_creator, user_id)
    create_notification(
        user_id,
        'Verification Approved',
        'Your creator account has been verified! You can now submit ideas.',
        'success'
    )

    flash('Creator approved successfully!', 'success')
    return redirect(url_for('verify_creators'))

@app.route('/decline_creator/<int:user_id>')
@admin_required
def decline_creator(user_id):
    def _decline_creator(conn, user_id):
        conn.execute('UPDATE users SET verified = 2 WHERE id = ?', (user_id,))
    
    execute_db_operation(_decline_creator, user_id)
    create_notification(
        user_id,
        'Verification Declined',
        'Your verification request has been declined. Please contact support for more information.',
        'warning'
    )

    flash('Creator verification declined.', 'warning')
    return redirect(url_for('verify_creators'))

@app.route('/approve_investor/<int:user_id>')
@admin_required
def approve_investor(user_id):
    def _approve_investor(conn, user_id):
        conn.execute('UPDATE users SET verified = 1 WHERE id = ?', (user_id,))
    
    execute_db_operation(_approve_investor, user_id)
    create_notification(
        user_id,
        'Verification Approved',
        'Your investor account has been verified! You can now view and invest in ideas.',
        'success'
    )

    flash('Investor approved successfully!', 'success')
    return redirect(url_for('verify_investors'))

@app.route('/decline_investor/<int:user_id>')
@admin_required
def decline_investor(user_id):
    def _decline_investor(conn, user_id):
        conn.execute('UPDATE users SET verified = 2 WHERE id = ?', (user_id,))
    
    execute_db_operation(_decline_investor, user_id)
    create_notification(
        user_id,
        'Verification Declined',
        'Your verification request has been declined. Please contact support for more information.',
        'warning'
    )

    flash('Investor verification declined.', 'warning')
    return redirect(url_for('verify_investors'))

@app.route('/admin/ideas')
@admin_required
def admin_ideas():
    def _get_admin_ideas(conn):
        return conn.execute('''
            SELECT i.*, u.username, u.email as contact_email
            FROM ideas i
            JOIN users u ON i.user_id = u.id
            ORDER BY i.created_at DESC
        ''').fetchall()
    
    ideas = execute_db_operation(_get_admin_ideas)
    return render_template('admin_ideas.html', ideas=ideas)

@app.route('/remove_idea/<int:idea_id>')
@admin_required
def remove_idea(idea_id):
    def _remove_idea(conn, idea_id):
        conn.execute('DELETE FROM ideas WHERE id = ?', (idea_id,))
    
    execute_db_operation(_remove_idea, idea_id)
    
    flash('Idea removed successfully!', 'success')
    return redirect(url_for('admin_ideas'))

@app.route('/delete_user/<int:user_id>')
@admin_required
def delete_user(user_id):
    def _delete_user(conn, user_id):
        # Delete user's related data first (foreign key constraints)
        conn.execute('DELETE FROM ideas WHERE user_id = ?', (user_id,))
        conn.execute('DELETE FROM investment_requests WHERE investor_id = ? OR creator_id = ?', (user_id, user_id))
        conn.execute('DELETE FROM notifications WHERE user_id = ?', (user_id,))
        conn.execute('DELETE FROM wallet_transactions WHERE user_id = ?', (user_id,))
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    
    execute_db_operation(_delete_user, user_id)
    
    flash('User deleted successfully!', 'success')
    return redirect(url_for('user_management'))

@app.route('/unverify_user/<int:user_id>/<role>')
@admin_required
def unverify_user(user_id, role):
    def _unverify_user(conn, user_id):
        conn.execute('UPDATE users SET verified = 0 WHERE id = ?', (user_id,))
    
    execute_db_operation(_unverify_user, user_id)
    
    flash(f'{role.title()} unverified successfully!', 'success')
    return redirect(url_for('user_management'))

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)