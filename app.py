# app.py
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
import os
import random
import threading
import time
import requests
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or 'chase-rice-fanpage-secret-2023'

# Database initialization
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # Create raffle entries table
    c.execute('''CREATE TABLE IF NOT EXISTS raffle_entries
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  email TEXT NOT NULL,
                  favorite_song TEXT,
                  entry_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

    # Create admin users table
    c.execute('''CREATE TABLE IF NOT EXISTS admin_users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL)''')

    # Create members table
    c.execute('''CREATE TABLE IF NOT EXISTS members
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  email TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL,
                  first_name TEXT,
                  last_name TEXT,
                  phone_number TEXT,
                  sex TEXT,
                  date_of_birth TEXT,
                  message_to_chase TEXT,
                  newsletter_subscription INTEGER DEFAULT 0,
                  registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

    # Add missing columns to existing members table if they don't exist
    try:
        c.execute("ALTER TABLE members ADD COLUMN message_to_chase TEXT")
    except sqlite3.OperationalError:
        pass  # Column already exists

    try:
        c.execute("ALTER TABLE members ADD COLUMN newsletter_subscription INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass  # Column already exists

    # Create winners table
    c.execute('''CREATE TABLE IF NOT EXISTS winners
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  raffle_id INTEGER,
                  win_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY(raffle_id) REFERENCES raffle_entries(id))''')

    # Create tours table
    c.execute('''CREATE TABLE IF NOT EXISTS tours
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  date TEXT NOT NULL,
                  venue TEXT NOT NULL,
                  city TEXT NOT NULL,
                  state_or_country TEXT NOT NULL,
                  ticket_url TEXT,
                  created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

    # Create member counter table
    c.execute('''CREATE TABLE IF NOT EXISTS member_counter
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  current_count INTEGER NOT NULL DEFAULT 1247,
                  last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Insert default member counter if not exists
    c.execute("SELECT COUNT(*) FROM member_counter")
    if c.fetchone()[0] == 0:
        c.execute("INSERT INTO member_counter (current_count) VALUES (1247)")

    # Insert default admin user if not exists
    password_hash = generate_password_hash('admin123')
    try:
        c.execute("INSERT INTO admin_users (username, password_hash) VALUES (?, ?)", 
                 ('admin', password_hash))
    except sqlite3.IntegrityError:
        pass  # Admin user already exists

    conn.commit()
    conn.close()

# Database connection helper
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Helper function to check if user is logged in
def member_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('member_logged_in'):
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('member_login'))
        return f(*args, **kwargs)
    return decorated_function

# Health check endpoint to prevent spinning down
@app.route('/health')
def health_check():
    return jsonify({
        'status': 'healthy', 
        'timestamp': datetime.now().isoformat(),
        'message': 'Chase Rice Fan Page is awake and running'
    })

# Background thread for self-pinging (optional)
def keep_alive():
    """Background thread to self-ping the application"""
    while True:
        try:
            # This will work when running locally
            requests.get('http://localhost:5000/health', timeout=5)
            print(f"Self-ping at {datetime.now()}")
        except requests.exceptions.RequestException:
            try:
                # Fallback for production environments
                base_url = os.environ.get('BASE_URL', 'http://localhost:5000')
                requests.get(f'{base_url}/health', timeout=5)
                print(f"Self-ping at {datetime.now()}")
            except:
                print("Self-ping failed")
        time.sleep(300)  # Ping every 5 minutes (less than 15-minute timeout)

# Routes
@app.route('/')
def index():
    # Fetch upcoming tours for the homepage
    conn = get_db_connection()
    tours = conn.execute('SELECT * FROM tours ORDER BY date ASC LIMIT 3').fetchall()
    
    # Fetch current member counter
    counter_row = conn.execute('SELECT current_count FROM member_counter ORDER BY id DESC LIMIT 1').fetchone()
    member_count = counter_row[0] if counter_row else 1247
    
    conn.close()
    return render_template('index.html', tours=tours, member_count=member_count)

@app.route('/bio')
@member_required
def bio():
    return render_template('bio.html')

@app.route('/music')
@member_required
def music():
    return render_template('music.html')

@app.route('/tour')
@member_required
def tour():
    conn = get_db_connection()
    tours = conn.execute('SELECT * FROM tours ORDER BY date ASC').fetchall()
    conn.close()
    return render_template('tour.html', tours=tours)

@app.route('/raffle', methods=['GET', 'POST'])
@member_required
def raffle():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        favorite_song = request.form.get('favorite_song', '')

        if not name or not email:
            flash('Please fill in all required fields.', 'error')
            return redirect(url_for('raffle'))

        conn = get_db_connection()
        conn.execute('INSERT INTO raffle_entries (name, email, favorite_song) VALUES (?, ?, ?)',
                    (name, email, favorite_song))
        conn.commit()
        conn.close()

        flash('Thanks for entering the raffle! Good luck!', 'success')
        return redirect(url_for('raffle'))

    return render_template('raffle.html')

@app.route('/winners')
@member_required
def winners():
    conn = get_db_connection()
    winners = conn.execute('''SELECT raffle_entries.name, raffle_entries.favorite_song, winners.win_date 
                             FROM winners 
                             JOIN raffle_entries ON winners.raffle_id = raffle_entries.id 
                             ORDER BY winners.win_date DESC''').fetchall()
    conn.close()
    return render_template('winners.html', winners=winners)

# Member authentication routes
@app.route('/register', methods=['GET', 'POST'])
def member_register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        first_name = request.form.get('first_name', '')
        last_name = request.form.get('last_name', '')
        phone_number = request.form.get('phone_number', '')
        sex = request.form.get('sex', '')
        date_of_birth = request.form.get('date_of_birth', '')
        message_to_chase = request.form.get('message_to_chase', '')
        newsletter_subscription = 1 if request.form.get('newsletter_subscription') else 0

        # Validation
        if not username or not email or not password:
            flash('Please fill in all required fields.', 'error')
            return redirect(url_for('member_register'))

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('member_register'))

        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return redirect(url_for('member_register'))

        # Check if user already exists
        conn = get_db_connection()
        existing_user = conn.execute('SELECT * FROM members WHERE username = ? OR email = ?', 
                                   (username, email)).fetchone()

        if existing_user:
            flash('Username or email already exists.', 'error')
            conn.close()
            return redirect(url_for('member_register'))

        # Create new member
        password_hash = generate_password_hash(password)
        conn.execute('''INSERT INTO members (username, email, password_hash, first_name, last_name, phone_number, sex, date_of_birth, message_to_chase, newsletter_subscription) 
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
                    (username, email, password_hash, first_name, last_name, phone_number, sex, date_of_birth, message_to_chase, newsletter_subscription))
        conn.commit()
        conn.close()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('member_login'))

    return render_template('member_register.html')

@app.route('/login', methods=['GET', 'POST'])
def member_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM members WHERE username = ? OR email = ?', 
                          (username, username)).fetchone()
        conn.close()

        if user and check_password_hash(user['password_hash'], password):
            session['member_logged_in'] = True
            session['member_id'] = user['id']
            session['member_username'] = user['username']
            flash(f'Welcome back, {user["first_name"] or user["username"]}!', 'success')
            return redirect(url_for('bio'))  # Redirect to Bio page after login
        else:
            flash('Invalid username/email or password.', 'error')

    return render_template('member_login.html')

@app.route('/logout')
def member_logout():
    session.pop('member_logged_in', None)
    session.pop('member_id', None)
    session.pop('member_username', None)
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('index'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM admin_users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password_hash'], password):
            session['admin_logged_in'] = True
            session['admin_username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid credentials. Please try again.', 'error')

    return render_template('admin_login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    entry_count = conn.execute('SELECT COUNT(*) FROM raffle_entries').fetchone()[0]
    recent_entries = conn.execute('SELECT * FROM raffle_entries ORDER BY entry_date DESC LIMIT 5').fetchall()
    conn.close()

    return render_template('admin_dashboard.html', entry_count=entry_count, recent_entries=recent_entries)

@app.route('/admin/members')
def admin_members():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    members = conn.execute('''SELECT id, username, email, first_name, last_name, phone_number, sex, date_of_birth, registration_date 
                             FROM members ORDER BY registration_date DESC''').fetchall()
    conn.close()

    return render_template('admin_members.html', members=members)

@app.route('/admin/member/<int:member_id>')
def admin_member_detail(member_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    member = conn.execute('SELECT * FROM members WHERE id = ?', (member_id,)).fetchone()
    conn.close()

    if not member:
        flash('Member not found.', 'error')
        return redirect(url_for('admin_members'))

    return render_template('admin_member_detail.html', member=member)

@app.route('/admin/member/delete/<int:member_id>', methods=['POST'])
def admin_delete_member(member_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    member = conn.execute('SELECT * FROM members WHERE id = ?', (member_id,)).fetchone()

    if not member:
        flash('Member not found.', 'error')
        conn.close()
        return redirect(url_for('admin_members'))

    # Delete the member
    conn.execute('DELETE FROM members WHERE id = ?', (member_id,))
    conn.commit()
    conn.close()

    flash(f'Member "{member["username"]}" has been deleted successfully.', 'success')
    return redirect(url_for('admin_members'))

@app.route('/admin/member/add', methods=['GET', 'POST'])
def admin_add_member():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        first_name = request.form.get('first_name', '')
        last_name = request.form.get('last_name', '')
        phone_number = request.form.get('phone_number', '')
        sex = request.form.get('sex', '')
        date_of_birth = request.form.get('date_of_birth', '')
        message_to_chase = request.form.get('message_to_chase', '')
        newsletter_subscription = 1 if request.form.get('newsletter_subscription') else 0

        # Validation
        if not username or not email or not password:
            flash('Please fill in all required fields.', 'error')
            return redirect(url_for('admin_add_member'))

        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return redirect(url_for('admin_add_member'))

        # Check if user already exists
        conn = get_db_connection()
        existing_user = conn.execute('SELECT * FROM members WHERE username = ? OR email = ?', 
                                   (username, email)).fetchone()

        if existing_user:
            flash('Username or email already exists.', 'error')
            conn.close()
            return redirect(url_for('admin_add_member'))

        # Create new member
        password_hash = generate_password_hash(password)
        conn.execute('''INSERT INTO members (username, email, password_hash, first_name, last_name, phone_number, sex, date_of_birth, message_to_chase, newsletter_subscription) 
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
                    (username, email, password_hash, first_name, last_name, phone_number, sex, date_of_birth, message_to_chase, newsletter_subscription))
        conn.commit()
        conn.close()

        flash(f'Member "{username}" has been added successfully.', 'success')
        return redirect(url_for('admin_members'))

    return render_template('admin_add_member.html')

@app.route('/admin/tours')
def admin_tours():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    tours = conn.execute('SELECT * FROM tours ORDER BY date ASC').fetchall()
    conn.close()

    return render_template('admin_tours.html', tours=tours)

@app.route('/admin/tour/add', methods=['GET', 'POST'])
def admin_add_tour():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        date = request.form['date']
        venue = request.form['venue']
        city = request.form['city']
        state_or_country = request.form['state_or_country']
        ticket_url = request.form.get('ticket_url', '')

        # Validation
        if not date or not venue or not city or not state_or_country:
            flash('Please fill in all required fields.', 'error')
            return redirect(url_for('admin_add_tour'))

        # Create new tour
        conn = get_db_connection()
        conn.execute('''INSERT INTO tours (date, venue, city, state_or_country, ticket_url) 
                       VALUES (?, ?, ?, ?, ?)''', 
                    (date, venue, city, state_or_country, ticket_url))
        conn.commit()
        conn.close()

        flash(f'Tour date at {venue} has been added successfully.', 'success')
        return redirect(url_for('admin_tours'))

    return render_template('admin_add_tour.html')

@app.route('/admin/tour/delete/<int:tour_id>', methods=['POST'])
def admin_delete_tour(tour_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    tour = conn.execute('SELECT * FROM tours WHERE id = ?', (tour_id,)).fetchone()

    if not tour:
        flash('Tour not found.', 'error')
        conn.close()
        return redirect(url_for('admin_tours'))

    # Delete the tour
    conn.execute('DELETE FROM tours WHERE id = ?', (tour_id,))
    conn.commit()
    conn.close()

    flash(f'Tour at {tour["venue"]} has been deleted successfully.', 'success')
    return redirect(url_for('admin_tours'))

@app.route('/admin/pick_winner')
def pick_winner():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    conn = get_db_connection()

    # Get all entries
    entries = conn.execute('SELECT * FROM raffle_entries').fetchall()

    if not entries:
        flash('No entries to pick from!', 'error')
        return redirect(url_for('admin_dashboard'))

    # Pick a random winner
    winner = random.choice(entries)

    # Add to winners table
    conn.execute('INSERT INTO winners (raffle_id) VALUES (?)', (winner['id'],))
    conn.commit()

    # Get winner info for display
    winner_info = conn.execute('''SELECT * FROM raffle_entries WHERE id = ?''', 
                              (winner['id'],)).fetchone()
    conn.close()

    return render_template('pick_winner.html', winner=winner_info)

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('admin_login'))

@app.route('/api/increment_counter', methods=['POST'])
def increment_counter():
    """API endpoint to increment the member counter"""
    conn = get_db_connection()
    
    # Get current count
    counter_row = conn.execute('SELECT current_count FROM member_counter ORDER BY id DESC LIMIT 1').fetchone()
    current_count = counter_row[0] if counter_row else 1247
    
    # Increment by 1
    new_count = current_count + 1
    
    # Update in database
    conn.execute('UPDATE member_counter SET current_count = ?, last_updated = CURRENT_TIMESTAMP WHERE id = (SELECT id FROM member_counter ORDER BY id DESC LIMIT 1)', (new_count,))
    conn.commit()
    conn.close()
    
    return {'success': True, 'new_count': new_count}

@app.route('/admin/counter')
def admin_counter():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    counter_row = conn.execute('SELECT current_count, last_updated FROM member_counter ORDER BY id DESC LIMIT 1').fetchone()
    conn.close()
    
    current_count = counter_row[0] if counter_row else 1247
    last_updated = counter_row[1] if counter_row else 'Never'

    return render_template('admin_counter.html', current_count=current_count, last_updated=last_updated)

@app.route('/admin/counter/update', methods=['POST'])
def admin_update_counter():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    new_count = request.form.get('new_count')
    
    # Validation
    if not new_count or not new_count.isdigit():
        flash('Please enter a valid number.', 'error')
        return redirect(url_for('admin_counter'))
    
    new_count = int(new_count)
    if new_count < 0:
        flash('Counter value cannot be negative.', 'error')
        return redirect(url_for('admin_counter'))

    # Update counter in database
    conn = get_db_connection()
    conn.execute('UPDATE member_counter SET current_count = ?, last_updated = CURRENT_TIMESTAMP WHERE id = (SELECT id FROM member_counter ORDER BY id DESC LIMIT 1)', (new_count,))
    conn.commit()
    conn.close()

    flash(f'Member counter updated to {new_count:,}!', 'success')
    return redirect(url_for('admin_counter'))

if __name__ == '__main__':
    init_db()

    # Start the keep-alive thread (optional - uncomment if you want automatic pinging)
    # threading.Thread(target=keep_alive, daemon=True).start()

    app.run(host='0.0.0.0', port=5000, debug=True)