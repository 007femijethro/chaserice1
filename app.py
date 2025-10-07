from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_from_directory
import os
import random
import threading
import time
import requests
import queue
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
from email.message import EmailMessage
from functools import wraps 
from contextlib import contextmanager
from sqlalchemy import text
from db import engine


app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or 'chase-rice-fanpage-secret-2023'

# --- Email configuration ---
EMAIL_SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
EMAIL_SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
EMAIL_USERNAME  = os.environ.get("SMTP_USER", "")
EMAIL_PASSWORD  = os.environ.get("SMTP_PASS", "")
EMAIL_FROM      = os.environ.get("FROM_EMAIL", EMAIL_USERNAME or "no-reply@example.com")
EMAIL_FROM_NAME = os.environ.get("FROM_NAME", "Chase Rice Fan Club")
ADMIN_EMAIL     = os.environ.get("ADMIN_EMAIL", "")
EMAIL_USE_SSL   = os.environ.get("SMTP_SSL", "false").lower() == "true"

# Email queue for background processing
email_queue = queue.Queue()
email_worker_running = True

def email_worker():
    """Background worker to process emails"""
    while email_worker_running:
        try:
            # Wait for emails with timeout
            task = email_queue.get(timeout=30)
            if task is None:  # Shutdown signal
                break

            subject, to_addrs, html_body, text_body = task
            try:
                send_email(subject, to_addrs, html_body, text_body)
                print(f"Background email sent to {to_addrs}")
            except Exception as e:
                print(f"Background email failed: {e}")
            finally:
                email_queue.task_done()

        except queue.Empty:
            continue

# Start email worker thread
email_thread = threading.Thread(target=email_worker, daemon=True)
email_thread.start()

def send_email(subject: str, to_addrs: list[str], html_body: str, text_body: str | None = None):
    if not to_addrs:
        return
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = f"{EMAIL_FROM_NAME} <{EMAIL_FROM}>"
        msg["To"] = ", ".join(to_addrs)
        if text_body:
            msg.set_content(text_body)
            msg.add_alternative(html_body, subtype="html")
        else:
            msg.set_content(html_body, subtype="html")

        if EMAIL_USE_SSL:
            try:
                with smtplib.SMTP_SSL(EMAIL_SMTP_HOST, EMAIL_SMTP_PORT) as smtp:
                    if EMAIL_USERNAME and EMAIL_PASSWORD:
                        smtp.login(EMAIL_USERNAME, EMAIL_PASSWORD)
                    smtp.send_message(msg)
            except Exception as e:
                print(f"[EMAIL ERROR] SSL connection failed: {e}")
                # Fallback to regular SMTP
                with smtplib.SMTP(EMAIL_SMTP_HOST, EMAIL_SMTP_PORT) as smtp:
                    try:
                        smtp.starttls()
                    except smtplib.SMTPException:
                        pass
                    if EMAIL_USERNAME and EMAIL_PASSWORD:
                        smtp.login(EMAIL_USERNAME, EMAIL_PASSWORD)
                    smtp.send_message(msg)
        else:
            with smtplib.SMTP(EMAIL_SMTP_HOST, EMAIL_SMTP_PORT) as smtp:
                try:
                    smtp.starttls()
                except smtplib.SMTPException:
                    pass
                if EMAIL_USERNAME and EMAIL_PASSWORD:
                    smtp.login(EMAIL_USERNAME, EMAIL_PASSWORD)
                smtp.send_message(msg)
        print(f"[EMAIL SENT] To: {to_addrs}, Subject: {subject}")
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")

def send_email_async(subject, to_addrs, html_body, text_body=None):
    """Queue email for background sending"""
    try:
        email_queue.put((subject, to_addrs, html_body, text_body))
        return True
    except Exception as e:
        print(f"Failed to queue email: {e}")
        return False

def send_welcome_email(member_data):
    """Send welcome email to new members"""
    subject = "Welcome to the Chase Rice Fan Club!"

    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
            .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }}
            .welcome {{ font-size: 24px; color: #764ba2; margin-bottom: 20px; }}
            .button {{ display: inline-block; background: #667eea; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin: 20px 0; }}
            .footer {{ text-align: center; margin-top: 30px; color: #666; font-size: 14px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🎵 Chase Rice Fan Club 🎵</h1>
            </div>
            <div class="content">
                <div class="welcome">Welcome aboard, {member_data.get('first_name') or member_data.get('username')}!</div>

                <p>We're thrilled to have you join our community of Chase Rice fans! Here's what you can look forward to:</p>

                <ul>
                    <li>🎤 Exclusive tour updates and early ticket access</li>
                    <li>🎵 Behind-the-scenes content and music previews</li>
                    <li>🎟️ Member-only raffles and giveaways</li>
                    <li>👥 Connect with other fans in our community</li>
                    <li>📰 Curated Chase Rice news and updates</li>
                </ul>

                <p>Your account has been successfully created with the following details:</p>
                <p><strong>Username:</strong> {member_data.get('username')}<br>
                <strong>Email:</strong> {member_data.get('email')}<br>
                <strong>Member Since:</strong> {datetime.now().strftime('%B %d, %Y')}</p>

                <a href="{url_for('index', _external=True)}" class="button">Visit Fan Club</a>

                <p>If you have any questions or need assistance, don't hesitate to reach out to us.</p>

                <div class="footer">
                    <p>Keep the music playing!<br>
                    <strong>The Chase Rice Fan Club Team</strong></p>
                    <p><small>This is an automated message, please do not reply directly to this email.</small></p>
                </div>
            </div>
        </div>
    </body>
    </html>
    """

    text_body = f"""
    Welcome to the Chase Rice Fan Club, {member_data.get('first_name') or member_data.get('username')}!

    We're thrilled to have you join our community of Chase Rice fans! 

    Your account details:
    Username: {member_data.get('username')}
    Email: {member_data.get('email')}
    Member Since: {datetime.now().strftime('%B %d, %Y')}

    What you'll get as a member:
    - Exclusive tour updates and early ticket access
    - Behind-the-scenes content and music previews
    - Member-only raffles and giveaways
    - Connect with other fans
    - Curated Chase Rice news

    Visit the fan club: {url_for('index', _external=True)}

    Keep the music playing!
    The Chase Rice Fan Club Team

    This is an automated message, please do not reply directly to this email.
    """

    send_email_async(subject, [member_data.get('email')], html_body, text_body)

def send_admin_notification(subject, member_data, action_type="registration"):
    """Send notification email to admin"""
    if not ADMIN_EMAIL:
        return

    action_text = {
        "registration": "registered",
        "login": "signed in"
    }.get(action_type, action_type)

    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: #dc3545; color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }}
            .content {{ background: #f8f9fa; padding: 25px; border-radius: 0 0 10px 10px; }}
            .alert {{ background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 15px 0; }}
            .info-table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
            .info-table th, .info-table td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
            .info-table th {{ background: #e9ecef; width: 30%; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>🔔 Fan Club Admin Notification</h2>
            </div>
            <div class="content">
                <div class="alert">
                    <strong>Action:</strong> Member {action_text}<br>
                    <strong>Time:</strong> {timestamp}
                </div>

                <h3>Member Details:</h3>
                <table class="info-table">
                    <tr><th>Username:</th><td>{member_data.get('username')}</td></tr>
                    <tr><th>Email:</th><td>{member_data.get('email')}</td></tr>
                    <tr><th>Full Name:</th><td>{member_data.get('first_name', '')} {member_data.get('last_name', '')}</td></tr>
                    <tr><th>Phone:</th><td>{member_data.get('phone_number', 'Not provided')}</td></tr>
                    <tr><th>Sex:</th><td>{member_data.get('sex', 'Not specified')}</td></tr>
                    <tr><th>Date of Birth:</th><td>{member_data.get('date_of_birth', 'Not provided')}</td></tr>
                    <tr><th>Newsletter:</th><td>{'Subscribed' if member_data.get('newsletter_subscription') else 'Not subscribed'}</td></tr>
                </table>

                {f"<h3>Message to Chase:</h3><p>{member_data.get('message_to_chase', 'None')}</p>" if member_data.get('message_to_chase') else ""}

                <p><a href="{url_for('admin_member_detail', member_id=member_data.get('id'), _external=True)}">View member details in admin panel</a></p>
            </div>
        </div>
    </body>
    </html>
    """

    text_body = f"""
    FAN CLUB ADMIN NOTIFICATION
    ===========================

    Action: Member {action_text}
    Time: {timestamp}

    Member Details:
    ---------------
    Username: {member_data.get('username')}
    Email: {member_data.get('email')}
    Full Name: {member_data.get('first_name', '')} {member_data.get('last_name', '')}
    Phone: {member_data.get('phone_number', 'Not provided')}
    Sex: {member_data.get('sex', 'Not specified')}
    Date of Birth: {member_data.get('date_of_birth', 'Not provided')}
    Newsletter: {'Subscribed' if member_data.get('newsletter_subscription') else 'Not subscribed'}

    {f"Message to Chase: {member_data.get('message_to_chase', 'None')}" if member_data.get('message_to_chase') else ""}

    View member details: {url_for('admin_member_detail', member_id=member_data.get('id'), _external=True)}
    """

    send_email_async(subject, [ADMIN_EMAIL], html_body, text_body)

def send_raffle_confirmation(entry_data):
    """Send raffle entry confirmation email"""
    subject = "You're in! Chase Rice Raffle Entry Confirmed"

    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: linear-gradient(135deg, #28a745, #20c997); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
            .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }}
            .confirmation {{ font-size: 24px; color: #28a745; margin-bottom: 20px; }}
            .entry-details {{ background: white; padding: 20px; border-radius: 5px; margin: 20px 0; }}
            .footer {{ text-align: center; margin-top: 30px; color: #666; font-size: 14px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🎟️ Chase Rice Raffle Entry 🎟️</h1>
            </div>
            <div class="content">
                <div class="confirmation">You're officially entered!</div>

                <p>Hello {entry_data.get('name')},</p>
                <p>Your entry into the Chase Rice raffle has been confirmed. Good luck!</p>

                <div class="entry-details">
                    <h3>Your Entry Details:</h3>
                    <p><strong>Name:</strong> {entry_data.get('name')}<br>
                    <strong>Email:</strong> {entry_data.get('email')}<br>
                    <strong>Favorite Song:</strong> {entry_data.get('favorite_song', 'Not specified')}<br>
                    <strong>Entry Date:</strong> {datetime.now().strftime('%B %d, %Y at %H:%M')}</p>
                </div>

                <p>We'll notify you if you win! Winners are typically announced within 7-10 days after the raffle closes.</p>

                <div class="footer">
                    <p>Best of luck!<br>
                    <strong>Chase Rice Fan Club</strong></p>
                </div>
            </div>
        </div>
    </body>
    </html>
    """

    send_email_async(subject, [entry_data.get('email')], html_body)
# --- End email configuration ---

# Database initialization (Postgres/SQLAlchemy)
def init_db():
    with engine.begin() as conn:
        # raffle_entries
        conn.execute(text('''
            CREATE TABLE IF NOT EXISTS raffle_entries (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                favorite_song TEXT,
                entry_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        '''))

        # admin_users
        conn.execute(text('''
            CREATE TABLE IF NOT EXISTS admin_users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        '''))

        # members
        conn.execute(text('''
            CREATE TABLE IF NOT EXISTS members (
                id SERIAL PRIMARY KEY,
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
                registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        '''))

        # winners
        conn.execute(text('''
            CREATE TABLE IF NOT EXISTS winners (
                id SERIAL PRIMARY KEY,
                raffle_id INTEGER,
                win_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                CONSTRAINT fk_winner_raffle FOREIGN KEY(raffle_id) REFERENCES raffle_entries(id)
            )
        '''))

        # tours
        conn.execute(text('''
            CREATE TABLE IF NOT EXISTS tours (
                id SERIAL PRIMARY KEY,
                date TEXT NOT NULL,
                venue TEXT NOT NULL,
                city TEXT NOT NULL,
                state_or_country TEXT NOT NULL,
                ticket_url TEXT,
                created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        '''))

        # unique index for idempotent tour updates
        conn.execute(text('''
            CREATE UNIQUE INDEX IF NOT EXISTS uniq_tour
            ON tours(date, venue, city, state_or_country)
        '''))

        # member_counter
        conn.execute(text('''
            CREATE TABLE IF NOT EXISTS member_counter (
                id SERIAL PRIMARY KEY,
                current_count INTEGER NOT NULL DEFAULT 1247,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        '''))

        # Insert default member counter if not exists
        row = conn.execute(text('SELECT COUNT(*) AS c FROM member_counter')).fetchone()
        if row and (row[0] or row._mapping.get('c')) == 0:
            conn.execute(text('INSERT INTO member_counter (current_count) VALUES (1247)'))

        # Insert default admin user if not exists
        password_hash = generate_password_hash('admin123')
        conn.execute(text('''
            INSERT INTO admin_users (username, password_hash)
            VALUES (:u, :p)
            ON CONFLICT (username) DO NOTHING
        '''), {"u": "admin", "p": password_hash})

        # Seed tour dates (idempotent upsert)
        current_tours = [
            ('2025-09-25', 'Vina Robles Amphitheatre', 'Paso Robles', 'CA', 'https://www.ticketmaster.com/chase-rice-tickets/artist/1580113'),
            ('2025-09-26', 'House of Blues Anaheim', 'Anaheim', 'CA', 'https://www.ticketmaster.com/chase-rice-tickets/artist/1580113'),
            ('2025-09-27', 'The Fruit Yard Amphitheater', 'Modesto', 'CA', 'https://www.ticketmaster.com/chase-rice-tickets/artist/1580113'),
            ('2025-10-02', 'Hampton Beach Casino Ballroom', 'Hampton Beach', 'NH', 'https://www.ticketmaster.com/chase-rice-tickets/artist/1580113'),
            ('2025-10-04', 'Toads Place', 'New Haven', 'CT', 'https://www.ticketmaster.com/chase-rice-tickets/artist/1580113'),
            ('2025-10-16', 'The Jones Assembly', 'Oklahoma City', 'OK', 'https://www.ticketmaster.com/chase-rice-tickets/artist/1580113'),
            ('2025-10-17', 'Golden Nugget', 'Lake Charles', 'LA', 'https://www.ticketmaster.com/chase-rice-tickets/artist/1580113')
        ]
        for date_v, venue, city, state, url in current_tours:
            conn.execute(text('''
                INSERT INTO tours (date, venue, city, state_or_country, ticket_url)
                VALUES (:date, :venue, :city, :state, :url)
                ON CONFLICT (date, venue, city, state_or_country)
                DO UPDATE SET ticket_url = EXCLUDED.ticket_url,
                              created_date = CURRENT_TIMESTAMP
            '''), {"date": date_v, "venue": venue, "city": city, "state": state, "url": url})

# Database connection helper
@contextmanager
def get_db_connection():
    # yields a SQLAlchemy Connection with transaction
    with engine.begin() as conn:
        yield conn

# Helper function to check if user is logged in
def member_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('member_logged_in'):
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('member_login'))
        return f(*args, **kwargs)
    return decorated_function

# Security headers middleware
@app.after_request
def add_security_headers(response):
    """Add security headers to block scanners"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

    # Block common vulnerability scanner paths
    if any(path in request.path for path in ['/wp-admin', '/wordpress', '/phpmyadmin', '/.env']):
        response.status_code = 403
        response.data = b'Access Forbidden'

    return response

# Static files for admin routes
@app.route('/admin/static/<path:filename>')
def admin_static(filename):
    """Serve static files for admin routes"""
    return send_from_directory(os.path.join(app.root_path, 'static'), filename)

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
    with get_db_connection() as conn:
        tours = conn.execute(text('SELECT * FROM tours ORDER BY date ASC LIMIT 3')).fetchall()

        # Fetch current member counter
        counter_row = conn.execute(text('SELECT current_count FROM member_counter ORDER BY id DESC LIMIT 1')).fetchone()
        member_count = counter_row[0] if counter_row else 1247

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
    with get_db_connection() as conn:
        tours = conn.execute(text('SELECT * FROM tours ORDER BY date ASC')).fetchall()
    return render_template('tour.html', tours=tours)

@app.route('/winners')
@member_required
def winners():
    with get_db_connection() as conn:
        winners = conn.execute(text('''
            SELECT raffle_entries.name, raffle_entries.favorite_song, winners.win_date 
            FROM winners 
            JOIN raffle_entries ON winners.raffle_id = raffle_entries.id 
            ORDER BY winners.win_date DESC
        ''')).fetchall()
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
            return render_template('member_register.html', 
                                 username=username, email=email, first_name=first_name, 
                                 last_name=last_name, phone_number=phone_number)

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('member_register.html',
                                 username=username, email=email, first_name=first_name,
                                 last_name=last_name, phone_number=phone_number)

        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('member_register.html',
                                 username=username, email=email, first_name=first_name,
                                 last_name=last_name, phone_number=phone_number)

        # Check if user already exists & create new member
        try:
            with get_db_connection() as conn:
                existing_user = conn.execute(
                    text('SELECT 1 FROM members WHERE username = :username OR email = :email'),
                    {"username": username, "email": email}
                ).fetchone()

                if existing_user:
                    flash('Username or email already exists.', 'error')
                    return render_template('member_register.html',
                                         username=username, email=email, first_name=first_name,
                                         last_name=last_name, phone_number=phone_number)

                password_hash = generate_password_hash(password)
                new_id_row = conn.execute(text('''
                    INSERT INTO members (username, email, password_hash, first_name, last_name, phone_number, sex, date_of_birth, message_to_chase, newsletter_subscription)
                    VALUES (:username, :email, :password_hash, :first_name, :last_name, :phone_number, :sex, :date_of_birth, :message_to_chase, :newsletter_subscription)
                    RETURNING id
                '''), {
                    "username": username,
                    "email": email,
                    "password_hash": password_hash,
                    "first_name": first_name,
                    "last_name": last_name,
                    "phone_number": phone_number,
                    "sex": sex,
                    "date_of_birth": date_of_birth,
                    "message_to_chase": message_to_chase,
                    "newsletter_subscription": newsletter_subscription
                }).fetchone()

                member_id = new_id_row[0]
                new_member = conn.execute(text('SELECT * FROM members WHERE id = :id'), {"id": member_id}).fetchone()
        except Exception as e:
            flash('Database error. Please try again.', 'error')
            print(f"Database error during registration: {e}")
            return render_template('member_register.html',
                                 username=username, email=email, first_name=first_name,
                                 last_name=last_name, phone_number=phone_number)

        # Send welcome email to new member (async)
        try:
            member_data = dict(new_member._mapping)
            send_welcome_email(member_data)
        except Exception as e:
            print(f"[EMAIL ERROR] Welcome email failed: {e}")

        # Send admin notification (async)
        try:
            send_admin_notification(
                f"New Member Registration: {username}",
                member_data,
                "registration"
            )
        except Exception as e:
            print(f"[EMAIL ERROR] Admin notification failed: {e}")

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('member_login'))

    return render_template('member_register.html')

@app.route('/login', methods=['GET', 'POST'])
def member_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            with get_db_connection() as conn:
                user = conn.execute(
                    text('SELECT * FROM members WHERE username = :u OR email = :u'),
                    {"u": username}
                ).fetchone()
        except Exception as e:
            flash('Database error. Please try again.', 'error')
            print(f"Database error during login: {e}")
            return render_template('member_login.html')

        if user and check_password_hash(user._mapping['password_hash'], password):
            session['member_logged_in'] = True
            session['member_id'] = user._mapping['id']
            session['member_username'] = user._mapping['username']

            # Send sign-in notification to admin (async)
            try:
                member_data = dict(user._mapping)
                send_admin_notification(
                    f"Member Sign In: {user._mapping['username']}",
                    member_data,
                    "login"
                )
            except Exception as e:
                print(f"[EMAIL ERROR] Sign-in notification failed: {e}")

            first_name = user._mapping.get("first_name")
            flash(f"Welcome back, {first_name or user._mapping['username']}!", 'success')
            return redirect(url_for('bio'))
        else:
            flash('Invalid username/email or password.', 'error')

    return render_template('member_login.html')

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

        try:
            with get_db_connection() as conn:
                conn.execute(text('INSERT INTO raffle_entries (name, email, favorite_song) VALUES (:name, :email, :favorite_song)'),
                            {"name": name, "email": email, "favorite_song": favorite_song})
        except Exception as e:
            flash('Database error. Please try again.', 'error')
            print(f"Database error during raffle entry: {e}")
            return redirect(url_for('raffle'))

        # Send raffle confirmation email (async)
        try:
            entry_data = {
                'name': name,
                'email': email,
                'favorite_song': favorite_song
            }
            send_raffle_confirmation(entry_data)
        except Exception as e:
            print(f"[EMAIL ERROR] Raffle confirmation failed: {e}")

        flash('Thanks for entering the raffle! Good luck!', 'success')
        return redirect(url_for('raffle'))

    return render_template('raffle.html')

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

        try:
            with get_db_connection() as conn:
                user = conn.execute(text('SELECT * FROM admin_users WHERE username = :u'), {"u": username}).fetchone()
        except Exception as e:
            flash('Database error. Please try again.', 'error')
            print(f"Database error during admin login: {e}")
            return render_template('admin_login.html')

        if user and check_password_hash(user._mapping['password_hash'], password):
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

    with get_db_connection() as conn:
        entry_count = conn.execute(text('SELECT COUNT(*) FROM raffle_entries')).fetchone()[0]
        recent_entries = conn.execute(text('SELECT * FROM raffle_entries ORDER BY entry_date DESC LIMIT 5')).fetchall()

    return render_template('admin_dashboard.html', entry_count=entry_count, recent_entries=recent_entries)

@app.route('/admin/members')
def admin_members():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    with get_db_connection() as conn:
        members = conn.execute(text('''
            SELECT id, username, email, first_name, last_name, phone_number, sex, date_of_birth, registration_date 
            FROM members ORDER BY registration_date DESC
        ''')).fetchall()

    return render_template('admin_members.html', members=members)

@app.route('/admin/member/<int:member_id>')
def admin_member_detail(member_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    with get_db_connection() as conn:
        member = conn.execute(text('SELECT * FROM members WHERE id = :id'), {"id": member_id}).fetchone()

    if not member:
        flash('Member not found.', 'error')
        return redirect(url_for('admin_members'))

    return render_template('admin_member_detail.html', member=member)

@app.route('/admin/member/delete/<int:member_id>', methods=['POST'])
def admin_delete_member(member_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    try:
        with get_db_connection() as conn:
            member = conn.execute(text('SELECT * FROM members WHERE id = :id'), {"id": member_id}).fetchone()

            if not member:
                flash('Member not found.', 'error')
                return redirect(url_for('admin_members'))

            # Delete the member
            conn.execute(text('DELETE FROM members WHERE id = :id'), {"id": member_id})
    except Exception as e:
        flash('Database error. Please try again.', 'error')
        print(f"Database error during member deletion: {e}")
        return redirect(url_for('admin_members'))

    flash(f'Member "{member._mapping["username"]}" has been deleted successfully.', 'success')
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

        try:
            with get_db_connection() as conn:
                existing_user = conn.execute(text('SELECT 1 FROM members WHERE username = :username OR email = :email'),
                                             {"username": username, "email": email}).fetchone()

                if existing_user:
                    flash('Username or email already exists.', 'error')
                    return redirect(url_for('admin_add_member'))

                password_hash = generate_password_hash(password)
                conn.execute(text('''
                    INSERT INTO members (username, email, password_hash, first_name, last_name, phone_number, sex, date_of_birth, message_to_chase, newsletter_subscription)
                    VALUES (:username, :email, :password_hash, :first_name, :last_name, :phone_number, :sex, :date_of_birth, :message_to_chase, :newsletter_subscription)
                '''), {
                    "username": username,
                    "email": email,
                    "password_hash": password_hash,
                    "first_name": first_name,
                    "last_name": last_name,
                    "phone_number": phone_number,
                    "sex": sex,
                    "date_of_birth": date_of_birth,
                    "message_to_chase": message_to_chase,
                    "newsletter_subscription": newsletter_subscription
                })
        except Exception as e:
            flash('Database error. Please try again.', 'error')
            print(f"Database error during admin member add: {e}")
            return redirect(url_for('admin_add_member'))

        flash(f'Member "{username}" has been added successfully.', 'success')
        return redirect(url_for('admin_members'))

    return render_template('admin_add_member.html')

@app.route('/admin/tours')
def admin_tours():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    with get_db_connection() as conn:
        tours = conn.execute(text('SELECT * FROM tours ORDER BY date ASC')).fetchall()

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
        try:
            with get_db_connection() as conn:
                conn.execute(text('''
                    INSERT INTO tours (date, venue, city, state_or_country, ticket_url)
                    VALUES (:date, :venue, :city, :state, :url)
                    ON CONFLICT (date, venue, city, state_or_country)
                    DO UPDATE SET ticket_url = EXCLUDED.ticket_url,
                                  created_date = CURRENT_TIMESTAMP
                '''), {"date": date, "venue": venue, "city": city, "state": state_or_country, "url": ticket_url})
        except Exception as e:
            flash('Database error. Please try again.', 'error')
            print(f"Database error during tour add: {e}")
            return redirect(url_for('admin_add_tour'))

        flash(f'Tour date at {venue} has been added successfully.', 'success')
        return redirect(url_for('admin_tours'))

    return render_template('admin_add_tour.html')

@app.route('/admin/tour/delete/<int:tour_id>', methods=['POST'])
def admin_delete_tour(tour_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    try:
        with get_db_connection() as conn:
            tour = conn.execute(text('SELECT * FROM tours WHERE id = :id'), {"id": tour_id}).fetchone()

            if not tour:
                flash('Tour not found.', 'error')
                return redirect(url_for('admin_tours'))

            # Delete the tour
            conn.execute(text('DELETE FROM tours WHERE id = :id'), {"id": tour_id})
    except Exception as e:
        flash('Database error. Please try again.', 'error')
        print(f"Database error during tour deletion: {e}")
        return redirect(url_for('admin_tours'))

    flash(f'Tour at {tour._mapping["venue"]} has been deleted successfully.', 'success')
    return redirect(url_for('admin_tours'))

@app.route('/admin/pick_winner')
def pick_winner():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    with get_db_connection() as conn:
        # Get all entries
        entries = conn.execute(text('SELECT * FROM raffle_entries')).fetchall()

        if not entries:
            flash('No entries to pick from!', 'error')
            return redirect(url_for('admin_dashboard'))

        # Pick a random winner
        winner = random.choice(entries)

        # Add to winners table
        conn.execute(text('INSERT INTO winners (raffle_id) VALUES (:rid)'), {"rid": winner._mapping['id']})

        # Get winner info for display
        winner_info = conn.execute(text('SELECT * FROM raffle_entries WHERE id = :id'), {"id": winner._mapping['id']}).fetchone()

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
    # Basic security check - only allow if not logged in as member
    if session.get('member_logged_in'):
        return jsonify({'success': False, 'error': 'Not allowed for logged-in members'}), 403

    try:
        with get_db_connection() as conn:
            # Get current count
            counter_row = conn.execute(text('SELECT current_count FROM member_counter ORDER BY id DESC LIMIT 1')).fetchone()
            current_count = counter_row[0] if counter_row else 1247

            # Increment by 1
            new_count = current_count + 1

            # Update in database
            conn.execute(text('''
                UPDATE member_counter 
                SET current_count = :n, last_updated = CURRENT_TIMESTAMP 
                WHERE id = (SELECT id FROM member_counter ORDER BY id DESC LIMIT 1)
            '''), {"n": new_count})
    except Exception:
        return jsonify({'success': False, 'error': 'Database error'}), 500

    return jsonify({'success': True, 'new_count': new_count})

@app.route('/admin/counter')
def admin_counter():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    with get_db_connection() as conn:
        counter_row = conn.execute(text('SELECT current_count, last_updated FROM member_counter ORDER BY id DESC LIMIT 1')).fetchone()

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
    try:
        with get_db_connection() as conn:
            conn.execute(text('''
                UPDATE member_counter 
                SET current_count = :n, last_updated = CURRENT_TIMESTAMP 
                WHERE id = (SELECT id FROM member_counter ORDER BY id DESC LIMIT 1)
            '''), {"n": new_count})
    except Exception as e:
        flash('Database error. Please try again.', 'error')
        print(f"Database error during counter update: {e}")
        return redirect(url_for('admin_counter'))

    flash(f'Member counter updated to {new_count:,}!', 'success')
    return redirect(url_for('admin_counter'))

# Cleanup function for email worker
def cleanup_email_worker():
    global email_worker_running
    email_worker_running = False
    email_queue.put(None)  # Signal shutdown
    email_thread.join(timeout=5)

# Register cleanup function
import atexit
atexit.register(cleanup_email_worker)

if __name__ == '__main__':
    init_db()

    # Start the keep-alive thread (optional - uncomment if you want automatic pinging)
    # threading.Thread(target=keep_alive, daemon=True).start()

    app.run(host='0.0.0.0', port=5000, debug=True)
