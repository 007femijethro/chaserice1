    # app.py
    from flask import Flask, render_template, request, redirect, url_for, session, flash
    import sqlite3
    import os
    import random
    from datetime import datetime
    from werkzeug.security import generate_password_hash, check_password_hash

    app = Flask(__name__)
    app.secret_key = 'your-secret-key-here'  # Change this in production

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

        # Create winners table
        c.execute('''CREATE TABLE IF NOT EXISTS winners
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      raffle_id INTEGER,
                      win_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      FOREIGN KEY(raffle_id) REFERENCES raffle_entries(id))''')

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

    # Routes
    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/bio')
    def bio():
        return render_template('bio.html')

    @app.route('/music')
    def music():
        return render_template('music.html')

    @app.route('/raffle', methods=['GET', 'POST'])
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
    def winners():
        conn = get_db_connection()
        winners = conn.execute('''SELECT raffle_entries.name, raffle_entries.favorite_song, winners.win_date 
                                 FROM winners 
                                 JOIN raffle_entries ON winners.raffle_id = raffle_entries.id 
                                 ORDER BY winners.win_date DESC''').fetchall()
        conn.close()
        return render_template('winners.html', winners=winners)

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

    if __name__ == '__main__':
        init_db()
        app.run(host='0.0.0.0', port=5000, debug=True)