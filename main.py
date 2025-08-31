from flask import Flask, render_template, request, redirect, url_for
from replit import db
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Initialize the database for raffle entries
if "raffle_entries" not in db:
    db["raffle_entries"] = []

# Homepage
@app.route('/')
def index():
    return render_template('index.html')

# Raffle Page - Show Form
@app.route('/raffle')
def raffle():
    return render_template('raffle.html')

# Raffle Page - Handle Form Submission
@app.route('/enter_raffle', methods=['POST'])
def enter_raffle():
    name = request.form['name']
    email = request.form['email']
    song = request.form.get('favorite_song', 'Not provided') # Optional field

    # Create an entry dictionary
    entry = {"name": name, "email": email, "song": song}

    # Add the entry to the database list
    current_entries = db["raffle_entries"]
    current_entries.append(entry)
    db["raffle_entries"] = current_entries

    # Show a confirmation page (you can improve this later)
    return f"<h1>Thanks for entering, {name}!</h1><p>Your favorite song is: {song}. Good luck!</p><a href='/'>Go Home</a>"

# SECRET ADMIN PAGE - Pick a Winner
@app.route('/admin')
def admin():
    # Check if the user is authenticated (you'll need to implement this with a login form or basic auth)
    # For now, we'll just show the page. SEE NOTE BELOW.
    entries = db["raffle_entries"]
    return render_template('admin.html', entries=entries)

# NOTE: You MUST implement proper authentication for the /admin route before making your Repl public.
# Research "Flask HTTP Basic Auth" or use the Replit Secrets you set up.

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
