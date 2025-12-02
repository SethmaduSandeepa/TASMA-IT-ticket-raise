from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from pymongo import MongoClient
from dotenv import load_dotenv
import os
import bcrypt
from datetime import datetime
from bson.objectid import ObjectId

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
try:
    client = MongoClient(os.getenv("MONGO_URI"), serverSelectionTimeoutMS=5000)
    client.admin.command('ping')
    db = client.it_helpdesk
    users = db.users
    tickets = db.tickets
except Exception as e:
    print("\n*** MongoDB connection error: ", e, "\n")
    raise SystemExit("Could not connect to MongoDB. Please check your MONGO_URI, network, and Atlas cluster settings.")

@app.before_request
def before_request():
    g.pending_count = 0
    if 'username' in session and session.get('role') == 'admin':
        g.pending_count = users.count_documents({"role": "user", "status": "pending"})

# ...existing code...


# ...existing code...

# Admin: View and manage pending user requests
@app.route('/admin/requests', methods=['GET', 'POST'])
def user_requests():
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    if request.method == 'POST':
        action = request.form.get('action')
        user_id = request.form.get('user_id')
        if action == 'accept':
            users.update_one({"_id": ObjectId(user_id)}, {"$set": {"status": "active"}})
            flash("User accepted.")
        elif action == 'delete':
            users.delete_one({"_id": ObjectId(user_id)})
            flash("User deleted.")
        return redirect(url_for('user_requests'))
    pending_users = list(users.find({"role": "user", "status": "pending"}))
    return render_template('user_requests.html', pending_users=pending_users)


# Ensure admin exists (run once or improve with setup route)
admin_user = users.find_one({"username": "admin"})
if not admin_user:
    hashed = bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt())
    users.insert_one({
        "username": "admin",
        "password": hashed,
        "role": "admin"
    })

@app.route('/')
def index():
    if 'username' in session:
        if session['role'] == 'admin':
            return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('user_home'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        pc_name = request.form['pc_name']
        if users.find_one({"username": username}):
            flash("Username already exists.")
            return render_template('register.html')
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        users.insert_one({
            "username": username,
            "password": hashed,
            "role": "user",
            "pc_name": pc_name,
            "status": "pending"
        })
        flash("Registration request sent. Please wait for admin approval.")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users.find_one({"username": username})
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            if user.get('status', 'active') != 'active':
                flash("Your account is not yet approved by admin.")
                return render_template('login.html')
            session['username'] = user['username']
            session['role'] = user['role']
            return redirect(url_for('index'))
        flash("Invalid credentials")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/user')
def user_home():
    if 'username' not in session or session['role'] != 'user':
        return redirect(url_for('login'))
    user_tickets = list(tickets.find({"user": session['username']}))
    return render_template('user_home.html', tickets=user_tickets)

@app.route('/user/new', methods=['GET'])
def new_ticket():
    if 'username' not in session or session['role'] != 'user':
        return redirect(url_for('login'))
    return render_template('new_ticket.html')

@app.route('/user/submit', methods=['POST'])
def submit_ticket():
    if 'username' not in session or session['role'] != 'user':
        return redirect(url_for('login'))
    title = request.form['title']
    description = request.form['description']
    user = users.find_one({"username": session['username']})
    pc_name = user.get("pc_name", "") if user else ""
    tickets.insert_one({
        "user": session['username'],
        "title": title,
        "description": description,
        "status": "Open",
        "created_at": datetime.utcnow(),
        "pc_name": pc_name
    })
    flash("Ticket submitted!")
    return redirect(url_for('user_home'))

@app.route('/admin')
def dashboard():
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    all_tickets = list(tickets.find())
    return render_template('dashboard.html', tickets=all_tickets)

@app.route('/admin/update/<ticket_id>', methods=['POST'])
def update_ticket(ticket_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
    new_status = request.form['status']
    tickets.update_one(
        {"_id": ObjectId(ticket_id)},
        {"$set": {"status": new_status, "updated_at": datetime.utcnow()}}
    )
    return redirect(url_for('dashboard'))

# Helper for ObjectId in templates
from bson.objectid import ObjectId
app.jinja_env.globals.update(ObjectId=ObjectId)

if __name__ == '__main__':
    app.run(debug=False)