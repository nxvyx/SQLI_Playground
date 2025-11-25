from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import sqlite3
import time
from datetime import datetime
import os
from pathlib import Path

# Get the absolute path to the templates directory
BASE_DIR = Path(__file__).parent
TEMPLATE_DIR = BASE_DIR.parent / 'templates'

app = Flask(__name__, template_folder=str(TEMPLATE_DIR))
app.secret_key = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vuln_app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
def init_db():
    conn = sqlite3.connect('vuln_app.db')
    c = conn.cursor()
    
    # Create users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  email TEXT)''')
    
    # Create products table
    c.execute('''CREATE TABLE IF NOT EXISTS products
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  description TEXT,
                  price REAL)''')
    
    # Add some test data if not exists
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        c.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                 ('admin', 'admin123', 'admin@example.com'))
        c.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                 ('user1', 'password123', 'user1@example.com'))
        
    c.execute("SELECT COUNT(*) FROM products")
    if c.fetchone()[0] == 0:
        products = [
            ('Laptop', 'High performance laptop', 999.99),
            ('Smartphone', 'Latest smartphone', 699.99),
            ('Tablet', 'Portable tablet', 299.99)
        ]
        c.executemany("INSERT INTO products (name, description, price) VALUES (?, ?, ?)", products)
    
    conn.commit()
    conn.close()

# Vulnerable login function
def vulnerable_login(username, password):
    conn = sqlite3.connect('vuln_app.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # This is intentionally vulnerable to SQL injection
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    
    # Log the attempt
    log_attempt(request.remote_addr, query, 'login_attempt')
    
    try:
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        
        if user:
            log_attempt(request.remote_addr, f"Successful login for {username}", 'login_success')
            return user
        else:
            log_attempt(request.remote_addr, f"Failed login attempt for {username}", 'login_failed')
            return None
    except Exception as e:
        log_attempt(request.remote_addr, f"SQL Error: {str(e)}", 'sql_error')
        return None

# Secure login function (for comparison)
def secure_login(username, password):
    conn = sqlite3.connect('vuln_app.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Using parameterized query to prevent SQL injection
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    
    try:
        cursor.execute(query, (username, password))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            log_attempt(request.remote_addr, f"Secure login for {username}", 'secure_login_success')
        else:
            log_attempt(request.remote_addr, f"Secure login failed for {username}", 'secure_login_failed')
            
        return user
    except Exception as e:
        log_attempt(request.remote_addr, f"Secure login error: {str(e)}", 'secure_login_error')
        return None

# Vulnerable search function
def search_products_vulnerable(search_term):
    conn = sqlite3.connect('vuln_app.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # This is intentionally vulnerable to SQL injection
    query = f"SELECT * FROM products WHERE name LIKE '%{search_term}%' OR description LIKE '%{search_term}%'"
    
    # Log the search attempt
    log_attempt(request.remote_addr, query, 'search_attempt')
    
    try:
        cursor.execute(query)
        results = cursor.fetchall()
        conn.close()
        return results
    except Exception as e:
        log_attempt(request.remote_addr, f"Search error: {str(e)}", 'search_error')
        return []

# Logging function
def log_attempt(ip, data, attempt_type):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"{timestamp} - {ip} - {attempt_type} - {data}\n"
    
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    # Write to log file
    with open(f'logs/security.log', 'a') as f:
        f.write(log_entry)

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # Use the vulnerable login function
        user = vulnerable_login(username, password)
        
        if user:
            return f"Welcome {user['username']}! You are now logged in."
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/secure-login', methods=['GET', 'POST'])
def secure_login_route():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # Use the secure login function
        user = secure_login(username, password)
        
        if user:
            return f"Welcome {user['username']}! You are now securely logged in."
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('secure_login.html')

# Secure search function (for comparison)
def search_products_secure(search_term):
    conn = sqlite3.connect('vuln_app.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Using parameterized query to prevent SQL injection
    query = "SELECT * FROM products WHERE name LIKE ? OR description LIKE ?"
    search_pattern = f"%{search_term}%"
    
    try:
        cursor.execute(query, (search_pattern, search_pattern))
        results = cursor.fetchall()
        conn.close()
        log_attempt(request.remote_addr, f"Secure search for: {search_term}", 'secure_search_success')
        return results
    except Exception as e:
        log_attempt(request.remote_addr, f"Secure search error: {str(e)}", 'secure_search_error')
        return []

@app.route('/search', methods=['GET', 'POST'])
def search():
    results = []
    search_term = ''
    
    if request.method == 'POST':
        search_term = request.form.get('search', '')
        results = search_products_vulnerable(search_term)
    
    return render_template('search.html', results=results, search_term=search_term)

@app.route('/secure-search', methods=['GET', 'POST'])
def secure_search():
    results = []
    search_term = ''
    
    if request.method == 'POST':
        search_term = request.form.get('search', '')
        results = search_products_secure(search_term)
    
    return render_template('secure_search.html', results=results, search_term=search_term)

@app.route('/api/search', methods=['GET'])
def api_search():
    search_term = request.args.get('q', '')
    if not search_term:
        return jsonify({'error': 'No search term provided'}), 400
    
    results = search_products_vulnerable(search_term)
    return jsonify([dict(row) for row in results])

@app.route('/api/secure-search', methods=['GET'])
def api_secure_search():
    search_term = request.args.get('q', '')
    if not search_term:
        return jsonify({'error': 'No search term provided'}), 400
    
    results = search_products_secure(search_term)
    return jsonify([dict(row) for row in results])

@app.route('/logs')
def view_logs():
    """View security logs for educational purposes"""
    try:
        if os.path.exists('logs/security.log'):
            with open('logs/security.log', 'r') as f:
                logs = f.readlines()
            logs.reverse()  # Show latest first
            return render_template('logs.html', logs=logs)
        else:
            return render_template('logs.html', logs=[])
    except Exception as e:
        return f"Error reading logs: {str(e)}"

@app.route('/tutorials')
def tutorials():
    """Educational tutorials for SQL injection"""
    return render_template('tutorials.html')

if __name__ == '__main__':
    # Initialize the database
    init_db()
    
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    app.run(debug=True, port=5000)
