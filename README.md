# 🔓 SQL Injection Playground with Detection Engine

An interactive educational platform to learn about SQL Injection (SQLi) vulnerabilities, detection mechanisms, and proper defense techniques. This comprehensive project demonstrates both vulnerable code patterns and their secure alternatives with real-time monitoring and analysis.

## 🎯 Project Objectives

- **Learn SQLi Vulnerabilities**: Understand how SQL injection attacks work through hands-on examples
- **Real-time Detection**: Monitor and detect SQL injection attempts using pattern matching and analysis
- **Defensive Patterns**: Compare vulnerable vs. secure code side-by-side
- **Educational Focus**: Designed for developers, security professionals, and students
- **Complete Platform**: Includes vulnerable app, secure app, detection engine, and monitoring dashboard

## 🏗️ Project Structure

```
sqli-playground/
├── app/                           # Main Flask application
│   ├── __init__.py
│   ├── app.py                     # Vulnerable & secure endpoints
│   └── __pycache__/
├── detection_engine/              # SQLi Detection & Monitoring
│   ├── __init__.py
│   ├── sqli_detector.py          # Pattern detection engine
│   ├── monitor.py                # Real-time log monitoring
│   └── dashboard.py              # Analytics dashboard
├── templates/                     # HTML templates
│   ├── base.html                 # Base template with styling
│   ├── index.html                # Home page
│   ├── login.html                # Vulnerable login
│   ├── secure_login.html         # Secure login
│   ├── search.html               # Vulnerable search
│   ├── secure_search.html        # Secure search
│   ├── logs.html                 # Security event logs
│   └── dashboard.html            # Monitoring dashboard
├── static/                        # Static assets
├── logs/                          # Security logs (auto-generated)
│   ├── security.log              # All security events
│   └── attack_attempts.log       # Detected attacks
├── init_database.py              # Database initialization
├── run.py                         # Main application runner
├── requirements.txt              # Python dependencies
└── README.md                      # This file
```

## 🚀 Quick Start

### Prerequisites

- Python 3.7+
- pip package manager
- Windows, macOS, or Linux

### Installation & Setup

1. **Create a virtual environment (recommended):**
   ```bash
   python -m venv venv
   
   # On Windows:
   .\venv\Scripts\activate
   
   # On macOS/Linux:
   source venv/bin/activate
   ```

2. **Install required packages:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Initialize the database (optional - auto-created on first run):**
   ```bash
   python init_database.py
   ```

4. **Run the application:**
   ```bash
   python run.py
   ```

5. **Access the application:**
   - **Vulnerable App**: http://localhost:5000
   - **Dashboard**: http://localhost:5001
   - **Secure App**: http://localhost:5000/secure-login

## 📚 Features & Components

### 1. **Vulnerable Application** (Port 5000)

Demonstrates SQL injection vulnerabilities through two main modules:

#### Login Page
- **URL**: `/login` (Vulnerable) | `/secure-login` (Secure)
- **Vulnerability**: String concatenation in SQL queries
- **How to Test**: 
  - Username: `admin' OR '1'='1` | Password: `anything`
  - Username: `admin'--` | Password: `anything`

#### Product Search
- **URL**: `/search` (Vulnerable) | `/secure-search` (Secure)
- **Vulnerability**: Direct user input in LIKE clause
- **How to Test**:
  - Search: `' OR '1'='1`
  - Search: `' UNION SELECT id, password, email, 0 FROM users--`

### 2. **SQLi Detection Engine**

#### Pattern Detection (`sqli_detector.py`)
```python
# Detects SQL injection patterns:
- SQL Keywords: UNION, SELECT, INSERT, UPDATE, DELETE, etc.
- SQL Comments: --, /*, #
- Tautologies: OR '1'='1', 1=1, etc.
- Time-based: WAITFOR, SLEEP
- Error-based: CAST, CONVERT, IF, BENCHMARK
- Stacked queries: ; followed by SQL keywords
```

#### Key Methods:
- `detect_in_logs()` - Analyze existing logs for SQLi patterns
- `analyze_http_request()` - Check URL params, POST data, headers
- `_check_string()` - Pattern matching on input strings
- `generate_report()` - Create human-readable findings report

#### Real-time Monitoring (`monitor.py`)
- File system watcher for security.log
- Immediate pattern detection on new entries
- Color-coded severity levels (High/Medium/Low)
- Automatic attack logging to attack_attempts.log

### 3. **Security Dashboard** (`dashboard.py`)

Monitoring dashboard with analytics and visualization:

**Endpoints**:
- `GET /` - Main dashboard view
- `GET /api/metrics` - Real-time metrics
- `GET /api/attacks` - Detected attacks with pagination
- `GET /api/attack/<id>` - Attack details & recommendations
- `GET /api/logs` - Raw security logs
- `GET /api/statistics` - Comprehensive statistics

**Dashboard Features**:
- Real-time attack detection
- Severity breakdown
- IP address tracking
- Attack pattern analysis
- Recommendations for defense

### 4. **Logging System**

#### Log Files
- **`logs/security.log`**: All security events (logins, searches, errors)
- **`logs/attack_attempts.log`**: JSON-formatted detected attacks

#### Log Entry Format
```
2024-11-25 10:30:45 - 127.0.0.1 - login_attempt - SELECT * FROM users WHERE username='admin' AND password='test'
```

## 🧪 Testing & Attack Examples

### Test Credentials
```
Username: admin | Password: admin123
Username: user1 | Password: password123
```

### Vulnerable Login - Injection Examples

#### 1. **Tautology-Based SQLi**
```
Username: admin' OR '1'='1
Password: anything

Generated Query:
SELECT * FROM users WHERE username='admin' OR '1'='1' AND password='anything'
```

#### 2. **Comment-Based Bypass**
```
Username: admin'--
Password: anything

Generated Query:
SELECT * FROM users WHERE username='admin'--' AND password='anything'
```

#### 3. **UNION-Based Injection** (if database structure exposed)
```
Username: admin' UNION SELECT 1,2,3--
Password: anything
```

### Vulnerable Search - Injection Examples

#### 1. **Data Extraction**
```
Search: ' OR '1'='1

Generated Query:
SELECT * FROM products WHERE name LIKE '%' OR '1'='1%' OR description LIKE '%' OR '1'='1%'

Result: Returns ALL products (authentication bypass)
```

#### 2. **UNION-Based Extraction**
```
Search: ' UNION SELECT id, password, email, price FROM users--

Generated Query:
SELECT * FROM products WHERE name LIKE '%' UNION SELECT id, password, email, price FROM users--%'

Result: Extracts user credentials!
```

### Secure Endpoints - Tests Show Protection

Try the same injection payloads on secure endpoints - they **will not work** because:
- Parameterized queries treat input as data, not SQL code
- Special characters are automatically escaped
- SQL structure is defined separately from user input

## 🛡️ Defense Mechanisms Explained

### ✅ Correct: Parameterized Queries

```python
# Using parameterized queries (SAFE)
query = "SELECT * FROM users WHERE username = ? AND password = ?"
cursor.execute(query, (username, password))

# Why it's safe:
# 1. SQL structure is defined separately
# 2. User input is treated as data, not code
# 3. Special characters are automatically escaped
# 4. Database driver handles all escaping
```

### ❌ Incorrect: String Concatenation

```python
# DO NOT USE - VULNERABLE!
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
cursor.execute(query)

# Why it's vulnerable:
# 1. User input is directly inserted into SQL code
# 2. Special characters break the query structure
# 3. Attacker can inject arbitrary SQL
# 4. No protection against malicious input
```

### Other Defense Layers

1. **Input Validation**
   ```python
   # Validate type, length, format
   if not isinstance(username, str) or len(username) > 50:
       raise ValueError("Invalid username")
   ```

2. **Least Privilege**
   ```sql
   -- Create restricted database user
   GRANT SELECT, UPDATE ON products TO app_user;
   -- Never grant DROP, CREATE, or ALTER permissions
   ```

3. **Error Handling**
   ```python
   try:
       cursor.execute(query, params)
   except Exception as e:
       log_error(e)  # Log internally
       return {"error": "Database operation failed"}  # Generic message to user
   ```

4. **Web Application Firewall (WAF)**
   - Monitor incoming requests for SQLi patterns
   - Block suspicious input
   - Alert on detection

## 📊 Monitoring & Analytics

### View Real-Time Logs

```bash
# Terminal 1: Run the main application
python run.py

# Terminal 2: Start monitoring
python -m detection_engine.monitor --log-dir logs --log-file security.log

# Terminal 3: Check statistics
python -c "from detection_engine.sqli_detector import SQLiDetector; \
d = SQLiDetector(); \
findings = d.detect_in_logs(); \
print(d.generate_report(findings))"
```

### Dashboard Metrics

1. **Total Attacks**: Count of all detected SQLi attempts
2. **Severity Breakdown**: High/Medium/Low distribution
3. **Attack Types**: Classification by injection type
4. **Top Attackers**: IP addresses with most attempts
5. **Attack Patterns**: Most common SQL keywords/patterns
6. **Time-based Analysis**: Attacks in last hour/day/week

## 🔍 How Detection Works

### Pattern Matching Process

1. **Read Log Entry**
   ```
   2024-11-25 10:30:45 - 127.0.0.1 - login_attempt - SELECT * FROM users WHERE username='admin' OR '1'='1'
   ```

2. **Extract Query**
   ```
   SELECT * FROM users WHERE username='admin' OR '1'='1'
   ```

3. **Apply Regex Patterns**
   - Check for SQL keywords
   - Look for comment sequences
   - Identify tautologies
   - Match suspicious patterns

4. **Calculate Severity**
   - HIGH: UNION SELECT, EXEC, WAITFOR, xp_cmdshell
   - MEDIUM: OR/AND with conditions, comments, basic keywords
   - LOW: Generic patterns

5. **Generate Alert**
   ```json
   {
     "timestamp": "2024-11-25T10:30:45",
     "ip": "127.0.0.1",
     "severity": "high",
     "type": "login_attempt",
     "matched_patterns": ["OR.*=.*", "UNION.*SELECT"],
     "data": "SELECT * FROM users WHERE username='admin' OR '1'='1'"
   }
   ```

## 📈 Performance Considerations

- **Detection Speed**: < 1ms per log entry on modern systems
- **Pattern Count**: 20+ regex patterns for comprehensive detection
- **Log Processing**: Handles 1000+ entries efficiently
- **Memory Usage**: ~50MB for typical logging load

## 🔐 Security Best Practices

### For Developers
1. ✅ Always use parameterized queries
2. ✅ Validate and sanitize all inputs
3. ✅ Use an ORM (SQLAlchemy, Django ORM)
4. ✅ Implement proper error handling
5. ✅ Never trust user input
6. ✅ Use principle of least privilege
7. ✅ Keep frameworks updated

### For Operations
1. ✅ Monitor database logs
2. ✅ Use database activity monitoring
3. ✅ Implement WAF rules
4. ✅ Regular security audits
5. ✅ Database access controls
6. ✅ Encryption at rest and in transit
7. ✅ Regular backups and recovery testing

## 📚 Resources & References

### Official Documentation
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [OWASP Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)

### Learning Resources
- PortSwigger Web Security Academy: SQL Injection
- HackTheBox: SQL Injection labs
- TryHackMe: SQL Injection challenges

### Tools for Testing
- SQLmap: Automated SQL injection tester
- Burp Suite: Web security testing
- OWASP ZAP: Security scanner

## 🤝 Contributing

This is an educational project. Contributions for improvements, additional attack examples, or detection patterns are welcome!

### Possible Enhancements
- [ ] Add time-based blind SQLi detection
- [ ] Implement database activity monitoring
- [ ] Add more sophisticated attack patterns
- [ ] Create interactive tutorials
- [ ] Add vulnerability scoring system
- [ ] Implement multi-language support

## ⚠️ Disclaimer

**This application is intentionally vulnerable for educational purposes ONLY.**

- ⛔ **Never** deploy this code to production
- ⛔ **Never** use on systems you don't own
- ⛔ Use only in isolated lab environments
- ⛔ For learning and authorized testing only

This project is intended for:
- Security professionals learning attack techniques
- Developers understanding vulnerabilities
- Students in cybersecurity courses
- Organizations conducting authorized security training

## 📝 License

This educational project is provided as-is for learning purposes.

## 👨‍💻 Author

Created as an educational SQL Injection Playground to demonstrate vulnerabilities and defenses.

---

## 📞 Getting Help

### Troubleshooting

**Port Already in Use**
```bash
# Windows
netstat -ano | findstr :5000
taskkill /PID <PID> /F

# macOS/Linux
lsof -i :5000
kill -9 <PID>
```

**Database Issues**
```bash
# Remove old database
del vuln_app.db  # Windows
rm vuln_app.db   # macOS/Linux

# Recreate on next run
python run.py
```

**Import Errors**
```bash
# Reinstall dependencies
pip install --upgrade pip
pip install -r requirements.txt --force-reinstall
```

---

**Happy Learning! 🚀 Remember: With great power comes great responsibility.**
  - `app.py` - Main application code
  - `templates/` - HTML templates
  - `static/` - Static files (CSS, JS, images)

- `detection_engine/` - SQL injection detection system
  - `sqli_detector.py` - Core detection logic
  - `monitor.py` - Real-time log monitoring
  - `dashboard.py` - Web-based monitoring dashboard

- `logs/` - Log files (created automatically)
  - `security.log` - Application logs
  - `attack_attempts.log` - Detected attack attempts

## How to Use

1. **Vulnerable Login**
   - Visit: http://localhost:5000/login
   - Try SQL injection: `admin' --` as username (leave password empty)

2. **Secure Login**
   - Visit: http://localhost:5000/secure-login
   - See how parameterized queries prevent SQL injection

3. **Vulnerable Search**
   - Visit: http://localhost:5000/search
   - Try SQL injection: `' UNION SELECT id, username, password, NULL FROM users--`

4. **Monitor Attacks**
   - Visit: http://localhost:5001
   - View real-time detection of SQL injection attempts

## Troubleshooting

- **Port already in use**: If you get a port in use error, either kill the process using the port or change the port in `run.py`
- **Module not found**: Make sure you've installed all requirements and activated your virtual environment
- **Template errors**: Ensure all template files are in the `templates/` directory

## Security Note

This application is intentionally vulnerable to SQL injection for educational purposes. Do not deploy this application in a production environment or on a public network.
