import os, logging, re

from datetime import date
from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify
from database import SessionLocal, Target, ScanResult, Users
from scanner import add_target, scan_xss, save_scan_result, get_remediation_suggestions, scan_sql_injection
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash

logging.basicConfig(filename='app.log', level=logging.DEBUG, 
                    format='%(asctime)s %(levelname)s: %(message)s')

PASSWORD_REGEX = r"^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()_+{}|:\"<>?~]).{8,}$"

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

@app.route("/registration", methods=["POST", "GET"])
def registration():
    if request.method == "POST":
        session_db = SessionLocal()
        username = request.form['username']
        passwd = request.form['password']
        rpasswd = request.form['rpassword']
        existing_user = session_db.query(Users).filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different username.', 'danger')
            session_db.close()
            return redirect(url_for('registration'))
        if not re.match(PASSWORD_REGEX, passwd):
            flash('Password must contain at least 8 characters, including at least one digit, one uppercase letter, one lowercase letter, and one special character (!@#$%^&*()_+{}|:\"<>?~)', 'danger')
            session_db.close()
            return redirect(url_for('registration'))
        if passwd != rpasswd:
            flash('Passwords do not match!', 'danger')
            session_db.close()
            return redirect(url_for('registration'))
        else:
            hashed_passwd = generate_password_hash(passwd, method='pbkdf2:sha256')
            new_user = Users(username=username, passwd=hashed_passwd)
            try:
                session_db.add(new_user)
                session_db.commit()
                flash('Successfully registered! Proceed to login.', 'success')
            except Exception as e:
                logging.error(f"Error during registration: {e}")
                flash('Invalid entries received... Try again!', 'danger')
            finally:
                session_db.close()
            return redirect(url_for('login'))
    return render_template("registration.html")

@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        session_db = SessionLocal()
        username = request.form['username']
        passwd = request.form['password']
        user = session_db.query(Users).filter_by(username=username).first()
        if user and check_password_hash(user.passwd, passwd):
            session['username'] = username
            session_db.close()
            return redirect(url_for("index"))
        else:
            flash('Invalid username or password!', 'danger')
            session_db.close()
            return redirect(url_for('login'))
    return render_template("login.html")

@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    else:
        session_db = SessionLocal()
        username = session['username']
        latest_target = session_db.query(Target).filter_by(username=username).order_by(Target.created_at.desc()).first()
        scan_results = session_db.query(ScanResult).filter_by(username=username).order_by(ScanResult.found_at.desc()).all()
        latest_scan_result = None
        if scan_results:
            latest_scan_result = scan_results[0]
        session_db.close()
        today = date.today()
        return render_template('index.html', username=username, latest_target=latest_target, scan_results=scan_results, latest_scan_result=latest_scan_result, today=today)

@app.route('/add_target', methods=['POST'])
def add_target_route():
    url = request.form['url']
    logging.debug(f"Adding target URL: {url}")
    success, message = add_target(url)
    if not success:
        flash(message, 'danger')
    else:
        flash(message, 'success')
    return redirect(url_for('index'))

@app.route('/scan/<int:target_id>')
def scan(target_id):
    session_db = SessionLocal()
    username = session.get('username')
    if not username:
        session_db.close()
        return redirect(url_for('login'))
    target = session_db.query(Target).filter_by(id=target_id, username=username).first()
    if target:
        logging.debug(f"Scanning target: {target.url}")

        xss_result, xss_desc = scan_xss(target.url)
        if xss_result:
            save_scan_result(target.id, target.url, "XSS", xss_desc, get_remediation_suggestions("XSS"), username)

        sql_injection_result, sql_injection_desc = scan_sql_injection(target.url)
        if sql_injection_result:
            save_scan_result(target.id, target.url, "SQL Injection", sql_injection_desc, get_remediation_suggestions("SQL Injection"), username)

        if not xss_result and not sql_injection_result:
            save_scan_result(target.id, target.url, "No Vulnerabilities", "No vulnerabilities detected", "No remediation needed", username)
        
        target.is_scanned = True
        session_db.commit()

    session_db.close()
    return redirect(url_for('index'))

@app.route('/today_scans')
def today_scans():
    if 'username' not in session:
        return redirect(url_for('login'))
    session_db = SessionLocal()
    username = session['username']
    today = date.today()
    scan_results = session_db.query(ScanResult).filter_by(username=username).order_by(ScanResult.found_at.desc()).all()
    today_scans = [
        {
            'target_url': result.target_url,
            'vulnerability_type': result.vulnerability_type,
            'description': result.description,
            'remediation': result.remediation,
            'found_at': result.found_at.strftime('%Y-%m-%d %H:%M:%S')
        }
        for result in scan_results if result.found_at.date() == today
    ]
    session_db.close()
    return jsonify(today_scans)


@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)