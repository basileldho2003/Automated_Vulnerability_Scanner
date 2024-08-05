from flask import session
import requests
from urllib.parse import urlparse
import logging
from database import SessionLocal, Target, ScanResult

logging.basicConfig(filename='scanner.log', level=logging.DEBUG, 
                    format='%(asctime)s %(levelname)s: %(message)s')

def add_target(url):
    if not validate_url(url):
        logging.error(f"Invalid URL format: {url}")
        return False, "Invalid URL format. Please enter a valid URL starting with http:// or https://."
    session_db = SessionLocal()
    username = session.get('username')
    if not username:
        logging.error("No username found in session.")
        return False, "User not logged in."
    target = Target(url=url, username=username)
    session_db.add(target)
    session_db.commit()
    session_db.close()
    logging.debug(f"Added target URL: {url}")
    return True, "Target added successfully."

def validate_url(url):
    parsed = urlparse(url)
    if parsed.scheme in ['http', 'https']:
        if '.' in parsed.netloc:
            return True
    return False

def scan_xss(url):
    if not validate_url(url):
        logging.error(f"Invalid URL format for XSS scan: {url}")
        return False, "Invalid URL format"
    
    payload = "<script>alert('XSS')</script>"
    data = {'comment': payload}
    try:
        response = requests.post(url, data=data, timeout=5)
        logging.debug(f"XSS test URL: {url}")
        logging.debug(f"XSS response status: {response.status_code}")
        logging.debug(f"XSS response text: {response.text}")
        if payload in response.text:
            return True, "XSS vulnerability detected"
    except requests.exceptions.RequestException as e:
        logging.error(f"XSS request failed: {e}")
    return False, "No XSS vulnerability detected"

def scan_sql_injection(url):
    if not validate_url(url):
        logging.error(f"Invalid URL format for SQL injection scan: {url}")
        return False, "Invalid URL format"

    payload = "' OR '1'='1' --"
    data = {'username': payload, 'password': 'password'}
    try:
        response = requests.post(url, data=data, timeout=5)
        logging.debug(f"SQL Injection test URL: {url}")
        logging.debug(f"SQL Injection response status: {response.status_code}")
        logging.debug(f"SQL Injection response text: {response.text}")
        if "Login successful!" in response.text:
            return True, "SQL Injection vulnerability detected"
    except requests.exceptions.RequestException as e:
        logging.error(f"SQL Injection request failed: {e}")
    return False, "No SQL Injection vulnerability detected"

def save_scan_result(target_id, target_url, vulnerability_type, description, remediation, username):
    session_db = SessionLocal()
    result = ScanResult(
        target_id=target_id,
        target_url=target_url,
        vulnerability_type=vulnerability_type,
        description=description,
        remediation=remediation,
        username=username
    )
    session_db.add(result)
    session_db.commit()
    session_db.close()
    logging.debug(f"Saved scan result: {result}")

def get_remediation_suggestions(vulnerability_type):
    suggestions = {
        "XSS": "Use proper input validation and encoding.",
        "SQL Injection": "Use parameterized queries or prepared statements."
    }
    return suggestions.get(vulnerability_type, "No suggestions available.")
