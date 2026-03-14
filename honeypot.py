from flask import Flask, request
from datetime import datetime, timedelta
import threading
import pandas as pd
import os
import geoip2.database
from colorama import Fore, init

# Initialize colorama
init(autoreset=True)
app = Flask(__name__)

# ---------------- Config ----------------
LOG_FILE = "honeypot_logs.txt"
BLOCKED_IPS = {}
attempts = {}
MAX_LOGIN_ATTEMPTS = 5
BLOCK_DURATION = timedelta(minutes=2)
SQL_PATTERNS = ["'", "--", " OR ", " AND ", ";", "DROP ", "SELECT "]
GEO_DB = "GeoLite2-City.mmdb"  # Must be in same folder

# ---------------- Helpers ----------------
def log_attack(data):
    try:
        with open(LOG_FILE, "a") as f:
            f.write(data + "\n")
    except Exception as e:
        print(Fore.RED + f"[ERROR] Could not write to log file: {e}")

def get_geo(ip):
    if not os.path.exists(GEO_DB):
        return "Geo-IP DB not found"
    try:
        with geoip2.database.Reader(GEO_DB) as reader:
            response = reader.city(ip)
            city = response.city.name or "Unknown City"
            country = response.country.name or "Unknown Country"
            return f"{city}, {country}"
    except Exception:
        return "Unknown Location"

def unblock_ip_later(ip):
    def unblock():
        if ip in BLOCKED_IPS:
            del BLOCKED_IPS[ip]
            print(Fore.GREEN + f"[INFO] IP {ip} unblocked automatically.")
    timer = threading.Timer(BLOCK_DURATION.total_seconds(), unblock)
    timer.start()

def is_blocked(ip):
    unblock_time = BLOCKED_IPS.get(ip)
    if unblock_time and datetime.now() < unblock_time:
        return True
    elif unblock_time:
        del BLOCKED_IPS[ip]
    return False

def block_ip(ip, reason=""):
    if ip not in BLOCKED_IPS:
        BLOCKED_IPS[ip] = datetime.now() + BLOCK_DURATION
        unblock_ip_later(ip)
        alert = f"[ALERT] {ip} BLOCKED for {BLOCK_DURATION.seconds//60} min! Reason: {reason}"
        log_attack(alert)
        print(Fore.RED + alert)

def generate_dashboard():
    dashboard_file = "dashboard.html"
    if not os.path.exists(LOG_FILE):
        with open(dashboard_file, "w") as f:
            f.write("<h2>No logs yet.</h2>")
        return

    try:
        # Read log file safely
        df = pd.read_csv(LOG_FILE, sep="|", names=["timestamp","ip","event","details"], 
                         engine="python", header=None, dtype=str, on_bad_lines='skip')
    except Exception as e:
        print(Fore.RED + f"[ERROR] Could not read log file: {e}")
        return

    html = """
    <html>
    <head>
        <title>Honeypot Dashboard</title>
        <style>
            table { border-collapse: collapse; width: 100%; }
            th, td { border: 1px solid black; padding: 8px; }
            th { background-color: #f2f2f2; }
            .alert { color: red; font-weight: bold; }
        </style>
    </head>
    <body>
        <h2>Honeypot Logs</h2>
        <table>
            <tr>
                <th>Timestamp</th>
                <th>IP</th>
                <th>Event</th>
                <th>Details</th>
            </tr>
    """
    for _, row in df.iterrows():
        details = str(row["details"]) if pd.notna(row["details"]) else ""
        alert_class = "alert" if any(x in details for x in ["BLOCKED", "SQL Injection", "Brute Force"]) else ""
        html += f"<tr class='{alert_class}'>"
        html += f"<td>{row['timestamp']}</td>"
        html += f"<td>{row['ip']}</td>"
        html += f"<td>{row['event']}</td>"
        html += f"<td>{details}</td>"
        html += "</tr>"
    html += "</table></body></html>"

    with open(dashboard_file, "w") as f:
        f.write(html)
    print(Fore.GREEN + f"[INFO] Dashboard generated: {dashboard_file}")

# ---------------- Routes ----------------
@app.route("/", methods=["GET", "POST"])
def fake_login():
    ip = request.remote_addr

    if is_blocked(ip):
        return Fore.RED + "Access Denied (Temporarily Blocked)"

    if ip not in attempts:
        attempts[ip] = 0

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        attempts[ip] += 1

        geo = get_geo(ip)
        log_data = f"[{datetime.now()}]|{ip}|LOGIN|User:{username} Pass:{password} GEO:{geo}"
        log_attack(log_data)
        print(Fore.YELLOW + "Login Attempt Detected!")
        print(Fore.CYAN + log_data)

        # SQL Injection Detection
        for pattern in SQL_PATTERNS:
            if pattern.lower() in username.lower() or pattern.lower() in password.lower():
                block_ip(ip, reason="SQL Injection Attempt")
                break

        # Brute Force Detection
        if attempts[ip] > MAX_LOGIN_ATTEMPTS:
            block_ip(ip, reason="Brute Force Attempt")

        generate_dashboard()
        return "Invalid Credentials"

    return """
        <h2>Secure Login</h2>
        <form method="POST">
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <input type="submit">
        </form>
    """

# ---------------- Run Server ----------------
if __name__ == "__main__":
    print(Fore.GREEN + "Honeypot Server Running on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000)