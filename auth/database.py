# auth/database.py

import sqlite3

DB_PATH = "users.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            security_question TEXT NOT NULL,
            security_answer TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # ✅ NEW — per-user scan history table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            target TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            total INTEGER DEFAULT 0,
            risk_score INTEGER DEFAULT 0,
            risk_label TEXT DEFAULT 'LOW RISK',
            risk_color TEXT DEFAULT '#22c55e',
            vulnerabilities TEXT DEFAULT '[]',
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    conn.commit()
    conn.close()
    print("[✔] Database initialized")


def get_user_by_username(username):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user


def get_user_by_email(email):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    return user


def create_user(username, hashed_password, email, security_question, security_answer):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password, email, security_question, security_answer) VALUES (?, ?, ?, ?, ?)",
            (username, hashed_password, email, security_question, security_answer)
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False


def update_password(username, new_hashed_password):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET password = ? WHERE username = ?",
        (new_hashed_password, username)
    )
    conn.commit()
    conn.close()


# ✅ NEW — save scan for a specific user
def save_scan_for_user(user_id, target, timestamp, total,
                        risk_score, risk_label, risk_color, vulnerabilities):
    import json
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scans
        (user_id, target, timestamp, total, risk_score, risk_label, risk_color, vulnerabilities)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        user_id, target, timestamp, total,
        risk_score, risk_label, risk_color,
        json.dumps(vulnerabilities)
    ))
    conn.commit()
    conn.close()


# ✅ NEW — get all scans for a specific user
def get_scans_for_user(user_id):
    import json
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM scans WHERE user_id = ? ORDER BY id DESC",
        (user_id,)
    )
    rows = cursor.fetchall()
    conn.close()

    scans = []
    for row in rows:
        scans.append({
            "id": row[0],
            "target": row[2],
            "timestamp": row[3],
            "total": row[4],
            "risk_score": row[5],
            "risk_label": row[6],
            "risk_color": row[7],
            "vulnerabilities": json.loads(row[8])
        })
    return scans


# ✅ NEW — get single scan by id (for PDF download)
def get_scan_by_id(scan_id, user_id):
    import json
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM scans WHERE id = ? AND user_id = ?",
        (scan_id, user_id)
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None
    return {
        "id": row[0],
        "target": row[2],
        "timestamp": row[3],
        "total": row[4],
        "risk_score": row[5],
        "risk_label": row[6],
        "risk_color": row[7],
        "vulnerabilities": json.loads(row[8])
    }