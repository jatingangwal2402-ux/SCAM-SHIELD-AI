"""
database.py - SQLite storage for ScamShield AI.

Tables
------
reported_numbers : phone numbers reported as scam (sample data + user reports)
history          : every check the user runs
"""
import os
import sqlite3
from datetime import datetime

# On Vercel the project folder is read-only; only /tmp is writable (and it is temporary).
if os.environ.get("VERCEL"):
    DB_PATH = "/tmp/scamshield.db"
else:
    DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scamshield.db")

# Dummy sample data for demo/testing only. These are NOT real people's numbers.
SAMPLE_REPORTS = [
    ("9000000001", 14, "Digital Arrest / Fake Police Scam"),
    ("9000000002", 7, "KYC / Bank Account Block Scam"),
    ("9000000003", 5, "Fake Job / Part-time Task Scam"),
    ("9000000004", 3, "Lottery / Prize Scam"),
    ("9000000005", 11, "OTP / PIN / Password Theft"),
    ("9000000006", 2, "Fake Courier / Customs Scam"),
    ("9000000007", 1, "Electricity Bill Disconnection Scam"),
]


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables and insert sample data the first time."""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """CREATE TABLE IF NOT EXISTS reported_numbers (
               number        TEXT PRIMARY KEY,
               reports       INTEGER NOT NULL DEFAULT 1,
               scam_type     TEXT,
               last_reported TEXT
           )"""
    )
    cur.execute(
        """CREATE TABLE IF NOT EXISTS history (
               id         INTEGER PRIMARY KEY AUTOINCREMENT,
               kind       TEXT NOT NULL,
               input_text TEXT NOT NULL,
               score      INTEGER NOT NULL,
               level      TEXT NOT NULL,
               scam_type  TEXT,
               created_at TEXT NOT NULL
           )"""
    )
    if cur.execute("SELECT COUNT(*) FROM reported_numbers").fetchone()[0] == 0:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cur.executemany(
            "INSERT INTO reported_numbers (number, reports, scam_type, last_reported) VALUES (?,?,?,?)",
            [(n, r, t, now) for n, r, t in SAMPLE_REPORTS],
        )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------- numbers
def lookup_number(number):
    conn = get_conn()
    row = conn.execute(
        "SELECT number, reports, scam_type, last_reported FROM reported_numbers WHERE number = ?",
        (number,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def report_number(number, scam_type="Unknown"):
    """Add a report. Creates the row or increases the report count."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_conn()
    cur = conn.cursor()
    row = cur.execute("SELECT reports FROM reported_numbers WHERE number = ?", (number,)).fetchone()
    if row:
        cur.execute(
            "UPDATE reported_numbers SET reports = reports + 1, last_reported = ?, "
            "scam_type = COALESCE(NULLIF(?, 'Unknown'), scam_type) WHERE number = ?",
            (now, scam_type, number),
        )
    else:
        cur.execute(
            "INSERT INTO reported_numbers (number, reports, scam_type, last_reported) VALUES (?,?,?,?)",
            (number, 1, scam_type, now),
        )
    conn.commit()
    total = cur.execute("SELECT reports FROM reported_numbers WHERE number = ?", (number,)).fetchone()[0]
    conn.close()
    return total


# ---------------------------------------------------------------- history
def add_history(kind, input_text, score, level, scam_type=None):
    conn = get_conn()
    conn.execute(
        "INSERT INTO history (kind, input_text, score, level, scam_type, created_at) VALUES (?,?,?,?,?,?)",
        (kind, input_text[:500], score, level, scam_type, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    )
    conn.commit()
    conn.close()


def get_history(limit=50):
    conn = get_conn()
    rows = conn.execute(
        "SELECT id, kind, input_text, score, level, scam_type, created_at "
        "FROM history ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def clear_history():
    conn = get_conn()
    conn.execute("DELETE FROM history")
    conn.commit()
    conn.close()
