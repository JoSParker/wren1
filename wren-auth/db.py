import sqlite3

DB_PATH = "wren_auth.db"

def get_conn():
    return sqlite3.connect(DB_PATH)

# Initialize database schema
def init_db():
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE,
        password TEXT,
        credits INTEGER,
        created_at TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS api_keys (
        id TEXT PRIMARY KEY,
        user_id TEXT,
        api_key TEXT,
        active INTEGER,
        created_at TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_events (
        id TEXT PRIMARY KEY,
        user_id TEXT,
        module TEXT,
        severity TEXT,
        action TEXT,
        reason TEXT,
        timestamp TEXT
    )
    """)

    conn.commit()
    conn.close()


# Always initialize tables on import
init_db()