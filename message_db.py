import sqlite3
from datetime import datetime, timedelta, timezone

DB_PATH = 'data.db'

class MessageDB:
    @staticmethod
    def init(cursor):
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS Messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                meetingId TEXT NOT NULL,
                username TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp DATETIME,  -- Allow manual timestamp insertion
                isPinned INTEGER DEFAULT 0,
                editedAt DATETIME
            )
        ''')

    @staticmethod
    def add_message(meetingId, username, message):
        # Define IST timezone
        ist = timezone(timedelta(hours=5, minutes=30))
        ist_now = datetime.now(ist).strftime('%Y-%m-%d %H:%M:%S')

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('INSERT INTO Messages (meetingId, username, message, timestamp) VALUES (?, ?, ?, ?)',
                  (meetingId, username, message, ist_now))
        conn.commit()
        conn.close()

    @staticmethod
    def get_messages(meetingId):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''
            SELECT username, message,
                   strftime("%H:%M", timestamp),
                   strftime("%d:%m", timestamp),
                   id
            FROM Messages
            WHERE meetingId = ?
            ORDER BY timestamp ASC
        ''', (meetingId,))
        messages = c.fetchall()
        conn.close()
        return messages

    @staticmethod
    def edit_message(message_id, new_text):
        ist = timezone(timedelta(hours=5, minutes=30))
        ist_now = datetime.now(ist).strftime('%Y-%m-%d %H:%M:%S')

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''
            UPDATE Messages
            SET message = ?, editedAt = ?
            WHERE id = ?
        ''', (new_text, ist_now, message_id))
        conn.commit()
        conn.close()

    @staticmethod
    def delete_message(message_id):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('DELETE FROM Messages WHERE id = ?', (message_id,))
        conn.commit()
        conn.close()
    @staticmethod
    def find_message_id(meetingId, username, timestamp):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''
            SELECT id FROM Messages
            WHERE meetingId = ? AND username = ? AND timestamp = ?
        ''', (meetingId, username, timestamp))
        result = c.fetchone()
        conn.close()
        return result[0] if result else None
    @staticmethod
    def pin_message(message_id):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('UPDATE Messages SET isPinned = 0 WHERE isPinned = 1')
        c.execute('UPDATE Messages SET isPinned = 1 WHERE id = ?', (message_id,))
        conn.commit()
        conn.close()
    @staticmethod
    def delete_messages_by_meeting(meetingId):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('DELETE FROM Messages WHERE meetingId = ?', (meetingId,))
        conn.commit()
        conn.close()
    @staticmethod
    def get_messages_grouped_by_date(meetingId):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''
            SELECT username, message,
                   strftime("%H:%M", timestamp) as time_only,
                   strftime("%d:%m", timestamp) as date_only,
                   id
            FROM Messages
            WHERE meetingId = ?
            ORDER BY timestamp ASC
        ''', (meetingId,))
        rows = c.fetchall()
        conn.close()

        # Group messages by date
        grouped_messages = {}
        for username, message, time_only, date_only, msg_id in rows:
            msg_obj = {
                "id": msg_id,
                "username": username,
                "message": message,
                "time": time_only
            }
            if date_only not in grouped_messages:
                grouped_messages[date_only] = []
            grouped_messages[date_only].append(msg_obj)

        return grouped_messages

    

SAFE_TABLES = []

def truncate_all_tables():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Get only safe, non-internal tables
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    for (name,) in c.fetchall():
        SAFE_TABLES.append(name)

    # Check if sqlite_sequence exists
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sqlite_sequence'")
    has_sequence = c.fetchone() is not None

    # ✅ Prebuild queries outside runtime SQL execution
    for table_name in SAFE_TABLES:
        print(f"Truncating table: {table_name}")
        if table_name == "users":
            c.execute("DELETE FROM users")
        elif table_name == "messages":
            c.execute("DELETE FROM messages")
        elif table_name == "groups":
            c.execute("DELETE FROM groups")
        # ... add more allowed tables here

        if has_sequence:
            c.execute("DELETE FROM sqlite_sequence WHERE name=?", (table_name,))

    conn.commit()
    conn.close()
    print("✅ All tables truncated.")

if __name__ == '__main__':
    # Add column if it doesn't exist
    truncate_all_tables()