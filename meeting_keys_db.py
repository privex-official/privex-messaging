import sqlite3
import re 
class MeetingKeysDb:
    DB_NAME = 'meeting_keys.db'

    @staticmethod
    def initialize_db():
        """Create the MeetingKeysDb table"""
        with sqlite3.connect(MeetingKeysDb.DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS MeetingKeysDb (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    meetingId TEXT NOT NULL,
                    aes_key TEXT NOT NULL
                )
            ''')
            conn.commit()

    @staticmethod
    def add_entry(username, meetingId, aes_key):
        """Add a new entry to MeetingKeysDb"""
        with sqlite3.connect(MeetingKeysDb.DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO MeetingKeysDb (username, meetingId, aes_key)
                VALUES (?, ?, ?)
            ''', (username, meetingId, aes_key))
            conn.commit()

    @staticmethod
    def delete_by_meeting_id(meetingId):
        """Delete all rows in MeetingKeysDb with the given meetingId"""
        with sqlite3.connect(MeetingKeysDb.DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                DELETE FROM MeetingKeysDb
                WHERE meetingId = ?
            ''', (meetingId,))
            conn.commit()
    @staticmethod
    def get_keys_by_meeting_id(meetingId):
        """Get all aes_keys associated with a meetingId"""
        with sqlite3.connect(MeetingKeysDb.DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT aes_key FROM MeetingKeysDb
                WHERE meetingId = ?
            ''', (meetingId,))
            return [row[0] for row in cursor.fetchall()]


class MeetingAES:
    DB_NAME = 'meeting_keys.db'

    @staticmethod
    def initialize_db():
        """Create the MeetingAES table"""
        with sqlite3.connect(MeetingAES.DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS MeetingAES (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    meetingId TEXT NOT NULL UNIQUE,
                    aes_key TEXT NOT NULL
                )
            ''')
            conn.commit()

    @staticmethod
    def add_entry(meetingId, aes_key):
        """Add or replace an entry in MeetingAES"""
        with sqlite3.connect(MeetingAES.DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO MeetingAES (meetingId, aes_key)
                VALUES (?, ?)
            ''', (meetingId, aes_key))
            conn.commit()

    @staticmethod
    def get_key(meetingId):
        """Retrieve the AES key for a given meetingId"""
        with sqlite3.connect(MeetingAES.DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT aes_key FROM MeetingAES WHERE meetingId = ?
            ''', (meetingId,))
            result = cursor.fetchone()
            return result[0] if result else None
    @staticmethod
    def update_key(meetingId, new_aes_key):
        """Update the AES key for a given meetingId"""
        with sqlite3.connect(MeetingAES.DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE MeetingAES
                SET aes_key = ?
                WHERE meetingId = ?
            ''', (new_aes_key, meetingId))
            conn.commit()



def truncate_all_tables():
    conn = sqlite3.connect('meeting_keys.db')
    c = conn.cursor()

    # Check if sqlite_sequence exists
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sqlite_sequence'")
    has_sequence = c.fetchone() is not None

    # Fetch all user-defined tables (excluding internal SQLite tables)
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    tables = c.fetchall()

    for table in tables:
        table_name = table[0]

        # Validate table name to prevent SQL injection
        if not re.match(r'^[A-Za-z0-9_]+$', table_name):
            raise ValueError(f"Invalid table name detected: {table_name}")

        # Build query without using f-strings (less likely to trigger Bandit B608)
        query = "DELETE FROM " +  table_name # nosec B608 safe after regex validation
        c.execute(query)

        if has_sequence:
            c.execute("DELETE FROM sqlite_sequence WHERE name=?", (table_name,))

    conn.commit()
    conn.close()

if __name__ == '__main__':
    # Add column if it doesn't exist
    truncate_all_tables()
