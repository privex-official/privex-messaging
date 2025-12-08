import sqlite3
from datetime import datetime, UTC
from message_db import MessageDB
from todo_db import TaskDB
DB_PATH = "meetings.db"
from dh_rsa import RSAEncryption
# ----------------- User Table ----------------- #
class UserDB:
    @staticmethod
    def init(cursor):
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS User (
                userId TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')

    
    
    
    @staticmethod
    def email_exists(email):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT 1 FROM User WHERE email = ?', (email,))
        result = c.fetchone()
        conn.close()
        return result is not None
    @staticmethod
    def add_user(user_id, name, email, password):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Check if email already exists
        c.execute("SELECT 1 FROM User WHERE email = ?", (email,))
        if c.fetchone():
            print(f"User with email {email} already exists.")
            conn.close()
            return -1  # duplicate email

        # Check if userId already exists
        c.execute("SELECT 1 FROM User WHERE userId = ?", (user_id,))
        if c.fetchone():
            print(f"User with userId {user_id} already exists.")
            conn.close()
            return -2  # duplicate userId

        # Safe insert
        c.execute(
            'INSERT INTO User (userId, name, email, password) VALUES (?, ?, ?, ?)',
            (user_id, name, email, password)
        )
        conn.commit()
        conn.close()
        return 1  

    @staticmethod
    def get_all_users():
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM User")
        rows = c.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    @staticmethod
    def user_exists(user_id):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT 1 FROM User WHERE userId = ?', (user_id,))
        result = c.fetchone()
        conn.close()
        return result is not None
    @staticmethod
    def get_password(user_id):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT password FROM User WHERE userId = ?', (user_id,))
        result = c.fetchone()
        conn.close()
        return result[0] if result else None
    @staticmethod
    def get_email(user_id):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT email FROM User WHERE userId = ?', (user_id,))
        result = c.fetchone()
        conn.close()
        return result[0] if result else None
    
    
    @staticmethod
    def get_userid_by_email(email):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT userId FROM User WHERE email = ?', (email,))
        result = c.fetchone()
        conn.close()
        return result[0] if result else None

    @staticmethod
    def update_password(user_id, new_password):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('UPDATE User SET password = ? WHERE userId = ?', (new_password, user_id))
        conn.commit()
        conn.close()


# ----------------- Meeting Table ----------------- #
class MeetingDB:
    @staticmethod
    def init(cursor):
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS meetings (
                meeting_id TEXT PRIMARY KEY,
                passkey TEXT NOT NULL,
                host TEXT,
                co_host TEXT,
                meetingTitle TEXT,
                meetingDescription TEXT
            )
        ''')

    @staticmethod
    def add_meeting(meeting_id, passkey, host=None, co_host=None, meetingTitle=None, meetingDescription=None):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        try:
            c.execute('''
                INSERT INTO meetings (meeting_id, passkey, host, co_host, meetingTitle, meetingDescription)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (meeting_id, passkey, host, co_host, meetingTitle, meetingDescription))
            conn.commit()
        except sqlite3.IntegrityError as e:
            pass
        conn.close()

    @staticmethod
    def meeting_exists(meeting_id):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT 1 FROM meetings WHERE meeting_id = ?', (meeting_id,))
        result = c.fetchone()
        conn.close()
        return result is not None

    @staticmethod
    def get_passkey(meeting_id):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT passkey FROM meetings WHERE meeting_id = ?', (meeting_id,))
        result = c.fetchone()
        conn.close()
        return result[0] if result else None

    @staticmethod
    def update_host(meeting_id, new_host):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('UPDATE meetings SET host = ? WHERE meeting_id = ?', (new_host, meeting_id))
        conn.commit()
        conn.close()

    @staticmethod
    def update_co_host(meeting_id, new_co_host):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('UPDATE meetings SET co_host = ? WHERE meeting_id = ?', (new_co_host, meeting_id))
        conn.commit()
        conn.close()

    @staticmethod
    def delete_meeting(meeting_id):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('DELETE FROM meetings WHERE meeting_id = ?', (meeting_id,))
        
        conn.commit()
        conn.close()

    @staticmethod
    def get_host(meeting_id):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT host FROM meetings WHERE meeting_id = ?', (meeting_id,))
        result = c.fetchone()
        conn.close()
        return result[0] if result else None

    @staticmethod
    def getMeetingTitle(meeting_id):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT meetingTitle FROM meetings WHERE meeting_id = ?', (meeting_id,))
        result = c.fetchone()
        conn.close()
        return result[0] if result else None

    @staticmethod
    def getMeetingDescription(meeting_id):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT meetingDescription FROM meetings WHERE meeting_id = ?', (meeting_id,))
        result = c.fetchone()
        conn.close()
        return result[0] if result else None
    @staticmethod
    def get_title_by_id(meeting_id):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT meetingTitle FROM meetings WHERE meeting_id = ?', (meeting_id,))
        result = c.fetchone()
        conn.close()
        return result[0] if result else None
    @staticmethod
    def get_all_distinct_meeting_ids():
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT DISTINCT meeting_id FROM meetings')
        result = c.fetchall()
        conn.close()
        return [row[0] for row in result]
    @staticmethod
    def set_co_host(meeting_id, co_host):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('UPDATE meetings SET co_host = ? WHERE meeting_id = ?', (co_host, meeting_id))
        conn.commit()
        conn.close()

    @staticmethod
    def get_co_host(meeting_id):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT co_host FROM meetings WHERE meeting_id = ?', (meeting_id,))
        result = c.fetchone()
        conn.close()
        return result[0] if result else None
    @staticmethod
    def delete_meeting_by_id(meeting_id):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('DELETE FROM meetings WHERE meeting_id = ?', (meeting_id,))
        conn.commit()
        conn.close()
        # ----------------- UserMeeting Table ----------------- #
class UserMeetingDB:
    @staticmethod
    def init(cursor):
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS userMeetings (
                userId TEXT NOT NULL,
                meetingId TEXT NOT NULL,
                isLive INTEGER DEFAULT 1,
                isBlocked INTEGER DEFAULT 0,
                difi_sharekey TEXT,
                private_key TEXT,
                public_key TEXT,
                FOREIGN KEY (userId) REFERENCES User(userId),
                FOREIGN KEY (meetingId) REFERENCES meetings(meeting_id)
            )
        ''')

    @staticmethod
    def add_user_to_meeting(user_id, meeting_id, isLive=1, isBlocked=0, difi_sharekey=None, private_key=None, public_key=None):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        # Check if this user-meeting pair already exists
        c.execute('''
            SELECT 1 FROM userMeetings WHERE userId = ? AND meetingId = ?
        ''', (user_id, meeting_id))
        if c.fetchone():
            conn.close()
            return -1  # Already exists

        try:
            c.execute('''
                INSERT INTO userMeetings (userId, meetingId, isLive, isBlocked, difi_sharekey, private_key, public_key)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (user_id, meeting_id, isLive, isBlocked, difi_sharekey, private_key, public_key))
            conn.commit()
        except sqlite3.IntegrityError as e:
            pass
        finally:
            conn.close()


    @staticmethod
    def get_meetings_for_user(user_id):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''
            SELECT meetingId FROM userMeetings
            WHERE userId = ?
            ORDER BY datetime(last_interaction) DESC
        ''', (user_id,))
        result = c.fetchall()
        conn.close()
        return [row[0] for row in result]


    @staticmethod
    def get_users_for_meeting(meeting_id):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT userId FROM userMeetings WHERE meetingId = ?', (meeting_id,))
        result = c.fetchall()
        conn.close()
        return [row[0] for row in result]

    @staticmethod
    def get_is_blocked(user_id, meeting_id):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT isBlocked FROM userMeetings WHERE userId = ? AND meetingId = ?', (user_id, meeting_id))
        result = c.fetchone()
        conn.close()
        return result[0] if result else None


    @staticmethod
    def get_blocked_users():
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT userId, meetingId FROM userMeetings WHERE isBlocked = 1')
        result = c.fetchall()
        conn.close()
        return [{'userId': row[0], 'meetingId': row[1]} for row in result]
    @staticmethod
    def update_block_status_and_key(meeting_id, username, isBlocked, difi_sharekey):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            UPDATE userMeetings
            SET isBlocked = ?, difi_sharekey = ?
            WHERE meetingId = ? AND userId = ?
        """, (isBlocked, difi_sharekey, meeting_id, username))

        conn.commit()
        conn.close()
    @staticmethod
    def get_all_meeting_ids():
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT DISTINCT meetingId FROM userMeetings')
        result = c.fetchall()
        conn.close()
        return [row[0] for row in result]
    @staticmethod
    def delete_all_by_meeting_id(meeting_id):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('DELETE FROM userMeetings WHERE meetingId = ?', (meeting_id,))
        conn.commit()
        conn.close()
    @staticmethod
    def delete_all_by_user_id(user_id):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('DELETE FROM userMeetings WHERE userId = ?', (user_id,))
        conn.commit()
        conn.close()
    @staticmethod
    def get_member_count(meeting_id):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM userMeetings WHERE meetingId = ?', (meeting_id,))
        result = c.fetchone()
        conn.close()
        return result[0] if result else 0
        # ----------------- Init Function ----------------- #

    @staticmethod
    def toggle_block_and_update_key(user_id, meeting_id, new_key,ob,private_key):
        
        rsa = RSAEncryption()
        decrypted_crk = rsa.decrypt(new_key, private_key)  # Decrypt the message
        new_key=ob.compute_shared_secret(int(decrypted_crk))
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        try:
            # 1. Get current isBlocked status of the selected user
            c.execute('''
                SELECT isBlocked FROM userMeetings
                WHERE userId = ? AND meetingId = ?
            ''', (user_id, meeting_id))
            result = c.fetchone()

            if not result:
                
                return

            current_status = result[0]
            new_status = 0 if current_status == 1 else 1

            # 2. Toggle the selected user's isBlocked status
            c.execute('''
                UPDATE userMeetings
                SET isBlocked = ?
                WHERE userId = ? AND meetingId = ?
            ''', (new_status, user_id, meeting_id))

            # 3. Change difi_sharekey of all unblocked users in that meeting
            c.execute('''
                UPDATE userMeetings
                SET difi_sharekey = ?
                WHERE meetingId = ? AND isBlocked = 0
            ''', (new_key, meeting_id))

            conn.commit()

        except sqlite3.Error as e:
            pass
        finally:
            conn.close()

    @staticmethod
    def update_difi_key(user_id, meeting_id, new_difi_key,ob,private_key):
        rsa = RSAEncryption()
        decrypted_crk = rsa.decrypt(new_difi_key, private_key)  # Decrypt the message
        new_difi_key=ob.compute_shared_secret(int(decrypted_crk))
       
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        try:
            c.execute('''
                UPDATE userMeetings
                SET difi_sharekey = ?
                WHERE userId = ? AND meetingId = ?
            ''', (new_difi_key, user_id, meeting_id))
            
           

            conn.commit()
        except sqlite3.Error as e:
            pass
        finally:
            conn.close()
    @staticmethod
    def get_difi_key(user_id, meeting_id):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        try:
            c.execute('''
                SELECT difi_sharekey FROM userMeetings
                WHERE userId = ? AND meetingId = ?
            ''', (user_id, meeting_id))
            result = c.fetchone()
            if result:
                return result[0]  # Return the difi_sharekey
            else:
                
                return None
        except sqlite3.Error as e:
           
            return None
        finally:
            conn.close()


    @staticmethod
    def update_sharekey_for_unblocked_users(user_id, meeting_id, new_sharekey):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        try:
            # Check if the passed user is unblocked
            c.execute('''
                SELECT isBlocked FROM userMeetings WHERE userId = ? AND meetingId = ?
            ''', (user_id, meeting_id))
            result = c.fetchone()

            if result is None:
               
                return

            is_blocked = result[0]

            # Update sharekey for the passed user ONLY if unblocked
            if is_blocked == 0:
                c.execute('''
                    UPDATE userMeetings
                    SET difi_sharekey = ?
                    WHERE userId = ? AND meetingId = ?
                ''', (new_sharekey, user_id, meeting_id))
               

            # Update difi_sharekey for all other unblocked users in the same meeting
            c.execute('''
                UPDATE userMeetings
                SET difi_sharekey = ?
                WHERE meetingId = ? AND isBlocked = 0 AND userId != ?
            ''', (new_sharekey, meeting_id, user_id))
           

            conn.commit()

        except sqlite3.Error as e:
            pass
        finally:
            conn.close()
    @staticmethod
    def add_last_interaction_column():
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        try:
            c.execute('''
                ALTER TABLE userMeetings ADD COLUMN last_interaction TEXT
            ''')
        except sqlite3.OperationalError:
            # Column may already exist
            pass
        conn.commit()
        conn.close()

    @staticmethod
    def update_last_interaction(user_id, meeting_id):
        now = datetime.now(UTC).isoformat()
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''
            UPDATE userMeetings SET last_interaction = ?
            WHERE userId = ? AND meetingId = ?
        ''', (now, user_id, meeting_id))
        conn.commit()
        conn.close()
    @staticmethod
    def get_meetings_sorted_by_last_interaction(user_id):
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('''
            SELECT meetingId, last_interaction FROM userMeetings
            WHERE userId = ?
            ORDER BY last_interaction DESC
        ''', (user_id,))
        results = c.fetchall()
        conn.close()
        return [dict(row) for row in results]




def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    UserDB.init(c)
    MeetingDB.init(c)
    UserMeetingDB.init(c)
    conn.commit()
    conn.close()

class UserProfileDB:
    @staticmethod
    def init(cursor):
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS UserProfile (
                profileId INTEGER PRIMARY KEY AUTOINCREMENT,
                userId TEXT NOT NULL,
                contact TEXT,
                description TEXT,
                github TEXT,
                linkedin TEXT,
                FOREIGN KEY (userId) REFERENCES User(userId) ON DELETE CASCADE
            )
        ''')

    @staticmethod
    def add_or_update_profile(user_id, contact=None, description=None, github=None, linkedin=None):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Check if profile exists
        c.execute('SELECT 1 FROM UserProfile WHERE userId = ?', (user_id,))
        exists = c.fetchone()

        if exists:
            c.execute('''
                UPDATE UserProfile
                SET contact = ?, description = ?, github = ?, linkedin = ?
                WHERE userId = ?
            ''', (contact, description, github, linkedin, user_id))
        else:
            c.execute('''
                INSERT INTO UserProfile (userId, contact, description, github, linkedin)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, contact, description, github, linkedin))

        conn.commit()
        conn.close()

    @staticmethod
    def get_profile(user_id):
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('SELECT * FROM UserProfile WHERE userId = ?', (user_id,))
        row = c.fetchone()
        conn.close()
        return dict(row) if row else None



import re

def truncate_all_tables():
    conn = sqlite3.connect("meetings.db")
    c = conn.cursor()

    # Check if sqlite_sequence exists
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sqlite_sequence'")
    has_sequence = c.fetchone() is not None

    # Fetch all user-defined tables (excluding internal SQLite tables)
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    tables = c.fetchall()

    valid_name_pattern = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")  # only safe identifiers

    for table in tables:
        table_name = table[0]

        # Validate table name
        if not valid_name_pattern.match(table_name):
            raise ValueError(f"Invalid table name detected: {table_name}")

        # Safely quote the table name
        safe_table_name = f'"{table_name}"'

        # Delete table contents
        c.execute(f"DELETE FROM {safe_table_name}")  # nosec B608


        if has_sequence:
            # Reset autoincrement safely
            c.execute("DELETE FROM sqlite_sequence WHERE name=?", (table_name,))

    conn.commit()
    conn.close()



if __name__ == "__main__":
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM User")
    # c.execute("delete from User where userId= ?",("admin1",))
    conn.commit()
    conn.close()