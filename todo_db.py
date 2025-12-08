import sqlite3

DB_PATH = 'todo.db'

class TaskDB:
    @staticmethod
    def init(cursor):
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS Tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                meetingId TEXT NOT NULL,
                hostedBy TEXT NOT NULL,
                assignedTo TEXT NOT NULL,
                taskName TEXT NOT NULL,
                uploadRequired INTEGER NOT NULL,
                comment TEXT,
                deadline DATETIME,
                isDone INTEGER DEFAULT 0
            )
        ''')

    @staticmethod
    def add_task(meetingId, hostedBy, assignedTo, taskName, uploadRequired, comment, deadline=None, isDone=False):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        TaskDB.init(c)
        c.execute('''
            INSERT INTO Tasks (meetingId, hostedBy, assignedTo, taskName, uploadRequired, comment, deadline, isDone)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (meetingId, hostedBy, assignedTo, taskName, int(uploadRequired), comment, deadline, int(isDone)))
        conn.commit()
        conn.close()
    @staticmethod
    def get_hosted_by(task_id):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT hostedBy FROM Tasks WHERE id = ?', (task_id,))
        result = c.fetchone()
        conn.close()
        return result[0] if result else None
    @staticmethod
    def get_all_tasks():
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT * FROM Tasks ORDER BY deadline ASC')
        tasks = c.fetchall()
        conn.close()
        return tasks

    @staticmethod
    def get_tasks_for_meeting(meeting_id):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''
            SELECT * FROM Tasks
            WHERE meetingId = ?
            ORDER BY deadline ASC
        ''', (meeting_id,))
        tasks = c.fetchall()
        conn.close()
        return tasks

    @staticmethod
    def get_meetings_for_task(task_name):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''
            SELECT DISTINCT meetingId FROM Tasks
            WHERE taskName = ?
        ''', (task_name,))
        meetings = c.fetchall()
        conn.close()
        return [row[0] for row in meetings]

    @staticmethod
    def get_tasks_assigned_by(hosted_by):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''
            SELECT * FROM Tasks
            WHERE hostedBy = ?
            ORDER BY deadline ASC
        ''', (hosted_by,))
        tasks = c.fetchall()
        conn.close()
        return tasks

    @staticmethod
    def get_deadline(task_id):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT deadline FROM Tasks WHERE id = ?', (task_id,))
        result = c.fetchone()
        conn.close()
        return result[0] if result else None

    @staticmethod
    def update_deadline(task_id, new_deadline):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''
            UPDATE Tasks
            SET deadline = ?
            WHERE id = ?
        ''', (new_deadline, task_id))
        conn.commit()
        conn.close()

    @staticmethod
    def get_is_done(task_id):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT isDone FROM Tasks WHERE id = ?', (task_id,))
        result = c.fetchone()
        conn.close()
        return bool(result[0]) if result else None

    @staticmethod
    def mark_done(task_id, done=True):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('UPDATE Tasks SET isDone = ? WHERE id = ?', (int(done), task_id))
        conn.commit()
        conn.close()
    @staticmethod
    def delete_task(task_id):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('DELETE FROM Tasks WHERE id = ?', (task_id,))
        conn.commit()
        conn.close()

    @staticmethod
    def update_task(task_id, **kwargs):
        if not kwargs:
            return

        allowed_fields = ['taskName', 'assignedTo', 'comment', 'deadline', 'uploadRequired', 'isDone']
        fields = []
        values = []

        for key, value in kwargs.items():
            if key in allowed_fields:
                fields.append(f"{key} = ?")
                values.append(int(value) if key in ['uploadRequired', 'isDone'] else value)

        if not fields:
            return

        set_clause = ", ".join(fields)
        values.append(task_id)

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        allowed_fields = ['taskName', 'assignedTo', 'comment', 'deadline', 'uploadRequired', 'isDone']
        if not all(field.split(" = ")[0] in allowed_fields for field in fields):
            raise ValueError("Invalid field name detected.")
        sql = "UPDATE Tasks SET " + ", ".join(fields) + " WHERE id = ?"  # nosec B608 — field names validated
        c.execute(sql, values)

        conn.commit()
        conn.close()
    @staticmethod
    def get_task_by_id(task_id):
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('SELECT * FROM Tasks WHERE id = ?', (task_id,))
        row = c.fetchone()
        conn.close()
        return dict(row) if row else None
    @staticmethod
    def delete_tasks_for_meeting(meeting_id):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('DELETE FROM Tasks WHERE meetingId = ?', (meeting_id,))
        conn.commit()
        conn.close()
    


# Optional: Initialize table
def initialize_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    TaskDB.init(c)
    conn.commit()
    conn.close()
    

def truncate_all_tables():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Check if sqlite_sequence exists
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sqlite_sequence'")
    has_sequence = c.fetchone() is not None

    # Fetch all user-defined tables (excluding internal SQLite tables)
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    tables = c.fetchall()

    for table in tables:
        table_name = table[0]
        
       # Ensure table name is safe
        if not table_name.isidentifier():
            raise ValueError("Invalid table name.")

        c.execute(f'DELETE FROM "{table_name}"')  # nosec B608 — table name validated as identifier
        if has_sequence:
            c.execute('DELETE FROM sqlite_sequence WHERE name=?', (table_name,))


    conn.commit()
    conn.close()
 

if __name__ == '__main__':
    # Add column if it doesn't exist
    truncate_all_tables()
