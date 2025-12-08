import secrets
import string
from config import *
from meeting_db import *

def meeting_id_create() -> str:
    CURRENT_RUNNING_MEETINGS = MeetingDB.get_all_distinct_meeting_ids()

    def generate_random_id():
        chars = string.ascii_lowercase + string.digits
        parts = [''.join(secrets.choice(chars) for _ in range(3)) for _ in range(3)]
        return '-'.join(parts)

    while True:
        meeting_id = generate_random_id()
        if meeting_id not in CURRENT_RUNNING_MEETINGS:
            CURRENT_RUNNING_MEETINGS.append(meeting_id)
            return meeting_id

def meeting_pass_key():
    # Generates a 6-digit secure passkey
    return secrets.randbelow(999999 - 111111 + 1) + 111111
