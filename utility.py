from cryptography.fernet import Fernet, MultiFernet
from meeting_keys_db import MeetingKeysDb, MeetingAES
from meeting_db import *
class E2E:
    def __init__(self):
        pass

    def create_AES_keys_for_users(self, users, meetingId):
        for user in users:
            key = Fernet.generate_key().decode()  # store as str
            MeetingKeysDb.add_entry(user, meetingId, key)

    def get_master_key(self, meetingId) -> MultiFernet:
        keys = MeetingKeysDb.get_keys_by_meeting_id(meetingId)
        keys = [Fernet(key.encode()) for key in keys]
        return MultiFernet(keys)

    def set_Aes_key(self, meetingId):
        # generate AES key and encrypt using MultiFernet
        plain_key = Fernet.generate_key()
        master_key = self.get_master_key(meetingId)
        encrypted_key = master_key.encrypt(plain_key)
        MeetingAES.add_entry(meetingId, encrypted_key.decode())  # save as str

    def format_key(self, meetingId, users):
        # retrieve encrypted key and decrypt it
        encrypted_key = MeetingAES.get_key(meetingId).encode()
        master_key = self.get_master_key(meetingId)
        decrypted_key = master_key.decrypt(encrypted_key)

        # rotate keys
        self.rotate_keys(meetingId, users)

        # re-encrypt the same key with new MultiFernet
        new_master_key = self.get_master_key(meetingId)
        re_encrypted_key = new_master_key.encrypt(decrypted_key)
        MeetingAES.update_key(meetingId, re_encrypted_key.decode())

    def encrypt(self, msg: bytes, meetingId) -> str:
        encrypted_key = MeetingAES.get_key(meetingId).encode()
        master_key = self.get_master_key(meetingId)
        actual_key = master_key.decrypt(encrypted_key)
        fernet = Fernet(actual_key)
        return fernet.encrypt(msg).decode()

    def decrypt(self, token: str, meetingId) -> bytes:
        encrypted_key = MeetingAES.get_key(meetingId).encode()
        master_key = self.get_master_key(meetingId)
        actual_key = master_key.decrypt(encrypted_key)
        fernet = Fernet(actual_key)
        return fernet.decrypt(token.encode())

    def rotate_keys(self, meetingId, users):
        MeetingKeysDb.delete_by_meeting_id(meetingId)
        self.create_AES_keys_for_users(users, meetingId)


if __name__== '__main__':
    e2e = E2E()
    meeting_id='du2-w90-pcx'
    users = UserMeetingDB.get_users_for_meeting('du2-w90-pcx')
    e2e.format_key(meeting_id,users)


    encrypted = e2e.encrypt(b"Hello World!", meeting_id)


    decrypted = e2e.decrypt(encrypted, meeting_id)



