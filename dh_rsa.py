import random
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
import base64
import os

# from Crypto.PublicKey import RSA
# from Crypto.Cipher import PKCS1_OAEP
# from Crypto.Signature import pkcs1_15
# from Crypto.Hash import SHA256
# import os
class RSAEncryption:
    def __init__(self):
        self._key = RSA.generate(2048)  # Generate RSA key
        self._private_key = self._key.export_key()
        self.public_key = self._key.publickey().export_key()

    @property
    def private_key(self):
        """Getter for private key"""
        return self._private_key

    @private_key.setter
    def private_key(self, new_key):
        """Setter for private key - Updates RSA key pair"""
        try:
            self._key = RSA.import_key(new_key)
            self._private_key = new_key
            self.public_key = self._key.publickey().export_key()  # Update public key as well
        except ValueError:
            raise ValueError("Invalid RSA Private Key!")

    def encrypt(self, public_key, message):
        recipient_key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(recipient_key)
        return cipher.encrypt(message)

    def decrypt(self, ciphertext,key):
        cipher = PKCS1_OAEP.new(RSA.import_key(key))
        return cipher.decrypt(ciphertext)

    def decrypt_key(self, cipher_text):
        """Decrypts an encrypted key to retrieve the original key."""
        return self.decrypt(cipher_text).decode()
# --- Diffie-Hellman Class ---
class DiffieHellman:
    def __init__(self, p, g):
        self.p = p
        self.g = g
        import secrets
        self.private_key = secrets.randbelow(p - 2) + 2 #!!!!!!!!!!!!!! this may cause issues of the program
        self.public_key = pow(g, self.private_key, p)

    def compute_shared_secret(self, received_public_key):
        return pow(received_public_key, self.private_key, self.p)


def generate_meeting_keys_RSA(meetingID, keys_dir="./keys/meetingRSA/"):
    '''
    Create RSA .pem public and private key files for a given meeting ID.
    '''
    os.makedirs(keys_dir, exist_ok=True)

    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    private_key_path = os.path.join(keys_dir, f"{meetingID}_private_key.pem")
    public_key_path = os.path.join(keys_dir, f"{meetingID}_public_key.pem")

    with open(private_key_path, "wb") as priv_file:
        priv_file.write(private_key)

    with open(public_key_path, "wb") as pub_file:
        pub_file.write(public_key)




def encrypt_with_private_key(key_path):
    '''
    Encrypt a message using RSA private key.
    Returns the base64 encoded encrypted message.
    '''
    message = "ThisIsASecretMessage"

    with open(key_path, 'rb') as f:
        private_key = RSA.import_key(f.read())

    cipher = PKCS1_OAEP.new(private_key)
    encrypted = cipher.encrypt(message.encode())

    return base64.b64encode(encrypted).decode()
def decrypt_with_public_key(key_path):
    '''
    Attempts decryption using the public key (for demonstration),
    and deletes both public & private key files if they are in ./keys/meetingRSA/
    '''
    folder = os.path.dirname(key_path)
    file_name = os.path.basename(key_path)

    if "_public_key.pem" not in file_name:
        raise ValueError("Expected a public key filename ending with '_public_key.pem'")

    meeting_id = file_name.replace("_public_key.pem", "")
    private_key_path = os.path.join(folder, f"{meeting_id}_private_key.pem")

    # Simulate encrypted message
    encrypted = encrypt_with_private_key(private_key_path)

    # Attempt decryption (this will fail if using public key with OAEP encryption)
    with open(key_path, 'rb') as f:
        public_key = RSA.import_key(f.read())

    cipher = PKCS1_OAEP.new(public_key)
    try:
        decrypted = cipher.decrypt(base64.b64decode(encrypted)).decode()
    except ValueError as e:
        decrypted = None

    # Only delete if inside ./keys/meetingRSA/
    abs_folder = os.path.abspath(folder)
    target_dir = os.path.abspath("./keys/meetingRSA/")
    if abs_folder == target_dir:
        for f in [key_path, private_key_path]:
            if os.path.exists(f):
                os.remove(f)
                

    return decrypted

from Cryptodome.Util import number

def generate_dh_parameters(bits=1024):
    if bits % 128 != 0 or bits <= 512:
        raise ValueError("Bits must be a multiple of 128 and > 512")

    q = number.getStrongPrime(bits)
    g = 2  # Generator can be a small prime, commonly 2
    return q, g
def encrypt_message(message, public_key_pem):
    public_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(message.encode())
    return base64.b64encode(encrypted).decode()
def decrypt_message(encrypted_base64, session):
    private_key_pem = session.get("private_key")
    if not private_key_pem:
        raise ValueError("Private key not found in session.")

    private_key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(private_key)

    encrypted_bytes = base64.b64decode(encrypted_base64.encode())
    decrypted = cipher.decrypt(encrypted_bytes).decode()
    return decrypted

def generate_new_difi_key(username,meetingId,P,G):
    host_difi=DiffieHellman(P,G)
    server_difi=DiffieHellman(P,G)
    
    
    host_difi_key=host_difi.compute_shared_secret(server_difi.public_key)
    server_difi_key=server_difi.compute_shared_secret(host_difi.public_key)
    
    return host_difi_key,server_difi_key




if __name__ =='__main__':
    meetingID='qwe-2es-hu2'
    host=DiffieHellman(13,2)
    server=DiffieHellman(13,2)
    
    
    
