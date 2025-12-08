from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
import os
import secrets
import random
class DiffieHellman:
    def __init__(self, p, g):
        self.p = p
        self.g = g
        # ✅ Cryptographically secure random integer
        self.private_key = secrets.randbelow(p - 2) + 2
        self.public_key = pow(g, self.private_key, p)

    def compute_shared_secret(self, received_public_key):
        return pow(received_public_key, self.private_key, self.p)


def generate_rsa_keypair(meeting_id, base_dir='keys'):
    """
    Generate RSA public-private key pair for a specific meeting.
    
    Parameters:
        meeting_id (str): Unique ID for the meeting
        base_dir (str): Base directory to store the keys

    Returns:
        dict: Paths to the generated private and public key files
    """
    # Directory for this specific meeting
    meeting_dir = os.path.join(base_dir, meeting_id)
    os.makedirs(meeting_dir, exist_ok=True)

    # File paths
    private_key_path = os.path.join(meeting_dir, 'private.pem')
    public_key_path = os.path.join(meeting_dir, 'public.pem')

    # Generate RSA key
    key = RSA.generate(2048)

    # Export private key
    with open(private_key_path, 'wb') as priv_file:
        priv_file.write(key.export_key())

    # Export public key
    with open(public_key_path, 'wb') as pub_file:
        pub_file.write(key.publickey().export_key())

    return {
        'private_key': private_key_path,
        'public_key': public_key_path
    }
from Cryptodome.PublicKey import RSA



def rsa_encrypt_for_meeting(meeting_id, plaintext, base_dir='keys'):
    """
    Encrypt data using the public RSA key for a specific meeting.
    
    Parameters:
        meeting_id (str): Meeting identifier
        plaintext (str): Message to encrypt
        base_dir (str): Base directory where keys are stored

    Returns:
        bytes: Encrypted message (ciphertext)
    """
    public_key_path = os.path.join(base_dir, meeting_id, 'public.pem')

    # Load public key
    with open(public_key_path, 'rb') as pub_file:
        public_key = RSA.import_key(pub_file.read())

    # Create cipher and encrypt
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(plaintext.encode())

    return ciphertext
def rsa_decrypt_for_meeting(meeting_id, ciphertext, base_dir='keys'):
    """
    Decrypt data using the private RSA key for a specific meeting.

    Parameters:
        meeting_id (str): Meeting identifier
        ciphertext (bytes): Encrypted message
        base_dir (str): Base directory where keys are stored

    Returns:
        str: Decrypted plaintext message
    """
    private_key_path = os.path.join(base_dir, meeting_id, 'private.pem')

    # Load private key
    with open(private_key_path, 'rb') as priv_file:
        private_key = RSA.import_key(priv_file.read())

    # Create cipher and decrypt
    cipher = PKCS1_OAEP.new(private_key)
    plaintext = cipher.decrypt(ciphertext)

    return plaintext.decode()


