from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
import base64
import os
from cryptography.fernet import Fernet  # ADD this

class Etoe:
    KEYS_DIR = "C:/Users/ACER/OneDrive/Desktop/projectInternShip/EtoE/keys"
    os.makedirs(KEYS_DIR, exist_ok=True)
   
    @staticmethod
    def get_public_key(username,meeting_id):
        path = os.path.join(Etoe.KEYS_DIR, f"{meeting_id}{username}_public.pem")
        with open(path, "rb") as f:
            public_key = RSA.import_key(f.read())
            return public_key

    @staticmethod
    def get_private_key(username,meeting_id):
        key_path = "secret.key"
        enc_pem_path = os.path.join(Etoe.KEYS_DIR, f"{meeting_id}{username}_private.pem.enc")

        with open(key_path, "rb") as f:
            fernet_key = f.read()
        fernet = Fernet(fernet_key)

        with open(enc_pem_path, "rb") as enc_file:
            encrypted_data = enc_file.read()
            decrypted = fernet.decrypt(encrypted_data)

        return RSA.import_key(decrypted)

    @staticmethod
    def encrypt_message(symmetric_key: bytes, plaintext_bytes: bytes) -> str:
        """Encrypt a message using Fernet (AES symmetric encryption)."""
        fernet = Fernet(symmetric_key)
        encrypted = fernet.encrypt(plaintext_bytes)
        return encrypted.decode()  # Already base64-encoded string

    @staticmethod
    def decrypt_message(symmetric_key: bytes, encrypted_str: str) -> str:
        """Decrypt a message using Fernet (AES symmetric encryption)."""
        fernet = Fernet(symmetric_key)
        decrypted = fernet.decrypt(encrypted_str.encode())
        return decrypted.decode()

    @staticmethod
    def sign_message(private_key, message: str) -> str:
        """Sign a plaintext message using private key."""
        h = SHA256.new(message.encode())
        signature = pkcs1_15.new(private_key).sign(h)
        return signature.hex()

    @staticmethod
    def verify_signature(public_key, message: str, signature_hex: str) -> bool:
        """Verify the digital signature using sender's public key."""
        try:
            h = SHA256.new(message.encode())
            signature = bytes.fromhex(signature_hex)
            pkcs1_15.new(public_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

