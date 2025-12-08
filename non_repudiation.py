from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
import os
import json
from datetime import datetime

def generate_keys(username, keys_dir="./keys", password=None):
    if not password:
        raise ValueError("Password must be provided for key encryption.")

    os.makedirs(keys_dir, exist_ok=True)

    key = RSA.generate(2048)
    private_key_path = os.path.join(keys_dir, f"{username}_private.pem")
    public_key_path = os.path.join(keys_dir, f"{username}_public.pem")

    encrypted_private_key = key.export_key(
        passphrase=password,
        pkcs=8,
        protection="scryptAndAES128-CBC"
    )
    with open(private_key_path, "wb") as f:
        f.write(encrypted_private_key)

    public_key = key.publickey().export_key()
    with open(public_key_path, "wb") as f:
        f.write(public_key)

def reset_keys_force_delete(username, new_password, keys_dir="./keys"):
    """
    WARNING: DELETES old keys and creates brand new ones.
    Any data encrypted with the old keys will be lost forever.
    """
    private_key_path = os.path.join(keys_dir, f"{username}_private.pem")
    public_key_path = os.path.join(keys_dir, f"{username}_public.pem")

    # 1. DELETE the existing files if they exist
    if os.path.exists(private_key_path):
        os.remove(private_key_path)
        print(f"Deleted old private key for {username}")
    
    if os.path.exists(public_key_path):
        os.remove(public_key_path)
        print(f"Deleted old public key for {username}")

    generate_keys(username,keys_dir,new_password)

    print(f"SUCCESS: New keys generated for {username}. Old data is now unrecoverable.")




def get_private_key(username, keys_dir="./keys", password=None):
    private_key_path = os.path.join(keys_dir, f"{username}_private.pem")

    if not os.path.exists(private_key_path):
        raise FileNotFoundError(f" Private key file not found: {private_key_path}")

    with open(private_key_path, "rb") as f:
        encrypted_key_data = f.read()

    try:
        key = RSA.import_key(encrypted_key_data, passphrase=password)
       
        return key
    except ValueError:
        raise ValueError(" Incorrect password or corrupt PEM file.")


def get_public_key(username, keys_dir="./keys"):
    public_key_path = os.path.join(keys_dir, f"{username}_public.pem")

    if not os.path.exists(public_key_path):
        raise FileNotFoundError(f" Public key file not found: {public_key_path}")

    with open(public_key_path, "rb") as f:
        public_key_data = f.read()

    try:
        public_key = RSA.import_key(public_key_data)
        return public_key
    except (ValueError, IndexError):
        raise ValueError(" Failed to load public key. File may be corrupted.")


def sign_message(private_key, message: str,username,sessionId) -> str:
    """Sign a plaintext message using the private key."""
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(private_key).sign(h)
    log_entry = {
        "session":sessionId,
        "sender": username,
        "signature": signature.hex(),
        "timestamp": datetime.utcnow().isoformat()
    }

    # Save log entry (append-only style)
    with open("chat_logs.json", "a") as f:
        f.write(json.dumps(log_entry) + "\n")
    return signature.hex()


def verify_signature(public_key, message: str, signature_hex: str,username,sessionId) -> bool:
    """Verify the digital signature using sender's public key."""
    status="verified"
    try:
        h = SHA256.new(message.encode())
        signature = bytes.fromhex(signature_hex)
        pkcs1_15.new(public_key).verify(h, signature)
        
        
        return True
    except (ValueError, TypeError):
        status="not verified"
        

        
        return False 
    finally:
        log_entry = {
            "session":sessionId,
            "sender": username,
            "status": status,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Save log entry (append-only style)
        with open("chat_logs_verified.json", "a") as f:
            f.write(json.dumps(log_entry) + "\n")
        






