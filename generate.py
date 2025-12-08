from Cryptodome.PublicKey import RSA
from cryptography.fernet import Fernet

import os

def RSA_generate_and_encrypt_keys(username,meeting_id, keys_dir):
    os.makedirs(keys_dir, exist_ok=True)

    # Step 1: Generate RSA key pair
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    # Step 2: Save public key normally
    with open(os.path.join(keys_dir, f"{meeting_id}{username}_public.pem"), "wb") as pub_file:
        pub_file.write(public_key)
    key_file = "secret.key"
    if not os.path.exists(key_file):
        aes_key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(aes_key)
    else:
        with open(key_file, "rb") as f:
            aes_key = f.read()

    fernet = Fernet(aes_key)

    # Step 4: Encrypt and store private key
    encrypted_private_key = fernet.encrypt(private_key)
    enc_path = os.path.join(keys_dir, f"{meeting_id}{username}_private.pem.enc")
    with open(enc_path, "wb") as f:
        f.write(encrypted_private_key)



def AES_generate_and_encrypt_keys( meeting_id, keys_dir):
    os.makedirs(keys_dir, exist_ok=True)

    # Step 1: Generate a symmetric AES key using Fernet
    symmetric_key = Fernet.generate_key()

    # Step 2: Save symmetric key with identifiable name
    key_filename = f"{meeting_id}.key"
    key_path = os.path.join(keys_dir, key_filename)

    with open(key_path, "wb") as key_file:
        key_file.write(symmetric_key)




    # Step 3: Generate or load Fernet key
    

def AES_encrypt_message(symmetric_key: bytes, plaintext_bytes: bytes) -> str:
    
    fernet = Fernet(symmetric_key)
    encrypted = fernet.encrypt(plaintext_bytes)
    return encrypted.decode()  # Already base64-encoded string

def AES_decrypt_message(symmetric_key: bytes, encrypted_str: str) -> str:
    fernet = Fernet(symmetric_key)
    decrypted = fernet.decrypt(encrypted_str.encode())
    return decrypted.decode()
    

