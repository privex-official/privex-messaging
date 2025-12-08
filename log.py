import logging
import json
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from datetime import datetime

# Generate keys (in real app, each user has their own keys)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

def sign_message(sender, message):
    # Hash the message
    msg_hash = hashlib.sha256(message.encode()).hexdigest()

    # Create digital signature
    signature = private_key.sign(
        msg_hash.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

    # Build log entry
    log_entry = {
        "sender": sender,
        "message_hash": msg_hash,
        "signature": signature.hex(),
        "timestamp": datetime.utcnow().isoformat()
    }

    # Save log entry (append-only style)
    with open("chat_logs.json", "a") as f:
        f.write(json.dumps(log_entry) + "\n")

    return log_entry

def verify_message(message, signature):
    msg_hash = hashlib.sha256(message.encode()).hexdigest()
    try:
        public_key.verify(
            bytes.fromhex(signature),
            msg_hash.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# Example usage
entry = sign_message("user123", "Hello, secure world!")
print("Log saved:", entry)

valid = verify_message("Hello, secure world!", entry["signature"])
print("Signature valid?", valid)
