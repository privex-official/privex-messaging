import hashlib

def sha256(txt):
    hex1 = hashlib.sha256(txt.encode()).hexdigest()
    return hex1