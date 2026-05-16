import hashlib

def verify_hash(raw_body: bytes, received_hash: str) -> bool:
    computed = hashlib.sha256(raw_body).hexdigest().upper()
    return computed == received_hash.upper()

def compute_hash(raw_body: bytes) -> str:
    return hashlib.sha256(raw_body).hexdigest().upper()