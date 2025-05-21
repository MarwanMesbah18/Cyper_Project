import hashlib
import secrets  # Python's built-in module for generating cryptographically secure random numbers

def generate_salt():
    return secrets.token_bytes(16)

def md5_hash_password(password, salt):
    # Combine the password and salt, then hash using MD5
    hashed_password = hashlib.md5(password.encode('utf-8') + salt).hexdigest()
    return hashed_password

# Example usage
password = "010mdo010"
salt = generate_salt()
hashed_password = md5_hash_password(password, salt)

print("Password:", password)
print("Salt:", salt)
print("MD5 Hash with Salt:", hashed_password)
