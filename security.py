import bcrypt
import secrets
from werkzeug.security import generate_password_hash, check_password_hash


secret_key = secrets.token_hex(32)
print(secret_key)


def hash_password(password):
    # Generate a random salt value
    salt = bcrypt.gensalt()

    # Hash the password using bcrypt with the salt and a high number of rounds
    password_hash = bcrypt.hashpw(password.encode(), salt, rounds=12)

    # Encode the salt and hash as a string for storage in the database
    return f'$2b$12${salt.decode()}${password_hash.decode()}'

def check_password_hash_compat(stored_password, password_to_check):
    # Check if the stored password is a bcrypt hash
    if stored_password.startswith('$2b$'):
        # Use the same salt and iteration count as the stored password
        password_hash = bcrypt.hashpw(password_to_check.encode(), stored_password.encode())
        return password_hash == stored_password.encode()
    else:
        # Use the Werkzeug check_password_hash() function to check the hash
        return check_password_hash(stored_password, password_to_check)
