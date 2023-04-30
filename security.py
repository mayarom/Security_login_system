import bcrypt
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from flask import flash
import re

# this is used to generate a secret key - used for session management
secret_key = secrets.token_hex(32)

# this function is used to hash the password


def hash_password(password):

    # Check if the password meets the password policy
    if (password_policy(password) == False):
        return False
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
        password_hash = bcrypt.hashpw(
            password_to_check.encode(), stored_password.encode())
        return password_hash == stored_password.encode()
    else:
        # Use the Werkzeug check_password_hash() function to check the hash
        return check_password_hash(stored_password, password_to_check)

  # Check if the password meets the password policy


def password_policy(password):
    if len(password) < 8:
        flash("Password should be at least 8 characters long")
        print("Password is too short")
        return False
    elif not any(char.isdigit() for char in password):
        flash("Password should contain at least one number")
        print("Password does not contain a number")
        return False
    elif not any(char.isupper() for char in password):
        flash("Password should contain at least one uppercase letter")
        print("Password does not contain an uppercase letter")
        return False
    elif not any(char.islower() for char in password):
        flash("Password should contain at least one lowercase letter")
        print("Password does not contain a lowercase letter")
        return False
    elif not any(char in '!@#$%^&*()_+}{":?><,./;' for char in password):
        flash("Password should contain at least one special character")
        print("Password does not contain a special character")
        return False
    else:
        return True

import re

def is_valid_email(email):
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_regex, email) is not None
