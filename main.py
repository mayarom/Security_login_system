import mysql.connector as connector
import argon2

# define the hashing functions
def argon_hash_password(password: str) -> str:
    ph = argon2.PasswordHasher()
    hashed_password = ph.hash(password)
    return hashed_password

def argon_verify_password(hashed_password: str, password: str) -> bool:
    ph = argon2.PasswordHasher()
    try:
        ph.verify(hashed_password, password)
        return True
    except argon2.exceptions.VerifyMismatchError:
        return False

# create a new user with hashed password
username = "maya"
password = "Maya272727@"
email = "maya5660@gmail.com"
hashed_password = argon_hash_password(password)

# create a new connection to the database
con = connector.connect(
    host="localhost",
    user="root",
    password="Manulis13615@",
    database="usersdb"
)

# create a cursor object
cur = con.cursor()

# insert the new user into the database
query = "INSERT INTO users (username, password, email) VALUES (%s, %s, %s)"
values = (username, hashed_password, "admin@mydomain.com")
cur.execute(query, values)

# commit the transaction and close the connection
con.commit()
con.close()
