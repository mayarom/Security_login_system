from werkzeug.security import generate_password_hash
from flask import Flask, render_template, request, redirect, url_for, session
import mysql.connector as connector
from flask import jsonify
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from security import check_password_hash_compat
from flask import flash
from security import password_policy, is_valid_email
from flask import Flask, render_template, request, redirect, url_for, session


app = Flask(__name__)
app.config['SECRET_KEY'] = '655f09d18cffb9fccdb80addef80754546ca068bebea420fa4e4afdad1d0548a'


class Database:
    def __init__(self):
        self.con = connector.connect(host='localhost',
                                     port='3306',
                                     user='root',
                                     password='Manulis13615@',
                                     database='usersdb')
        self.cur = self.con.cursor()

    def close(self):
        self.cur.close()
        self.con.close()

    def query(self, query, args=None):
        self.cur.execute(query, args)
        return self.cur.fetchall()

    def query_one(self, query, args=None):
        self.cur.execute(query, args)
        return self.cur.fetchone()


@app.route('/')
def home():
    return render_template('home.html', current_year=datetime.now().year)


@app.route('/user_login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        print("User login POST request received")
        username = request.form['username']
        password = request.form['password']
        print(f"Username: {username}, Password: {password}")

        db = Database()
        result = db.query(
            'SELECT * FROM users WHERE username = %s', (username, ))
        db.close()

        if len(result) == 1:
            user = result[0]
            # Compare the hashed passwords
            if check_password_hash_compat(user[3], password):
                session['user'] = username
                print("User login successful")
                return redirect(url_for('user_dashboard'))
            else:
                print("Invalid username or password")
                return render_template('user_login.html', error='Invalid username or password')
        else:
            print("Invalid username or password")
            return render_template('user_login.html', error='Invalid username or password')
    else:
        return render_template('user_login.html')


@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        print("Admin login POST request received")
        username = request.form['username']
        password = request.form['password']

        db = Database()
        result = db.query(
            'SELECT * FROM admin_users WHERE username = %s', (username, ))
        db.close()

        if len(result) == 1:
            admin = result[0]
            # Compare the hashed passwords
            if check_password_hash_compat(admin[1], password):
                session['admin'] = username
                print("Admin login successful")
                return redirect(url_for('admin_dashboard'))
            else:
                print("Invalid username or password")
                return render_template('admin_login.html', error='Invalid username or password')
        else:
            return render_template('admin_login.html', error='Invalid username or password')
    return render_template('admin_login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']

        # Check password policy
        if not password_policy(password):
            flash("Password must contain at least 8 characters, 1 uppercase letter, 1 lowercase letter, 1 number and 1 special character")
            return render_template('register.html')
        
        if not is_valid_email(email):
            flash("Please provide a valid email address")
            return render_template('register.html')

        db = Database()
        try:
            # Hash the password before inserting it into the database
            hashed_password = generate_password_hash(password)
            db.query('INSERT INTO users (email, username, password) VALUES (%s, %s, %s)',
                     (email, username, hashed_password))
            db.con.commit()
            db.close()
            print(
                f"User registered successfully: {username}, email: {email}, password: {password}")
            return redirect(url_for('user_login'))
        except Exception as e:
            db.con.rollback()
            db.close()
            print(f"Error: {str(e)}")
            flash(str(e))
            return render_template('register.html', error=str(e))
    else:
        return render_template('register.html')


@app.route('/user_dashboard')
def user_dashboard():
    if 'user' not in session:
        return redirect(url_for('user_login'))

    logout_url = url_for('logout')
    if request.method == 'POST':
        if request.form['action'] == 'My Profile':
            return redirect(url_for('user_profile'))

    return render_template('user_dashboard.html', user=session['user'], logout_url=logout_url)


@app.route('/admin_dashboard')
def admin_dashboard():
    if 'admin' in session:
        db = Database()
        users = db.query('SELECT * FROM users')
        admin = db.query_one(
            'SELECT * FROM users WHERE username = %s', [session['admin']])

        db.close()
        return render_template('admin_dashboard.html', username=session['admin'], users=users, admin=admin)
    else:
        return redirect(url_for('admin_login'))


@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('admin', None)
    return redirect(url_for('home'))


@app.route('/user_profile')
def user_profile():
    if 'user' not in session:
        return redirect(url_for('user_login'))

    db = Database()
    user = db.query(
        'SELECT * FROM users WHERE username = %s', (session['user'],))[0]
    #fill the email and username fields with the current values
    

    db.close()

    return render_template('user_profile.html', user=user)


@app.route('/admin_profile')
def admin_profile():
    if 'admin' in session:
        db = Database()
        admin = db.query(
            'SELECT * FROM admin_users WHERE username = %s', (session['admin'],))[0]
        db.close()
        return render_template('admin_profile.html', admin=admin)
    else:
        return redirect(url_for('admin_login'))


@app.route('/edit_user_profile', methods=['GET', 'POST'])
def edit_user_profile():
    if 'user' not in session:
        return redirect(url_for('user_login'))

    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        new_username = request.form['new_username']
        email = request.form['email']

        db = Database()
        try:
            print(f"Fetching user: {session['user']}")
            user = db.query_one(
                'SELECT * FROM users WHERE username = %s', (session['user'],))
            print(f"User fetched: {user}")

            if not check_password_hash(user['password'], old_password):
                raise Exception("Old password does not match")

            hashed_password = generate_password_hash(new_password)
            db.query('UPDATE users SET username = %s, email = %s, password = %s WHERE username = %s',
                     (new_username, email, hashed_password, session['user']))
            db.con.commit()
            db.close()
            print("User updated successfully")
            return redirect(url_for('user_profile'))
        except Exception as e:
            db.con.rollback()
            db.close()
            print(f"Error: {str(e)}")
            return render_template('edit_user_profile.html', error=str(e), user=user)
    else:
        db = Database()
        print(f"Fetching user: {session['user']}")
        user = db.query_one(
            'SELECT * FROM users WHERE username = %s', (session['user'],))

        print(f"User fetched: {user}")
        db.close()

        return render_template('edit_user_profile.html', user=user)


@app.route('/edit_admin_profile', methods=['GET', 'POST'])
def edit_admin_profile():
    if 'admin' not in session:
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        new_username = request.form['new_username']
        email = request.form['email']

        db = Database()
        try:
            print(f"Fetching admin: {session['admin']}")
            admin = db.query_one(
                'SELECT * FROM admin_users WHERE username = %s', (session['admin'],))
            print(f"Admin fetched: {admin}")

            if not check_password_hash(admin['password'], old_password):
                raise Exception("Old password does not match")

            hashed_password = generate_password_hash(new_password)
            db.query('UPDATE admin_users SET username = %s, email = %s, password = %s WHERE username = %s',
                     (new_username, email, hashed_password, session['admin']))
            db.con.commit()
            db.close()
            print("Admin updated successfully")
            return redirect(url_for('admin_profile'))
        except Exception as e:
            db.con.rollback()
            db.close()
            print(f"Error: {str(e)}")
            return render_template('edit_admin_profile.html', error=str(e), admin=admin)
    else:
        db = Database()
        print(f"Fetching admin: {session['admin']}")
        admin = db.query_one(
            'SELECT * FROM admin_users WHERE username = %s', (session['admin'],))

        print(f"Admin fetched: {admin}")
        db.close()

        return render_template('edit_admin_profile.html', admin=admin)


if __name__ == '__main__':
    app.run(debug=True)
