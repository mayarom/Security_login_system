
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
import mysql.connector as connector
from werkzeug.security import check_password_hash
from security import hash_password, password_policy, is_valid_email, aragon_verify_password, aragon_hash_password, secret_key


app = Flask(__name__)
app.secret_key = secret_key


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
            stored_password_hash = user[3]
            submitted_password = password
            if aragon_verify_password(stored_password_hash, submitted_password):
                session['user'] = username
                print("User login successful")
                return redirect(url_for('user_dashboard'))
            else:
                flash("Invalid username or password")
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
            stored_password_hash = admin[1]
            if aragon_verify_password(stored_password_hash, password):
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
            hashed_password = aragon_hash_password(password)
            if not hashed_password:
                flash("Password does not meet the requirements")
                return render_template('register.html')

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
    if 'user' in session:
        session.pop('user', None)
    if 'admin' in session:
        session.pop('admin', None)

    return redirect(url_for('home'))


@app.route('/user_profile')
def user_profile():
    if 'user' not in session:
        return redirect(url_for('user_login'))

    db = Database()
    user = db.query(
        'SELECT * FROM users WHERE username = %s', (session['user'],))[0]

    db.close()

    return render_template('user_profile.html', user=user)


@app.route('/admin_profile')
def admin_profile():
    if 'admin' in session:
        db = Database()
        admin = db.query(
            'SELECT username, password, email FROM admin_users WHERE username = %s', (session['admin'],))[0]
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

            hashed_password = hash_password(new_password)
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

            hashed_password = hash_password(new_password)
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


@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        db=Database()

        # Insert new user into database
        db.execute('INSERT INTO users (username, email, password) VALUES (%s, %s, %s)',
                   (username, email, password))
        db.commit()

        flash('User added successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('add_user.html')

  


@app.route('/delete_user/<int:id>')
def delete_user(id):
    if 'admin' not in session:
        return redirect(url_for('admin_login'))
    db = Database()
    db.query('DELETE FROM users WHERE id = %s', (id,))
    db.con.commit()
    db.close()
    return redirect(url_for('admin_dashboard'))


@app.route('/edit_user/<int:id>', methods=['GET', 'POST'])
def edit_user(id):
    if 'admin' not in session:
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        db = Database()
        try:
            hashed_password = hash_password(password)
            db.query('UPDATE users SET username = %s, email = %s, password = %s WHERE id = %s',
                     (username, email, hashed_password, id))
            db.con.commit()
            db.close()
            print("User updated successfully")
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            db.con.rollback()
            db.close()
            print(f"Error: {str(e)}")
            return render_template('edit_user.html', error=str(e))
    else:
        db = Database()
        user = db.query_one('SELECT * FROM users WHERE id = %s', (id,))
        db.close()
        return render_template('edit_user.html', user=user)


if __name__ == '__main__':
    app.run(debug=True)
