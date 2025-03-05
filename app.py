# Flask app using JWT and Sqlite3 to register/login/logout users with REST API requests

'''
Resources:
- https://www.linkedin.com/learning/building-restful-apis-with-flask
- https://camkode.com/posts/implementing-jwt-authentication-in-flask
'''

# Import libraries
from flask import Flask, jsonify, request
import sqlite3
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt, get_jwt_identity
from flask_mail import Mail, Message
from dotenv import load_dotenv
import os


# Define a function to create sqlite table
def create_sqlite_table():
    try:
        connection = sqlite3.connect("app.db", timeout=10)
        cursor = connection.cursor()
        cursor.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            )
        ''')
        connection.commit()
    except sqlite3.IntegrityError as e:
        print(f"SQLite unique constraint failed: {e}")
        connection.rollback()  # Roll back the transaction to avoid data corruption
    finally:
        connection.close()


# Create sqlite table if not created
create_sqlite_table()

# Get environment variables from .env file placed in root directory
load_dotenv()

# Flask config
app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET') # Place your variable to dotenv file
app.config['MAIL_SERVER']='sandbox.smtp.mailtrap.io' # Using free Mailtrap.io account to test/pretend sending emails
app.config['MAIL_PORT'] = 2525
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME') # Place your variable to dotenv file
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD') # Place your variable to dotenv file
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

# Jwt and mail config
jwt = JWTManager(app)
blacklisted_tokens = set()
mail = Mail(app)


# Define routes
@app.route("/")
def ok():
    return jsonify(message = "200 OK"), 200


@app.route('/register', methods=['POST'])
def register():
    email = request.form['email']
    connection = sqlite3.connect("app.db", timeout=10)
    cursor = connection.cursor()
    test = cursor.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if test:
        return jsonify(message='That email already exists.'), 409
    else:
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        password = request.form['password']
        cursor.execute("INSERT INTO users (first_name, last_name, email, password) VALUES (?,?,?,?)", (first_name, last_name, email, password,))
        connection.commit()
        connection.close()
        return jsonify(message='User created successfully.'), 201


@app.route('/login', methods=['POST'])
def login():
    if request.is_json:
        email = request.json['email']
        password = request.json['password']
    else:
        email = request.form['email']
        password = request.form['password']
    connection = sqlite3.connect("app.db", timeout=10)
    cursor = connection.cursor()
    test = cursor.execute("SELECT id FROM users WHERE email = ? AND password = ?", (email,password,)).fetchone()
    if test:
        access_token = create_access_token(identity=email)
        return jsonify(message="Login succeeded.", access_token=access_token)
    else:
        return jsonify(message="Bad email of password"), 401


@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()['jti']  # Get the unique identifier for the JWT token
    blacklisted_tokens.add(jti)  # Add the token to the blacklist
    return jsonify({'message': 'User logged out successfully'}), 200


@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    jti = get_jwt()['jti']
    if jti in blacklisted_tokens:
        return jsonify({'message': 'Token has been revoked'}), 401
    else:
        identity = get_jwt_identity()
        return jsonify(logged_in_as=identity), 200


@app.route('/retrieve_password/<string:email>', methods=['GET'])
def retrieve_password(email: str):
    connection = sqlite3.connect("app.db", timeout=10)
    cursor = connection.cursor()
    user = cursor.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if user:
        msg = Message("Your password is " + user[4],
                      sender="example@example.com",
                      recipients=[email])
        mail.send(msg)
        return jsonify(message="Password sent to " + email)
    else:
        return jsonify(message="That email doesn't exist"), 401


# Run flask app
if __name__ == "__main__":
    app.run(debug=True)
