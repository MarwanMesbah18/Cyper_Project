from flask import Flask, render_template, request, redirect, url_for
from cryptography.fernet import Fernet
import hashlib
import secrets

# Import Caesar Cipher functions from CaesarCipher.py
from CaesarCipher import caesar_encrypt, caesar_decrypt

# Import Password Generator functions from PasswordGenrator.py
from PasswordGenrator import generate_password, test_password_strength

app = Flask(__name__)

# Generate a key for encryption/decryption using Fernet
key = Fernet.generate_key()
fernet = Fernet(key)

# Function to generate a salt
def generate_salt():
    return secrets.token_bytes(16)

# Function to hash a password using MD5
def md5_hash_password(password, salt):
    hashed_password = hashlib.md5(password.encode('utf-8') + salt).hexdigest()
    return hashed_password

@app.route('/loading')
def loading():
    return render_template('loading.html')

@app.route('/')
def home():
    # Redirect to loading page first
    return redirect(url_for('loading'))

@app.route('/main')
def main_menu():
    return render_template('home.html')

@app.route('/md5', methods=['GET', 'POST'])
def md5_page():
    hash_result = None
    salt = None
    if request.method == 'POST':
        password = request.form['password']
        salt = generate_salt()
        hash_result = md5_hash_password(password, salt)
    return render_template('md5.html', hash_result=hash_result, salt=salt)

@app.route('/bcrypt', methods=['GET', 'POST'])
def bcrypt_page():
    bcrypt_result = None
    if request.method == 'POST':
        import bcrypt
        password = request.form['password']
        salt = bcrypt.gensalt()
        bcrypt_result = bcrypt.hashpw(password.encode('utf-8'), salt).decode()
    return render_template('bcrypt.html', bcrypt_result=bcrypt_result)

@app.route('/caesar', methods=['GET', 'POST'])
def caesar_page():
    caesar_result = None
    if request.method == 'POST':
        message = request.form['message']
        key = int(request.form['key'])
        action = request.form['action']
        if action == 'encrypt':
            caesar_result = caesar_encrypt(message, key)
        elif action == 'decrypt':
            caesar_result = caesar_decrypt(message, key)
    return render_template('caesar.html', caesar_result=caesar_result)

@app.route('/fernet', methods=['GET', 'POST'])
def fernet_page():
    fernet_result = None
    if request.method == 'POST':
        message = request.form['message']
        action = request.form['action']
        if action == 'encrypt':
            fernet_result = fernet.encrypt(message.encode()).decode()
        elif action == 'decrypt':
            try:
                fernet_result = fernet.decrypt(message.encode()).decode()
            except Exception:
                fernet_result = 'Invalid encrypted message!'
    return render_template('fernet.html', fernet_result=fernet_result)

@app.route('/password', methods=['GET', 'POST'])
def password_page():
    password = None
    strength = None
    strength_color = None
    missing_message = None
    error = None
    if request.method == 'POST':
        try:
            length = int(request.form['length'])
            use_lower = 'use_lower' in request.form
            use_upper = 'use_upper' in request.form
            use_digits = 'use_digits' in request.form
            use_special = 'use_special' in request.form
            password = generate_password(length, use_lower, use_upper, use_digits, use_special)
            level, color, missing = test_password_strength(password, use_lower, use_upper, use_digits, use_special)
            strength = level
            strength_color = color
            missing_message = missing
        except Exception as e:
            error = str(e)
    return render_template('password.html', password=password, strength=strength, strength_color=strength_color, missing_message=missing_message, error=error)

if __name__ == '__main__':
    app.run(debug=True)
