from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from pygments import highlight
from pygments.lexers import get_lexer_for_filename
from pygments.formatters import HtmlFormatter
from markupsafe import Markup
from flask_login import logout_user
from flask_login import login_user

import os
from flask_login import UserMixin

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a secure secret key in production
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'py'}

comments = {}
# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)


class User(UserMixin):
    def __init__(self, user_id, username=None, password_hash=None):
        self.id = user_id
        self.username = username
        self.password_hash = password_hash

# Mock user data for demonstration purposes (replace with a real user database)
users = {'user1': {'password_hash': generate_password_hash('password1')}, 'user2': {'password_hash': generate_password_hash('password2')}}

@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        return User(user_id)
    return None

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    if current_user.is_authenticated:
        files = os.listdir(app.config['UPLOAD_FOLDER'])
        return render_template('index.html', files=files)
    return redirect(url_for('login'))
# main.py

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the username is already taken (you may want to check a database)
        if username in users:
            flash('Username is already taken', 'error')
        else:
            # Store the user information (you may want to store this in a database)
            users[username] = {'password_hash': generate_password_hash(password)}

            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')


# main.py

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Validate the username and password
        if username in users and check_password_hash(users[username]['password_hash'], password):
            user = User(username, username, users[username]['password_hash'])

            # Log in the user
            login_user(user)

            flash('Login successful!', 'success')
            return redirect(url_for('index'))

        flash('Invalid username or password', 'error')

    return render_template('login.html')


from flask import redirect, url_for

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))


from flask import request, flash

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    # Check if a file was submitted in the request
    if 'file' not in request.files:
        flash('No file part', 'error')
        return redirect(request.url)

    file = request.files['file']

    # If the user submits an empty form
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(request.url)

    # If the file is allowed and valid
    if file and allowed_file(file.filename):
        # Securely save the file to the uploads folder
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        flash('File uploaded successfully!', 'success')
        return redirect(url_for('index'))
    else:
        flash('Invalid file type. Allowed types are .py', 'error')
        return redirect(request.url)

from flask_login import login_required

# ...

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # Read the contents of the file
    with open(file_path, 'r') as file:
        file_contents = file.read()

    # Syntax highlighting using Pygments
    lexer = get_lexer_for_filename(filename)
    formatter = HtmlFormatter()
    highlighted_code = highlight(file_contents, lexer, formatter)

    # Pass the highlighted code and the current_user information to the template
    return render_template('show_code.html', filename=filename, highlighted_code=Markup(highlighted_code), current_user=current_user)

@app.route('/add_comment/<filename>', methods=['POST'])
@login_required
def add_comment(filename):
    text = request.form.get('comment_text')

    # Retrieve or create comments list for the file
    file_comments = comments.get(filename, [])
    file_comments.append({'text': text, 'user': 'Anonymous'})

    # Update comments in the global variable
    comments[filename] = file_comments

    flash('Comment added successfully!', 'success')
    return redirect(url_for('uploaded_file', filename=filename))

@app.route('/delete/<filename>')
@login_required
def delete_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        flash('File deleted successfully!', 'success')
    else:
        flash('File not found!', 'error')
    return redirect(url_for('index'))

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True)
