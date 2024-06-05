from flask import Flask, render_template, request, url_for, flash, redirect
import sqlite3
from werkzeug.exceptions import abort 
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'jRv8sL2pFwXhN5aG9zQ3bU7cY6dA1eR3'


# Open the connection between the db and our app
def get_connection():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn

# Function to get the post id
def get_post(post_id):
    conn = get_connection()
    post = conn.execute('SELECT * FROM posts WHERE id = ?',
    (post_id,)).fetchone()
    conn.close
    if post is None:
        abort(404)
    return post

@app.route("/")
def index():
    # We used the connection to bring all the data from the table
    conn = get_connection()
    posts = conn.execute('SELECT * FROM posts').fetchall()
    return render_template("index.html", posts=posts)

@app.route("/<int:post_id>")
def post(post_id):
    post = get_post(post_id)
    return render_template("post.html", post=post)

@app.route("/create", methods = ['GET', 'POST'])
def create():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        
        if not title:
            flash("Title is required!")

        conn = get_connection()
        conn.execute("INSERT INTO posts (title, content) VALUES (?, ?)",
        (title, content))
        conn.commit()
        conn.close()
        return redirect(url_for('index'))

    return render_template("create.html")

@app.route('/<int:id>/edit', methods=('GET', 'POST'))
def edit(id):
    post = get_post(id)
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        if not title:
            flash('Title is required!')
        else:
            conn = get_connection()
            conn.execute('UPDATE posts SET title = ?, content = ?'
            ' WHERE id = ?',
            (title, content, id))
        conn.commit()
        conn.close()
        return redirect(url_for('index'))
    return render_template("edit.html", post=post)
    
@app.route('/<int:id>/delete', methods=('GET', 'POST'))
def delete(id):
    post = get_post(id)
    conn = get_connection()
    conn.execute('DELETE FROM posts WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    flash(' "{}" was successfully deleted!'.format(post['title']))
    return redirect(url_for('index'))

def get_connection():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn

# Function to get user by email
def get_user_by_email(email):
    conn = get_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()
    return user

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Check if email already exists
        if get_user_by_email(email):
            flash('Email address already exists', 'error')
        else:
            # Hash the password for security
            hashed_password = generate_password_hash(password, method='pbkdf2:sha512')
            conn = get_connection()
            conn.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', (username, email, hashed_password))
            conn.commit()
            conn.close()
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # Fetch the user from the database
        user = get_user_by_email(email)
        
        # Check if user exists and password is correct
        if user and check_password_hash(user['password'], password):
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password', 'error')
            
    return render_template('login.html')



def hash_existing_passwords():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute('SELECT id, password FROM users')
    users = cursor.fetchall()

    for user in users:
        user_id, password = user
        hashed_password = generate_password_hash(password, method='pbkdf2:sha512')
        cursor.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_password, user_id))

    conn.commit()
    conn.close()

hash_existing_passwords()

    

if __name__ == '__main__':
    app.run(debug=True)

