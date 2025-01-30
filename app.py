from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key'

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    conn = get_db_connection()
    posts = conn.execute('SELECT * FROM post').fetchall()
    conn.close()
    return render_template('index.html', posts=posts)

@app.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        conn = get_db_connection()
        conn.execute('INSERT INTO user (username, email, password) VALUES (?, ?, ?)',
                     (username, email, hashed_password))
        conn.commit()
        conn.close()

        flash('You have successfully registered!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM user WHERE email = ?', (email,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            flash('You have successfully logged in!', 'success')
            if user['is_admin']:
                return redirect(url_for('admin'))
            return redirect(url_for('index'))

        flash('Invalid email or password', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have successfully logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/create', methods=('GET', 'POST'))
def create():
    if 'user_id' not in session:
        flash('You need to be logged in to create a post.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']

        conn = get_db_connection()
        conn.execute('INSERT INTO post (title, content, user_id) VALUES (?, ?, ?)',
                     (title, content, session['user_id']))
        conn.commit()
        conn.close()

        flash('Your post has been created!', 'success')
        return redirect(url_for('index'))

    return render_template('create.html')

@app.route('/admin')
def admin():
    if 'user_id' not in session or not session.get('is_admin'):
        flash('You do not have access to this page.', 'danger')
        return redirect(url_for('index'))

    conn = get_db_connection()
    users = conn.execute('SELECT * FROM user').fetchall()
    conn.close()
    return render_template('admin.html', users=users)

@app.route('/post/<int:post_id>')
def post(post_id):
    conn = get_db_connection()
    post = conn.execute('SELECT * FROM post WHERE id = ?', (post_id,)).fetchone()
    conn.close()
    if post is None:
        flash('Post not found!', 'danger')
        return redirect(url_for('index'))
    return render_template('post.html', post=post)

@app.route('/edit/<int:id>', methods=('GET', 'POST'))
def edit(id):
    conn = get_db_connection()
    post = conn.execute('SELECT * FROM post WHERE id = ?', (id,)).fetchone()

    if post is None:
        flash('Post not found!', 'danger')
        return redirect(url_for('index'))

    if 'user_id' not in session or (post['user_id'] != session['user_id'] and not session.get('is_admin')):
        flash('You do not have permission to edit this post.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']

        conn.execute('UPDATE post SET title = ?, content = ? WHERE id = ?',
                     (title, content, id))
        conn.commit()
        conn.close()

        flash('Post has been updated!', 'success')
        return redirect(url_for('index'))

    conn.close()
    return render_template('edit.html', post=post)

@app.route('/delete/<int:id>', methods=('POST',))
def delete(id):
    conn = get_db_connection()
    post = conn.execute('SELECT * FROM post WHERE id = ?', (id,)).fetchone()

    if post is None:
        flash('Post not found!', 'danger')
        return redirect(url_for('index'))

    if 'user_id' not in session or (post['user_id'] != session['user_id'] and not session.get('is_admin')):
        flash('You do not have permission to delete this post.', 'danger')
        return redirect(url_for('index'))

    conn.execute('DELETE FROM post WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    flash('Post has been deleted!', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
