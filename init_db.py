import sqlite3
from werkzeug.security import generate_password_hash

connection = sqlite3.connect('database.db')

with open('schema.sql') as f:
    connection.executescript(f.read())

cur = connection.cursor()

# Admin user creation
hashed_password = generate_password_hash('123456', method='pbkdf2:sha256')
cur.execute("INSERT INTO user (username, email, password, is_admin) VALUES (?, ?, ?, ?)",
            ('admin', 'admin@blog.com', hashed_password, 1))

cur.execute("INSERT INTO user (username, email, password, is_admin) VALUES (?, ?, ?, ?)",
            ('kagan', 'kagan@blog.com', hashed_password, 0))

cur.execute("INSERT INTO user (username, email, password, is_admin) VALUES (?, ?, ?, ?)",
            ('ali', 'ali@blog.com', hashed_password, 0))


connection.commit()
connection.close()
