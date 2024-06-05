import sqlite3

# Veritabanı bağlantısı kur
connection = sqlite3.connect("database.db")

# schema.sql dosyasını aç ve içeriğini çalıştır
with open('schema.sql') as f:
    connection.executescript(f.read())

# Cursor oluştur
cur = connection.cursor()

# Veritabanına ilk gönderiyi ekle
cur.execute("INSERT INTO posts (title, content) VALUES (?, ?)",
            ('First Post', 'Content for the first post')
            )

# Veritabanına ikinci gönderiyi ekle
cur.execute("INSERT INTO posts (title, content) VALUES (?, ?)",
            ('Second Post', 'Content for the second post')
            )

# Değişiklikleri kaydet ve bağlantıyı kapat
connection.commit()
connection.close()

