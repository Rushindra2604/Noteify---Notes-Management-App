#pip install mysql-connector-python

import mysql.connector

db = mysql.connector.connect(
    host='localhost',
    port=3306,
    user='root',
    password='@RUSHI26',
    database='noteify',
    connection_timeout=5,
    use_pure=True
)

print("Database connection established.")

cursor = db.cursor()