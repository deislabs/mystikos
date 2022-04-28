import pyodbc
import jwt
import os
import numpy as np
import pandas as pd
import pycurl
import stat
import tty
from logzero import logger
from Crypto.Cipher import AES

def test_pyodbc(server: str, database: str, uid: str, password: str, driver: str, query: str):
    connstr = "Driver=" + driver
    connstr += ";Server=" + server
    connstr += ";Database=" + database
    connstr += ";UID=" + uid
    connstr += ";Password=" + password

    try:
        conn = pyodbc.connect(connstr)
    except pyodbc.Error as ex:
        print(ex)
    logger.info("Successful connected to database")

    cursor = conn.cursor()
    cursor.execute(query)
    row = cursor.fetchone()
    print(row)

def test_pandas():
    dates = pd.date_range("20210101", periods=6)
    df = pd.DataFrame(np.random.randn(6, 4), index=dates, columns=list("ABCD"))
    print(df)

    df2 = pd.DataFrame(np.random.randn(10, 4))
    print(df2)
    logger.info("test_pandas passed")

def test_pycrypto():
    key = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
    message = "abcdefghijklmnop"
    ciphertext = key.encrypt(message)
    print(ciphertext)

    cleartext = key.decrypt(ciphertext)
    print(cleartext)
    logger.info("test_pycrypto passed")

def test_pycurl():
    with open('pycurl.html', 'wb') as f:
        c = pycurl.Curl()
        c.setopt(c.URL, 'http://pycurl.io/')
        c.setopt(c.WRITEDATA, f)
        c.perform()
        c.close()
    f = open('pycurl.html', 'r')
    print(f.read(100))
    logger.info("test_pycurl passed")

def test_jwt():
    key = "secret"
    encoded = jwt.encode({"some": "payload"}, key, algorithm="HS256")
    print(encoded)

    clear = jwt.decode(encoded, key, algorithms="HS256")
    print(clear)
    logger.info("test_jwt passed")

def test_bidirectional_pty():
    master, read_slave = os.openpty()
    write_slave = os.dup(read_slave)
    tty.setraw(read_slave)
    data = bytearray()

    mode = os.fstat(master).st_mode
    assert(stat.S_ISCHR(mode))
    mode = os.fstat(read_slave).st_mode
    assert(stat.S_ISCHR(mode))
    mode = os.fstat(write_slave).st_mode
    assert(stat.S_ISCHR(mode))

    os.write(master, b'a')
    os.write(write_slave, b'1')
    os.write(write_slave, b'2345')

    os.write(master, b'bcde')
    chunk = os.read(master, 1024)
    assert(chunk == b'12345')
    chunk = os.read(read_slave, 1024)
    assert(chunk == b'abcde')
    print("test_bidirectional_pty passed")

if __name__ == "__main__":

    test_pyodbc(
        server=os.getenv("DB_SERVER_NAME"),
        database=os.getenv("DB_NAME"),
        uid = os.getenv("DB_USERID"),
        password = os.getenv("DB_PASSWORD"),
        driver="{ODBC Driver 17 for SQL Server}",
        query="SELECT USER_NAME()")

    test_pandas()

    test_pycrypto()

    test_pycurl()

    test_jwt()

    test_bidirectional_pty()
