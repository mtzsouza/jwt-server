import pytest
import sqlite3
import http.client
import json
import threading
import time
from http.server import HTTPServer

from main import MyServer, init_db, generate_key, hostName, serverPort

@pytest.fixture
def setup_db():
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    # Create a table specifically for testing
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')

    # Insert keys
    generate_key(cursor, 3600)
    generate_key(cursor, -3600)

    conn.commit()
    yield conn, cursor
    conn.close()

# Start the server
@pytest.fixture
def start_server():
    server = threading.Thread(target=run_server, daemon=True)
    server.start()
    time.sleep(1)  # Wait one second just to avoid racing conditions
    yield
def run_server():
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

# Test /auth
def test_valid_key_auth(setup_db, start_server):
    conn = http.client.HTTPConnection(hostName, serverPort)
    conn.request("POST", "/auth")
    response = conn.getresponse()
    assert response.status == 200
    token = response.read().decode('utf-8')
    assert token is not None  # Make sure it gives a token

def test_expired_key_auth(setup_db, start_server):
    conn = http.client.HTTPConnection(hostName, serverPort)
    conn.request("POST", "/auth?expired=true")
    response = conn.getresponse()
    assert response.status == 200
    token = response.read().decode('utf-8')
    assert token is not None

# Test GET request
def test_jwks(setup_db, start_server):
    conn = http.client.HTTPConnection(hostName, serverPort)
    conn.request("GET", "/.well-known/jwks.json")
    response = conn.getresponse()
    assert response.status == 200
    data = json.loads(response.read().decode('utf-8'))
    assert "keys" in data
    assert len(data["keys"]) > 0  # Make sure there's a key (at least)

# Test invalid path
def test_invalid_path(setup_db, start_server):
    conn = http.client.HTTPConnection(hostName, serverPort)
    conn.request("GET", "/ndkjasbdkasjb")
    response = conn.getresponse()
    assert response.status == 405

# Check the number of keys made during setup
def test_db_insertion(setup_db):
    conn, cursor = setup_db
    cursor.execute("SELECT COUNT(*) FROM keys")
    result = cursor.fetchone()
    assert result[0] == 2
