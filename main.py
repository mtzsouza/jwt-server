from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3

db_file = "totally_not_my_privateKeys.db"
hostName = "localhost"
serverPort = 8080

# Setup and start the database
def init_db():
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()

    # Create the table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')

    conn.commit()
    return conn, cursor

def insert_key(cursor, private_key, exp):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem, exp))

def generate_key(cursor, valid_duration_seconds):
    # Generate the RSA key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    exp = int((datetime.datetime.utcnow() + datetime.timedelta(seconds=valid_duration_seconds)).timestamp())
    insert_key(cursor, private_key, exp)

def get_key(cursor, expired=False):
    now = int(datetime.datetime.utcnow().timestamp())
    if expired:
        cursor.execute("SELECT key FROM keys WHERE exp < ? ORDER BY exp DESC LIMIT 1", (now,))
    else:
        cursor.execute("SELECT key FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1", (now,))
    result = cursor.fetchone()
    return result[0] if result else None

def get_valid_keys(cursor):
    now = int(datetime.datetime.utcnow().timestamp())
    cursor.execute("SELECT key FROM keys WHERE exp > ?", (now,))
    return cursor.fetchall()

def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

class MyServer(BaseHTTPRequestHandler):
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            conn, cursor = init_db()

            expired = 'expired' in params
            key_pem = get_key(cursor, expired)

            if not key_pem:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(bytes("No matching key found", "utf-8"))
                return

            headers = {"kid": "expiredKID" if expired else "goodKID"}
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + (datetime.timedelta(hours=-1) if expired else datetime.timedelta(hours=1))
            }

            encoded_jwt = jwt.encode(token_payload, key_pem, algorithm="RS256", headers=headers)

            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))

            conn.close()
            return

        self.send_response(405)
        self.end_headers()

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            conn, cursor = init_db()

            valid_keys = get_valid_keys(cursor)

            keys = {"keys": []}
            for key_pem_tuple in valid_keys:
                key_pem = key_pem_tuple[0]
                private_key = serialization.load_pem_private_key(key_pem, password=None)
                public_numbers = private_key.public_key().public_numbers()

                keys["keys"].append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "goodKID",
                    "n": int_to_base64(public_numbers.n),
                    "e": int_to_base64(public_numbers.e),
                })

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))

            conn.close()
            return

        self.send_response(405)
        self.end_headers()

if __name__ == "__main__":
    conn, cursor = init_db()

    # Generate a valid key and an expired one
    generate_key(cursor, 3600)  # Expires in 1 hour
    generate_key(cursor, -3600)  # Already expired

    conn.commit()
    conn.close()

    # Start the server
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    webServer.server_close()
