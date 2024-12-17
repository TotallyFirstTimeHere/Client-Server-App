import socket
import ssl
import logging
import threading
import json
import hashlib
import os

# Налаштування журналювання
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("server.log"),
        logging.StreamHandler()
    ]
)

# Перевірка сертифікатів SSL
if not os.path.exists('server.crt') or not os.path.exists('server.key'):
    print("SSL certificates not found, generating...")
    os.system("openssl req -x509 -newkey rsa:2048 -nodes -keyout server.key -out server.crt -days 365")

HOST = '127.0.0.1'
PORT = 65432

USER_DB = "users.json"
clients = []
nicknames = []

# Завантаження користувачів з файлу
def load_users():
    try:
        with open(USER_DB, 'r') as file:
            users = json.load(file)
            logging.info("Users database loaded successfully.")
            return users
    except FileNotFoundError:
        logging.warning("Users database not found, creating a new one.")
        return {}
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON: {e}")
        return {}

def save_users(users):
    try:
        with open(USER_DB, 'w') as file:
            json.dump(users, file)
            logging.info("Users database saved successfully.")
    except Exception as e:
        logging.error(f"Error saving users: {e}")

users = load_users()

# Хешування пароля
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Автентифікація клієнта
def authenticate(conn):
    while True:
        try:
            conn.sendall(b"LOGIN_OR_REGISTER:")
            option = conn.recv(1024).decode().strip()

            if option == "LOGIN":
                conn.sendall(b"USERNAME:")
                username = conn.recv(1024).decode().strip()
                conn.sendall(b"PASSWORD:")
                password = conn.recv(1024).decode().strip()

                if username in users and users[username] == hash_password(password):
                    conn.sendall(b"LOGIN_SUCCESS")
                    logging.info(f"{username} successfully logged in.")
                    conn.sendall(f"You are logged in as {username}.".encode())
                    return username
                else:
                    conn.sendall(b"LOGIN_FAILED")
                    logging.warning(f"Failed login attempt for username: {username}.")

            elif option == "REGISTER":
                conn.sendall(b"USERNAME:")
                username = conn.recv(1024).decode().strip()
                if username in users:
                    conn.sendall(b"USERNAME_TAKEN")
                    logging.warning(f"Registration failed: username '{username}' already exists.")
                else:
                    conn.sendall(b"PASSWORD:")
                    password = conn.recv(1024).decode().strip()

                    if len(password) < 6:
                        conn.sendall(b"PASSWORD_TOO_SHORT")
                        logging.warning(f"Registration failed: password too short for '{username}'.")
                    else:
                        users[username] = hash_password(password)
                        save_users(users)
                        conn.sendall(b"REGISTER_SUCCESS")
                        logging.info(f"New user registered: {username}.")
                        conn.sendall(f"You are registered and logged in as {username}.".encode())
                        return username

            else:
                conn.sendall(b"INVALID_OPTION")
                logging.warning("Invalid authentication option received.")
        except Exception as e:
            logging.error(f"Authentication error: {e}")
            conn.sendall(b"AUTH_ERROR")

# Передача повідомлень усім клієнтам
def broadcast(message, sender_conn=None):
    for client in clients:
        if client != sender_conn:
            try:
                client.sendall(message.encode())
            except Exception as e:
                logging.error(f"Broadcast error: {e}")
                remove_client(client)

# Видалення клієнта з чату
def remove_client(conn):
    if conn in clients:
        clients.remove(conn)
        logging.info("Client removed from the list of active connections.")

# Обробка клієнта
def handle_client(conn, addr):
    logging.info(f"New connection from {addr}")
    username = authenticate(conn)
    if not username:
        conn.close()
        return

    nicknames.append(username)
    clients.append(conn)
    broadcast(f"{username} has joined the chat!", conn)

    try:
        while True:
            message = conn.recv(2048).decode().strip()
            if message:
                logging.info(f"Message from {username}: {message}")
                broadcast(f"{username}: {message}", conn)
    except Exception as e:
        logging.error(f"Error with client {username}: {e}")
    finally:
        remove_client(conn)
        nicknames.remove(username)
        broadcast(f"{username} has left the chat.")
        conn.close()

# Налаштування SSL/TLS
try:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    logging.info("SSL context loaded successfully.")
except Exception as e:
    logging.critical(f"Failed to load SSL context: {e}")
    exit(1)

# Запуск сервера
try:
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    logging.info("Server started, waiting for connections...")
    print("[SERVER STARTED] Waiting for connections...")

    with context.wrap_socket(server_socket, server_side=True) as secure_socket:
        while True:
            conn, addr = secure_socket.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.start()
            logging.info(f"Active connections: {threading.active_count() - 1}")
except Exception as e:
    logging.critical(f"Server failed to start: {e}")
    exit(1)
