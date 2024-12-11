import socket        # Для створення мережевих сокетів
import ssl           # Для забезпечення SSL/TLS шифрування
import threading     # Для роботи з багатопотоковістю
import json          # Для зберігання облікових даних у JSON-файлі
import hashlib       # Для хешування паролів
import logging       # Для логування
import os

# Перевірка чи існують сертифікати. Якщо їх немає, вони будуть автоматично згенеровані.
if not os.path.exists('server.crt') or not os.path.exists('server.key'):
    print("SSL certificates not found, generating new ones...")
    os.system("openssl req -x509 -newkey rsa:2048 -nodes -keyout server.key -out server.crt -days 365")

# Налаштування журналювання
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("server.log"),  # Запис у файл
        logging.StreamHandler()            # Виведення у консоль
    ]
)

# Конфігурація сервера
HOST = '127.0.0.1'  # Локальний хост (сервер працює лише на моєму комп'ютері)
PORT = 65432         # Порт для підключення клієнтів

# Завантаження облікових даних
USER_DB = "users.json"
clients = []
nicknames = []
lock = threading.Lock()  # Блокування для доступу до списку клієнтів

# Завантаження користувачів з файлу
def load_users():
    try:
        with open(USER_DB, 'r') as file:
            users = json.load(file)
            logging.info("Users database loaded successfully.")
            return users
    except FileNotFoundError:
        logging.warning("Users database not found, creating a new one.")  # Додано логування
        return {}
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON: {e}")  # Додано логування помилок
        return {}

# Збереження користувачів у файл
def save_users(users):
    try:
        with open(USER_DB, 'w') as file:
            json.dump(users, file)  # Зберігає облікові записи у файл
    except Exception as e:
        logging.error(f"Error saving users: {e}")  # Додано логування помилок

users = load_users()

# Хешування пароля
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Функція аутентифікації
def authenticate(conn):
    try:
        option = conn.recv(1024).decode().strip()

        if option == "LOGIN":
            conn.sendall(b"USERNAME:")
            username = conn.recv(1024).decode().strip()
            conn.sendall(b"PASSWORD:")
            password = conn.recv(1024).decode().strip()

            if username in users and users[username] == hash_password(password):
                conn.sendall(b"LOGIN_SUCCESS")
                logging.info(f"{username} successfully logged in.")
                return username
            else:
                conn.sendall(b"LOGIN_FAILED")
                logging.warning(f"Failed login attempt for username: {username}.")
                return None

        elif option == "REGISTER":
            conn.sendall(b"USERNAME:")
            username = conn.recv(1024).decode().strip()
            if username in users:
                conn.sendall(b"USERNAME_TAKEN")
                logging.warning(f"Registration failed: username '{username}' already exists.")
                return None
            conn.sendall(b"PASSWORD:")
            password = conn.recv(1024).decode().strip()

            if len(password) < 6:  # Перевірка на мінімальну довжину пароля
                conn.sendall(b"PASSWORD_TOO_SHORT")
                logging.warning(f"Registration failed: password for username '{username}' too short.")
                return None

            users[username] = hash_password(password)
            save_users(users)
            conn.sendall(b"REGISTER_SUCCESS")
            logging.info(f"New user registered: {username}.")
            return username
        else:
            conn.sendall(b"INVALID_OPTION")
            logging.warning(f"Invalid option received: {option}")
            return None
    except Exception as e:
        logging.error(f"Authentication error: {e}")
        conn.sendall(b"AUTH_ERROR")
        return None

# Функція для трансляції повідомлень всім підключеним клієнтам, крім відправника
def broadcast(message, sender=None):
    """Надсилання повідомлення всім клієнтам, крім відправника."""
    with lock:  # Блокування доступу до списку клієнтів
        for client in clients:
            try:
                if sender:
                    index = clients.index(sender)
                    sender_nickname = nicknames[index]
                    # Перевіряємо, чи повідомлення ще не містить ніка
                    if not message.decode('utf-8').startswith(f"{sender_nickname}: "):
                        message = f"{sender_nickname}: {message.decode('utf-8')}".encode('utf-8')

                client.send(message)
            except Exception as e:
                logging.error(f"Error sending message to client: {e}")
                remove_client(client)

# Обробка зв'язку з конкретним клієнтом
def handle(client):
    """Обробка зв'язку з конкретним клієнтом."""
    while True:
        try:
            message = client.recv(1024)
            if not message:
                raise ConnectionResetError("Client closed the connection")
            broadcast(message, sender=client)
        except (ConnectionResetError, ConnectionAbortedError):
            print("Client disconnected.")
            remove_client(client)
            break
        except Exception as e:
            print(f"Error with client: {e}")
            remove_client(client)
            break

# Видалення клієнта зі списку та закриття з'єднання
def remove_client(client):
    """Видалення клієнта із сервера."""
    with lock:  # Блокування доступу до списків клієнтів
        if client in clients:
            index = clients.index(client)
            nickname = nicknames[index]
            clients.remove(client)
            client.close()
            nicknames.remove(nickname)
            broadcast(f"{nickname} left the chat".encode('utf-8'))
            logging.info(f"{nickname} disconnected.")

# Прийом та обробка нових з'єднань клієнтів
def receive():
    """Прийом та обробка нових з'єднань клієнтів."""
    while True:
        try:
            client, address = secure_server.accept()
            print(f"Connected from {str(address)}")

            # Автентифікація користувача
            nickname = authenticate(client)
            if nickname:
                nicknames.append(nickname)
                clients.append(client)

                print(f"Client nickname: {nickname}")
                broadcast(f"{nickname} joined the chat".encode("utf-8"))
                client.send("You have connected to the server".encode("utf-8"))

                # Запуск обробки клієнта в новому потоці
                thread = threading.Thread(target=handle, args=(client,), daemon=True)
                thread.start()
        except Exception as e:
            logging.error(f"Error accepting connection: {e}")

# Налаштовання SSL/TLS з використанням сертифіката та приватного ключа.
try:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    logging.info("SSL context loaded successfully.")
except Exception as e:
    logging.error(f"Failed to load SSL context: {e}")
    exit(1)

# Запуск сервера (основний цикл сервера)
try:
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    logging.info("Server started, waiting for connections...")
    print("[SERVER STARTED] Waiting for connections...")

    # Створює серверний сокет і переводить його в режим прослуховування.
    with context.wrap_socket(server_socket, server_side=True) as secure_server:
        receive()

except Exception as e:
    logging.critical(f"Server failed to start: {e}")
    exit(1)
finally:
    with open("users.json", "w") as file:
        json.dump(users, file)  # Збереження бази даних користувачів
    print("Server shut down")
