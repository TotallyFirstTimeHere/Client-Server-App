import socket
import ssl
import logging
import threading

# Налаштування журналювання
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("client.log"),  # Запис у файл
        logging.StreamHandler()  # Виведення у консоль
    ]
)

# Конфігурація клієнта
HOST = '127.0.0.1'  # Адреса сервера
PORT = 65432  # Порт сервера

# Налаштування SSL-контексту
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile="server.crt")
context.check_hostname = True
context.check_hostname = False  # Для самопідписаних сертифікатів
context.verify_mode = ssl.CERT_REQUIRED

# Створення TCP-з'єднання з сервером через SSL
def create_connection():
    try:
        sock = socket.create_connection((HOST, PORT))
        secure_sock = context.wrap_socket(sock, server_hostname=HOST)
        logging.info("Connected to server with SSL.")
        print("Підключено до сервера з SSL.")
        return secure_sock
    except Exception as e:
        logging.error(f"Connection error: {e}")
        print(f"Помилка підключення: {e}")
        return None

# Функція для отримання повідомлень від сервера
def receive_messages(secure_sock):
    try:
        while True:
            message = secure_sock.recv(1024).decode("utf-8")
            if message:
                print(message)  # Виведення отриманого повідомлення
            else:
                break
    except Exception as e:
        logging.error(f"Error receiving message: {e}")
        print("Помилка отримання повідомлення.")
    finally:
        secure_sock.close()

# Функція для надсилання повідомлень серверу
def send_messages(secure_sock):
    try:
        while True:
            message = input()
            if message.lower() == "exit":
                print("Вихід із чату...")
                break
            secure_sock.sendall(message.encode("utf-8"))
    except Exception as e:
        logging.error(f"Error sending message: {e}")
        print("Помилка при надсиланні повідомлення.")
    finally:
        secure_sock.close()

def authenticate(secure_sock):
    try:
        while True:
            option = input("LOGIN_OR_REGISTER: ").strip()
            secure_sock.sendall(option.encode())

            if option.upper() == "LOGIN":
                username = input("USERNAME: ").strip()
                password = input("PASSWORD: ").strip()
                secure_sock.sendall(username.encode())
                secure_sock.sendall(password.encode())

                response = secure_sock.recv(1024).decode()
                if response == "LOGIN_SUCCESS":
                    print(f"You are logged in as {username}.")
                    logging.info(f"User {username} logged in successfully.")
                    return username
                else:
                    print("Login failed. Try again.")

            elif option.upper() == "REGISTER":
                username = input("USERNAME: ").strip()
                secure_sock.sendall(username.encode())

                response = secure_sock.recv(1024).decode()
                if response == "USERNAME_TAKEN":
                    print("This username is already taken. Try again.")
                    continue

                password = input("PASSWORD: ").strip()
                secure_sock.sendall(password.encode())

                response = secure_sock.recv(1024).decode()
                if response == "REGISTER_SUCCESS":
                    print(f"You are registered and logged in as {username}.")
                    logging.info(f"User {username} registered successfully.")
                    return username
                else:
                    print("Registration failed. Try again.")
            else:
                print("Invalid option. Please enter LOGIN or REGISTER.")
    except Exception as e:
        logging.error(f"Authentication error: {e}")
        print("Помилка автентифікації.")
        return None

# Основна функція для запуску клієнта
def main():
    secure_sock = create_connection()
    if secure_sock is None:
        return

    # Запуск потоків для отримання та надсилання повідомлень
    receive_thread = threading.Thread(target=receive_messages, args=(secure_sock,), daemon=True)
    send_thread = threading.Thread(target=send_messages, args=(secure_sock,), daemon=True)

    receive_thread.start()
    send_thread.start()

    # Очікування завершення потоків
    receive_thread.join()
    send_thread.join()

if __name__ == "__main__":
    main()
