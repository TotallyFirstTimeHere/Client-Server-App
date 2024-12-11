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
context.check_hostname = False  # Якщо ви використовуєте самопідписаний сертифікат
context.verify_mode = ssl.CERT_REQUIRED

# Створення TCP-з'єднання з сервером через SSL
def create_connection():
    try:
        # Створення TCP-з'єднання
        sock = socket.create_connection((HOST, PORT))
        secure_sock = context.wrap_socket(sock, server_hostname=HOST)
        logging.info("Connected to server with SSL.")
        print("Підключено до сервера з SSL.")
        return secure_sock
    except Exception as e:
        logging.error(f"Connection error: {e}")
        print(f"Помилка підключення: {e}")
        return None

# Функція для коректного завершення програми
def exit_gracefully(secure_sock):
    print("\nВихід з програми...")
    secure_sock.close()

# Взаємодія з сервером (автентифікація, надсилання/отримання повідомлень)
def authenticate_and_communicate(secure_sock):
    try:
        while True:
            server_message = secure_sock.recv(1024).decode()
            if not server_message:
                logging.info("Server closed the connection.")
                break
            print(f"Сервер: {server_message}")

            if server_message.endswith(":"):  # Запит на введення користувача
                user_input = input()
                secure_sock.sendall(user_input.encode())

            elif server_message == "LOGIN_SUCCESS" or server_message == "REGISTER_SUCCESS":
                print("Успішно!")
            elif server_message == "LOGIN_FAILED":
                print("Невдалий вхід. Спробуйте ще раз.")
            elif server_message == "USERNAME_TAKEN":
                print("Ім'я користувача вже зайняте.")
            elif server_message == "AUTH_ERROR":
                print("Помилка автентифікації.")
            elif server_message.startswith("ERROR:"):
                print(server_message)
            else:
                # Можливо, це повідомлення від інших користувачів
                print(server_message)
    except Exception as e:
        logging.error(f"Error during communication: {e}")
        print(f"Помилка під час взаємодії з сервером: {e}")

# Функція для отримання повідомлень від сервера в окремому потоці
def receive_messages(secure_sock):
    try:
        while True:
            message = secure_sock.recv(1024).decode("utf-8")
            if message:
                print(message)
            else:
                break
    except Exception as e:
        logging.error(f"Error receiving message: {e}")
        print("Помилка отримання повідомлення.")
        secure_sock.close()

# Функція для надсилання повідомлень серверу
def send_messages(secure_sock):
    try:
        while True:
            message = input("")
            secure_sock.send(message.encode("utf-8"))
    except Exception as e:
        logging.error(f"Error sending message: {e}")
        print("Помилка при надсиланні повідомлення.")
        secure_sock.close()

# Основна функція для запуску клієнта
def main():
    secure_sock = create_connection()
    if secure_sock is None:
        return

    # Запуск автентифікації та взаємодії з сервером
    authenticate_and_communicate(secure_sock)

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
