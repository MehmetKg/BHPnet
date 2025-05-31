import sys
import socket
import getopt
import threading
import subprocess
import os
import ssl
import logging
from datetime import datetime

# Opsiyonel: Renkli log çıktısı için colorlog kullan
try:
    from colorlog import ColoredFormatter
    use_colorlog = True
except ImportError:
    use_colorlog = False

# Global değişkenler
listen = False
command = False
upload = False
execute = ""
target = ""
upload_destination = ""
port = 0
use_ssl = False
verbose = False
log_file = ""

# Komut beyaz listesi (isteğe bağlı güvenlik için)
ALLOWED_COMMANDS = ["ls", "dir", "whoami", "hostname", "ipconfig", "ifconfig"]

# Logging konfigürasyonu

def setup_logging():
    if use_colorlog:
        formatter = ColoredFormatter(
            "%(log_color)s%(asctime)s - %(levelname)s - %(message)s",
            log_colors={
                'DEBUG': 'cyan',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'bold_red',
            }
        )
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
    else:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

    logger = logging.getLogger('bhpnet')
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.addHandler(handler)

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(file_handler)

    return logger

logger = setup_logging()


def usage():
    print("Geliştirilmiş BHP Net Tool")
    print("\nKullanım: bhpnet.py -t hedef_ip -p port")
    print("-l --listen               - Dinleme moduna geç")
    print("-e --execute=dosya        - Bağlantı alınınca çalıştırılacak dosya")
    print("-c --command              - Komut satırı aç")
    print("-u --upload=dosya         - Bağlantı sonrası dosya yükleme")
    print("-s --ssl                  - SSL/TLS şifreleme kullan")
    print("-v --verbose              - Detaylı çıktı")
    print("--log=dosya.log           - Logları dosyaya yaz")
    sys.exit(0)


def main():
    global listen, port, execute, command, upload_destination, target, use_ssl, verbose, log_file, logger

    if not len(sys.argv[1:]):
        usage()

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hle:t:p:cu:sv", [
            "help", "listen", "execute=", "target=", "port=", "command",
            "upload=", "ssl", "verbose", "log="
        ])
    except getopt.GetoptError as err:
        print(str(err))
        usage()

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
        elif o in ("-l", "--listen"):
            listen = True
        elif o in ("-e", "--execute"):
            execute = a
        elif o in ("-c", "--command"):
            command = True
        elif o in ("-u", "--upload"):
            upload_destination = a
        elif o in ("-t", "--target"):
            target = a
        elif o in ("-p", "--port"):
            port = int(a)
        elif o in ("-s", "--ssl"):
            use_ssl = True
        elif o in ("-v", "--verbose"):
            verbose = True
        elif o == "--log":
            log_file = a

    logger = setup_logging()

    if use_ssl and (not os.path.exists("server.crt") or not os.path.exists("server.key")):
        logger.critical("SSL is enabled but certificates are missing.")
        sys.exit("[!] SSL sertifikaları eksik. Kapatılıyor...")

    if not listen and target and port > 0:
        buffer = sys.stdin.read()
        client_sender(buffer)

    if listen:
        server_loop()


def create_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if use_ssl:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile="server.crt", keyfile="server.key")
        return context.wrap_socket(sock, server_side=listen)
    return sock


def client_sender(buffer):
    try:
        client = create_socket()
        client.connect((target, port))
        logger.info(f"Connected to {target}:{port}")

        if len(buffer):
            client.send(buffer.encode())

        while True:
            response = ""
            while True:
                data = client.recv(4096).decode(errors='ignore')
                if not data:
                    break
                response += data
                if len(data) < 4096:
                    break

            if not response:
                break

            print(response, end='')

            buffer = input("") + "\n"
            client.send(buffer.encode())

    except Exception as e:
        logger.error(f"Exception in client_sender: {e}")
        print(f"[*] Exception! Exiting: {e}")
    finally:
        client.close()
        logger.info("Connection closed")


def server_loop():
    global target

    if not len(target):
        target = "0.0.0.0"

    server = create_socket()
    server.bind((target, port))
    server.listen(5)
    logger.info(f"Server listening on {target}:{port}")

    try:
        while True:
            client_socket, addr = server.accept()
            logger.info(f"Accepted connection from {addr[0]}:{addr[1]}")
            client_socket.settimeout(60)
            client_thread = threading.Thread(target=client_handler, args=(client_socket,))
            client_thread.start()
    except KeyboardInterrupt:
        logger.info("Server shutting down...")
    finally:
        server.close()


def run_command(command):
    command = command.strip()
    if not any(command.startswith(c) for c in ALLOWED_COMMANDS):
        return b"Command not allowed.\n"
    try:
        return subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True)
    except Exception as e:
        return f"Command execution failed: {str(e)}\n".encode()


def client_handler(client_socket):
    global upload_destination, execute, command

    try:
        if upload_destination:
            file_buffer = b""
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break
                file_buffer += data
                client_socket.send(f"Received {len(file_buffer)} bytes\r\n".encode())

            safe_path = os.path.abspath(upload_destination)
            if not safe_path.startswith(os.getcwd()):
                raise Exception("Invalid upload path")

            with open(safe_path, "wb") as f:
                f.write(file_buffer)

            msg = f"Successfully saved file to {safe_path}\n"
            client_socket.send(msg.encode())
            logger.info(msg.strip())

        if execute:
            output = run_command(execute)
            client_socket.send(output)

        if command:
            client_socket.send(b"<BHP:#> ")
            while True:
                cmd_buffer = ""
                while "\n" not in cmd_buffer:
                    data = client_socket.recv(1024).decode(errors='ignore')
                    if not data:
                        return
                    cmd_buffer += data

                response = run_command(cmd_buffer)
                client_socket.send(response + b"<BHP:#> ")

    except Exception as e:
        logger.error(f"Error in client_handler: {e}")
    finally:
        client_socket.close()
        logger.info("Client connection closed")


if __name__ == '__main__':
    main()
