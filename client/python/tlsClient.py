import socket
import ssl

hostname = '172.20.0.2'

HOST, PORT = '172.20.0.2', 443
#context = ssl.create_default_context()
def handle(conn):
    conn.write(b'GET / HTTP/1.1\n')
    print(conn.recv().decode())

def main():
    sock = socket.socket(socket.AF_INET)
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # optional
    conn = context.wrap_socket(sock, server_hostname=HOST)
    try:
        conn.connect((HOST, PORT))
        handle(conn)
    finally:
        conn.close()

if __name__ == '__main__':
    main()
