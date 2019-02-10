import socket
import ssl

#this is needed becaus some wiered bug - see https://stackoverflow.com/a/29977034 and https://stackoverflow.com/a/43191101
ssl.match_hostname = lambda cert, hostname: True

HOST, PORT, CERT = '', 443, '/usr/src/app/python/cwCA/intermediate/certs/ca-chain.cert.pem'



#!/usr/bin/python3
"""
from socket import AF_INET, SOCK_STREAM, SO_REUSEADDR, SOL_SOCKET, SHUT_RDWR
#import ssl

listen_addr = ''
listen_port = 443
server_cert = '/usr/src/app/python/cwCA/intermediate/certs/full-ca-chain.cert.pem'
#server_cert = '/usr/src/app/python/cwCA/intermediate/certs/www.ap.controlware.com.cert.pem'
server_key = '/usr/src/app/python/cwCA/intermediate/private/www.ap.controlware.com.key.pem'
client_certs = '/usr/src/app/python/cwCA/certs/ca.cert.pem'

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
#context.verify_mode = ssl.CERT_REQUIRED
context.load_cert_chain(certfile=server_cert, keyfile=server_key)
#context.load_verify_locations(cafile=client_certs)

bindsocket = socket.socket()
bindsocket.bind((listen_addr, listen_port))
bindsocket.listen(5)

while True:
    print("Waiting for client")
    newsocket, fromaddr = bindsocket.accept()
    print("Client connected: {}:{}".format(fromaddr[0], fromaddr[1]))
    conn = context.wrap_socket(newsocket, server_side=True)
    print("SSL established. Peer: {}".format(conn.getpeercert()))
    buf = b''  # Buffer to hold received client data
    try:
        while True:
            data = conn.recv(4096)
            if data:
                # Client sent us data. Append to buffer
                buf += data
            else:
                # No more data from client. Show buffer and close connection.
                print("Received:", buf)
                break
    finally:
        print("Closing connection")
        conn.shutdown(socket.SHUT_RDWR)
        conn.close()

exit()

"""
from cbor import dumps, loads
import OpenSSL.crypto

def verifyString(cert, sign, stringToVerify, algo):
    try:
        result = OpenSSL.crypto.verify(cert, sign, stringToVerify , algo)
        print("signature verified")
        return True
    except Exception as e:
        print(e)
        print("verify failed")
        return False

def getCertStringfromFile(filepath):
    with open(filepath, 'r') as myfile:
        fileString=myfile.read()#.replace('\n', '')
    myfile.close()
    return fileString

def handle(conn):
    byte_voucher = conn.recv(4096)
    #print(byte_voucher)
    tmp_voucher = loads(byte_voucher)
    #print(type(test), test)
    if 'voucher-request' not in tmp_voucher:
        print("cant handle msg")
    else:
        voucher = tmp_voucher['voucher-request']
        print(voucher["request"])
        print(voucher["signature"])
        request_artifact = loads(voucher["request"])
        manufacturerCert = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM,
            #request_artifact["devID"]  #lazy way just take cert from the message
            getCertStringfromFile('/usr/src/app/python/vendorCA/8021ARintermediate/certs/Dev1234.cert.pem')
        )

        verifyString(manufacturerCert, voucher["signature"], voucher["request"], "sha256")


    #print(request["nonce"])
    #print(request["created-on"])


    conn.write(b'HTTP/1.1 200 OK\n\n%s' % conn.getpeername()[0].encode())



def main():
  sock = socket.socket()
  sock.bind((HOST, PORT))
  sock.listen(5)
  context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
  context.load_cert_chain('/usr/src/app/python/cwCA/intermediate/certs/full-ca-chain.cert.pem', '/usr/src/app/python/cwCA/intermediate/private/www.ap.controlware.com.key.pem', password='password')
  context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # optional
  #context.verify_mode = ssl.CERT_REQUIRED
  context.set_ciphers('EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH')
  while True:
    conn = None
    ssock, addr = sock.accept()
    try:
      conn = context.wrap_socket(ssock, server_side=True)
      print ("cert:", conn.getpeercert())
      print("SSL established. Peer: {}".format(conn.getpeercert()))
      handle(conn)
    except ssl.SSLError as e:
      print(e)
    finally:
      if conn:
        conn.close()
if __name__ == '__main__':
  main()
