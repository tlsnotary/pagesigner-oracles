import socket
import subprocess
import threading
import random
import string
import os

def handler(sock, addr):
  try:
    sock.settimeout(1)
    data = sock.recv(32)
    myuid = '/dev/shm/' + ''.join(random.choice(string.ascii_letters + string.digits) for x in range(10))
    with open(myuid, 'wb') as f: f.write(data)
    mysig = subprocess.check_output(['openssl','rsautl','-sign','-inkey', '/dev/shm/private.pem' ,'-keyform','PEM', '-in', myuid])
    os.remove(myuid)
    sock.send(mysig)
    sock.close()
  except:
    sock.close()


if __name__ == "__main__":
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  server_address = ('127.0.0.1', 10003)
  sock.bind(server_address)
  sock.listen(100) #as many as possible
  while True:
    connection, client_address = sock.accept()
    threading.Thread(target=handler, args=(connection, client_address)).start()