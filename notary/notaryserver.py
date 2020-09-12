#!/usr/bin/env python
import base64, hashlib, os
import socket, sys, time
import subprocess
import threading
import random
import string
import hmac
import json

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

shared_memory = '/dev/shm/'

mps = {}
mpsLock = threading.Lock()


def rand_str():
    return ''.join(random.choice(string.ascii_letters + string.digits) for x in range(10))

def generateECKeypair():
    privDER = subprocess.check_output([
            'openssl',
            'ecparam',
            '-name',
            'prime256v1',
            '-genkey',
            '-outform',
            'der'])

    privpath = os.path.join(shared_memory, rand_str()+'.der')
    with open(privpath, 'wb') as f:
        f.write(privDER)

    pubDER = subprocess.check_output([
            'openssl',
            'ec',
            '-in',
            privpath,
            '-inform',
            'der',
            '-pubout',
            '-outform',
            'der'])

    os.remove(privpath)
    return (privDER, pubDER)


def getECDHSecret (myPrivDER, hisPubRaw):
    #asn1 encoding which has to be prepared to the raw pubkey to make it DER-formatted 
    #so that openssl can work with it
    preasn1 = b'\x30\x59\x30\x13\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07\x03\x42\x00'
    pubpath = os.path.join(shared_memory, rand_str()+'.der')
    with open(pubpath, 'wb') as f:
        f.write( preasn1 + hisPubRaw)

    privpath = os.path.join(shared_memory, rand_str()+'.der')
    with open(privpath, 'wb') as f:  
        f.write(myPrivDER)

    secret = subprocess.check_output([
                'openssl',
                'pkeyutl',
                '-derive',
                '-inkey',
                privpath,
                '-keyform',
                'der',
                '-peerkey',
                pubpath,
                '-peerform',
                'der'])

    os.remove(pubpath)
    os.remove(privpath)
    return secret

def AESGCMencrypt (key, data):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return (nonce+ciphertext)
    print('ciphertext', len(ciphertext), len(data))

    


    

class MessageProcessor(object):
    def __init__(self):
        self.id = None
        self.state = 0
        self.time_last_seen = int(time.time())
        self.ms = None
        self.commSymmetricKey = None #used to en/decrypt messages to/from the auditee
        self.client_write_key = None
        self.server_write_key = None
        self.client_write_IV = None
        self.server_write_IV = None
        self.ECpubkey = None 
        self.ECprivkey = None ##to be included in the sigserver's signature
        self.server_pubkey = None #to be included in the sigserver's signature
        self.commit_hash = None #to be included in the sigserver's signature

    def process_messages(self, request, b64data):
        print('self.state', self.state)
        if request == 'cr_sr_spk_commpk' and self.state == 0:
            self.state = 1
            msg_data = base64.b64decode(b64data)
            client_random = msg_data[:32]
            server_random = msg_data[32:64]
            self.server_pubkey = msg_data[64:129]
            comm_peerkey = msg_data[129:194] #The other party's pubkey for ECDH
            print('comm_peerkey', len(comm_peerkey))

            #derive ECDH shared secret for communication
            commPrivDER, commPubDER = generateECKeypair()
            commPubkey = commPubDER[-65:]
            #all future sensitive data will be encrypted with this key
            self.commSymmetricKey = getECDHSecret(commPrivDER, comm_peerkey)[:16]


            ECprivDER, ECpubDER = generateECKeypair()
            self.ECprivkey = ECprivDER[7:39]
            self.ECpubkey = ECpubDER[-65:]
            secret = getECDHSecret(ECprivDER, self.server_pubkey)

            #Calculate master secret
            seed = str.encode("master secret") + client_random + server_random
            a0 = seed
            a1 = hmac.new(secret, a0, hashlib.sha256).digest()
            a2 = hmac.new(secret, a1, hashlib.sha256).digest()
            p1 = hmac.new(secret, a1+seed, hashlib.sha256).digest()
            p2 = hmac.new(secret, a2+seed, hashlib.sha256).digest()
            ms = (p1+p2)[0:48]
            self.ms = ms

            #Expand keys
            seed = str.encode("key expansion") + server_random + client_random
            a0 = seed
            a1 = hmac.new(ms , a0, hashlib.sha256).digest()
            a2 = hmac.new(ms , a1, hashlib.sha256).digest()
            p1 = hmac.new(ms, a1+seed, hashlib.sha256).digest()
            p2 = hmac.new(ms, a2+seed, hashlib.sha256).digest()
            ek = (p1 + p2)[:40]
            #AES GCM doesnt need MAC keys
            self.client_write_key = ek[:16]
            self.server_write_key = ek[16:32]
            self.client_write_IV = ek[32:36]
            self.server_write_IV = ek[36:40]
            return 'cpk_commpk', base64.b64encode(self.ECpubkey + commPubkey)



        elif request == 'hshash' and self.state == 1: 
            self.state = 2
            hs_hash = base64.b64decode(b64data)
            assert len(hs_hash) == 32
            
            seed = str.encode('client finished') + hs_hash
            a0 = seed
            a1 = hmac.new(self.ms, a0, hashlib.sha256).digest()
            p1 = hmac.new(self.ms, a1+seed, hashlib.sha256).digest()
            verify_data = p1[:12]

            enc = AESGCMencrypt(self.commSymmetricKey, verify_data + self.client_write_key + self.client_write_IV)
            return 'vd_cwk_cwi', base64.b64encode(enc)




        elif request == 'encf_hshash2' and self.state == 2:
            self.state = 3
            data = base64.b64decode(b64data)
            assert(len(data) == 72)
            enc_f = data[:40]
            hshash2 = data[40:72]

            explicit_nonce = enc_f[:8]
            nonce = self.server_write_IV + explicit_nonce

            aad = b'' #additional_data
            aad += b'\x00\x00\x00\x00\x00\x00\x00\x00' #seq num 0
            aad += b'\x16' # type 0x16 = Handshake
            aad += b'\x03\x03' # TLS Version 1.2
            aad += b'\x00\x10' # 16 bytes of unencrypted data
            
            aesgcm = AESGCM(self.server_write_key)
            server_finished = aesgcm.decrypt(nonce, enc_f[8:40], aad)

            assert (server_finished[:4] == b'\x14\x00\x00\x0c')
            server_verify = server_finished[4:]

            seed = str.encode('server finished') + hshash2
            a0 = seed
            a1 = hmac.new(self.ms, a0, hashlib.sha256).digest()
            p1 = hmac.new(self.ms, a1+seed, hashlib.sha256).digest()
            verify_data = p1[:12]

            reply = b'\x00'
            if (server_verify == verify_data):
              reply = b'\x01'

            return 'verify_status',  base64.b64encode(reply)



        elif request == 'commithash' and self.state == 3:
            self.state = 4
            data = base64.b64decode(b64data)
            self.commit_hash = data[:32]
            
            time_bytes = int(time.time()).to_bytes(4, byteorder='big')
            data_to_be_signed = hashlib.sha256(self.ECprivkey + self.server_pubkey + self.commit_hash + time_bytes).digest()

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_address = ('127.0.0.1', 10003)
            sock.connect(server_address)
            sock.send(data_to_be_signed)
            signing_server_sig = sock.recv(80) #the sig is of variable length usually around 68-72 for P-256
            sig_len = len(signing_server_sig).to_bytes(1, byteorder='big')
            sock.close()

            enc = AESGCMencrypt(self.commSymmetricKey, self.server_write_key + self.server_write_IV + 
                sig_len + signing_server_sig + self.ECprivkey + self.ECpubkey + time_bytes)
            return 'swk_swi_sig_ecpriv_ecpub_time', base64.b64encode(enc)
        else:
            raise Exception("invalid request process_messages")


def handler(sock):
#only process one request and close the socket
    print('Handling a new connection', sock.fileno())
    global mps
    raw = None
    try:
        sock.settimeout(5)
        raw = sock.recv(2048)
        if not raw:
            print('No data received', sock.fileno())
            sock.close()
            return
        #/r/n/r//n separates the headers from the POST payload 
        payload = raw.decode().split('\r\n\r\n')[1]
        json_object = json.loads(payload)
        request = json_object['request']
        data = json_object['data']
        uid = json_object['uid']
        if (not request or not data or not uid):
            print('One of the headers missing', sock.fileno())
            sock.close()
            return
        if len(uid) != 10:
            print('UID length incorrect', sock.fileno())
            sock.close()
            return
        print('Processing message', request, sock.fileno())
        if uid not in mps:
            mp = MessageProcessor()
            mp.id = uid
            mpsLock.acquire(True)
            mps[uid] = mp
            mpsLock.release()
    
        response, respdata = mps[uid].process_messages(request, data)
        payload = json.dumps({'response':response, 'data':respdata.decode()})
        raw_response = ('HTTP/1.0 200 OK\r\n'+ \
            'Access-Control-Allow-Origin: *\r\n'+ \
                '\r\n\r\n'+ payload).encode()

        sock.send(raw_response)
        print('Sent response', response, sock.fileno())
        sock.close()
    except Exception as e: #e.g. base64 decode exception
        print('Exception while handling connection', sock.fileno(), e, raw)
        sock.close()


#purge old entries from mps
def mps_purge():
    global mps
    while True:
        time.sleep(1)
        mpsLock.acquire(True)
        now = int(time.time())
        for k,v in mps.items():
            if (now - v.time_last_seen) > 30:
                del mps[k]
                #if after deleting we continue iterating, we'll get the Error: dictionary changed size during iteration
                break 
        mpsLock.release()


if __name__ == "__main__":
    
    print('TLSNotary server started')
    threading.Thread(target=mps_purge).start()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_address = ('0.0.0.0', 10011)
    sock.bind(server_address)
    sock.listen(100) #as many as possible
    connection_number = 0
    while True:
        try:
            print('Waiting for a new connection')
            connection, client_address = sock.accept()
            connection_number += 1
            print('Connection accepted', connection_number)
            threading.Thread(target=handler, args=(connection,)).start()
        except Exception as e:
            print('Exception in notaryserver.py', e)
            pass
