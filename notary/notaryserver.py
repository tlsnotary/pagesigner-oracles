#!/usr/bin/env python
import base64, hashlib, os
import socket, sys, time
import subprocess
import threading
import random
import string

mps = {}
mpsLock = threading.Lock()

reliable_sites = {} #format {'github.com': {'expires':'date', 'modulus':data}, 'archive.org': {...}   }

def import_reliable_sites(d):
    with open(os.path.join(d,'pubkeys.txt'),'rb') as f: raw = f.read()
    lines = raw.decode().split('\n')
    name = ''
    expires = ''
    modulus = ''
    i = -1
    while True:
        i += 1
        if i >= len(lines):
            break
        x = lines[i]
        if x.startswith('#'):
            continue
        elif x.startswith('Name='):
            name=x[len('Name='):]
        elif x.startswith('Expires='):
            expires=x[len('Expires='):]
        elif x.startswith('Modulus='):
            mod_str = ''
            while True:                
                i +=1
                if i >= len(lines):
                    break
                line = lines[i]
                if line == '':
                    break
                mod_str += line
            reliable_sites[name] = {'expires':expires, 'modulus':bytes.fromhex(mod_str)}



class MessageProcessor(object):
    def __init__(self):
        self.id = None
        self.tlsns = shared.TLSNClientSession()
        self.state = 0
        self.time_last_seen = int(time.time())

    def process_messages(self, request, b64data):
        if request == 'rcr_rsr_rsname_n' and self.state == 0:
            msg_data = base64.b64decode(b64data)
            rss = shared.TLSNClientSession()
            rss.client_random = msg_data[:32]
            rss.server_random = msg_data[32:64]
            rs_choice_first5 = msg_data[64:69].decode()
            rs_choice = [k for k in  reliable_sites.keys() if k.startswith(rs_choice_first5)][0]
            if not rs_choice:
                raise Exception('Unknown reliable site', rs_choice_first5)
            n = msg_data[69:]
            rss.server_modulus = reliable_sites[rs_choice]['modulus']
            rss.server_mod_length = len(rss.server_modulus)
            rss.set_auditor_secret()
            rss.set_enc_second_half_pms()           
            rrsapms = rss.enc_second_half_pms

            self.tlsns.auditor_secret, self.tlsns.auditor_padding_secret=rss.auditor_secret, rss.auditor_padding_secret
            self.tlsns.server_mod_length, self.tlsns.server_modulus = len(n), n
            self.tlsns.set_enc_second_half_pms()
            self.time_last_seen = int(time.time())      
            return 'rrsapms_rhmac_rsapms', base64.b64encode(rrsapms+rss.p_auditor+self.tlsns.enc_second_half_pms)

        elif request == 'cs_cr_sr_hmacms_verifymd5sha' and self.state == 0: 
            self.state = 1
            data = base64.b64decode(b64data)
            assert len(data) == 125
            self.tlsns.chosen_cipher_suite = int.from_bytes(data[:1], 'big')
            self.tlsns.client_random = data[1:33]
            self.tlsns.server_random = data[33:65]
            md5_hmac1_for_ms=data[65:89]
            verify_md5 = data[89:105]
            verify_sha = data[105:125]
            self.tlsns.set_auditor_secret()
            self.tlsns.set_master_secret_half(half=1,provided_p_value=md5_hmac1_for_ms)         
            garbageized_hmac = self.tlsns.get_p_value_ms('auditor',[2]) #withhold the server mac
            hmac_verify_md5 = self.tlsns.get_verify_hmac(verify_sha, verify_md5, half=1)	
            hmacms_hmacek_hmacverify = self.tlsns.p_auditor[24:]+garbageized_hmac+hmac_verify_md5
            self.time_last_seen = int(time.time())
            return 'hmacms_hmacek_hmacverify', base64.b64encode(hmacms_hmacek_hmacverify)

        elif  request == 'verify_md5sha2' and self.state == 1:
            self.state = 2
            md5sha2 = base64.b64decode(b64data)
            md5hmac2 = self.tlsns.get_verify_hmac(md5sha2[16:],md5sha2[:16],half=1,is_for_client=False)
            self.time_last_seen = int(time.time())
            return 'verify_hmac2',  base64.b64encode(md5hmac2)

        elif request == 'commit_hash' and self.state == 2:
            commit_hash = base64.b64decode(b64data)
            response_hash = commit_hash[:32]
            time_bytes = int(time.time()).to_bytes(4, byteorder='big')
            data_to_be_signed = hashlib.sha256(response_hash + self.tlsns.pms2 + self.tlsns.server_modulus + time_bytes).digest()

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_address = ('127.0.0.1', 10003)
            sock.connect(server_address)
            sock.send(data_to_be_signed)
            signing_server_sig = sock.recv(512)
            sock.close()
            return 'pms2', base64.b64encode(self.tlsns.pms2+signing_server_sig+time_bytes)
        else:
            raise Exception("invalid request process_messages")


def handler(sock):
#only process one request and close the socket
    global mps
    try:
        sock.settimeout(1)
        raw = sock.recv(2048)
        if not raw:
            sock.close()
            return
        lines = raw.decode().split('\r\n')
        request = None
        data = None
        uid = None
        for x in lines:
            if x.startswith('Request: '):
                request = x[len('Request: '):]
                continue
            elif x.startswith('Data: '):
                data = x[len('Data: '):]
                continue
            elif x.startswith('UID: '):
                uid = x[len('UID: '):]
                continue
        if (not request or not data or not uid):
            sock.close()
            return
        if len(uid) != 10:
            sock.close()
            return
        if uid not in mps:
            mp = MessageProcessor()
            mp.id = uid
            mpsLock.acquire(True)
            mps[uid] = mp
            mpsLock.release()
    
        response, respdata = mps[uid].process_messages(request, data)
        raw_response = ('HTTP/1.0 200 OK\r\n'+ \
            'Access-Control-Allow-Origin: *\r\n'+ \
            'Access-Control-Expose-Headers: Response,Data\r\n'+ \
            'Response: '+response+'\r\n'+ \
            'Data: '+respdata.decode()+'\r\n\r\n').encode()

        sock.send(raw_response)
        sock.close()
    except: #e.g. base64 decode exception
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
    proj_dir = os.path.dirname(os.path.realpath(__file__))
    sys.path.append(proj_dir)
    import shared
    import_reliable_sites(proj_dir)

    threading.Thread(target=mps_purge).start()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_address = ('0.0.0.0', 10011)
    sock.bind(server_address)
    sock.listen(100) #as many as possible
    while True:
        try:
            connection, client_address = sock.accept()
            threading.Thread(target=handler, args=(connection,)).start()
        except Exception as e:
            print('Exception in notaryserver.py', e)
            pass
