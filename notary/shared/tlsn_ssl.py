import math, os, binascii, hmac
from hashlib import md5, sha1
#constants
md5_hash_len = 16
sha1_hash_len = 20
aes_block_size = 16
tls_ver_1_0 = b'\x03\x01'
tls_ver_1_1 = b'\x03\x02'
tls_versions = [tls_ver_1_0,tls_ver_1_1]
"""The amount of key material for each ciphersuite:
AES256-CBC-SHA: mac key 20*2, encryption key 32*2, IV 16*2 == 136bytes
AES128-CBC-SHA: mac key 20*2, encryption key 16*2, IV 16*2 == 104bytes
RC4128_SHA: mac key 20*2, encryption key 16*2 == 72bytes
RC4128_MD5: mac key 16*2, encryption key 16*2 == 64 bytes"""
tlsn_cipher_suites =  {47:['AES128',20,20,16,16,16,16],\
                    53:['AES256',20,20,32,32,16,16],\
                    5:['RC4SHA',20,20,16,16,0,0],\
                    4:['RC4MD5',16,16,16,16,0,0]}
#preprocessing: add the total number of bytes in the expanded keys format
#for each cipher suite, for ease of reference
for v in tlsn_cipher_suites.values():
    v.append(sum(v[1:]))


def bi2ba(bigint,fixed=None):
    m_bytes = []
    while bigint != 0:
        b = bigint%256
        m_bytes.insert( 0, b )
        bigint //= 256
    if fixed:
        padding = fixed - len(m_bytes)
        if padding > 0: m_bytes = [0]*padding + m_bytes
    return bytes(m_bytes)

def xor(a,b):
    return bytes(a^b for a,b in zip(a,b))

#convert bytearray into int
def ba2int(byte_array):
    return int.from_bytes(byte_array, 'big')



class TLSNSSLError(Exception):
    def __init__(self, msg, data=None):
        self.msg = msg
        if data:
            self.data = binascii.hexlify(data)
        else:
            self.data = ''
            
    def __str__(self):
            return self.msg + ': ' + self.data    

def ssl_dump(session, fn=None):
    #Note that this dump write could be encapsulated
    #in the TLSNSSLError class, but the session object
    #is not always available in context.
    filename = 'ssldump' if not fn else fn
    with open(filename,'wb') as f:
        f.write(session.dump())    
    
class TLSNClientSession(object):
    def __init__(self,server=None,port=443,ccs=None, tlsver=None):
        self.server_name = server
        self.ssl_port = port
        self.initial_tlsver = tlsver
        #current TLS version may be downgraded
        self.tlsver = tlsver
        self.n_auditee_entropy = 12
        self.n_auditor_entropy = 9
        self.auditor_secret = None
        self.auditee_secret = None
        self.auditor_padding_secret = None
        self.auditee_padding_secret = None
        self.pms1 = None #auditee's
        self.pms2 = None #auditor's
        self.enc_first_half_pms = None
        self.enc_second_half_pms = None
        self.enc_pms = None
        #client hello, server hello, certificate, server hello done,
        #client key exchange, change cipher spec, finished
        self.handshake_messages = [None] * 7
        self.handshake_hash_sha = None
        self.handshake_hash_md5 = None
        self.p_auditor = None
        self.p_auditee = None
        self.master_secret_half_auditor = None
        self.master_secret_half_auditee = None
        self.p_master_secret_auditor = None
        self.p_master_secret_auditee = None
        self.server_mac_key = None
        self.client_mac_key = None
        self.server_enc_key = None
        self.client_enc_key = None
        self.serverIV = None
        self.clientIV = None
        self.server_certificate = None
        self.server_modulus = None
        self.server_exponent = 65537
        self.server_mod_length = None

        #array of ciphertexts from each SSL record
        self.server_response_app_data=[]
        
        #unexpected app data is defined as that received after 
        #server finished, but before client request. This will
        #be decrypted, but not included in plaintext result.
        self.unexpected_server_app_data_count = 0
        self.unexpected_server_app_data_raw = ''
        
        #the HMAC required to construct the verify data
        #for the server Finished record
        self.verify_hmac_for_server_finished = None
        
        #for certain testing cases we want to limit the
        #choice of cipher suite to 1, otherwise we use
        #the globally defined standard 4:
        self.offered_cipher_suites = \
            {k: v for k,v in tlsn_cipher_suites.items() if k==ccs} \
            if ccs else tlsn_cipher_suites
        
        self.chosen_cipher_suite = ccs
     
    def dump(self):
        return_str='Session state dump: \n'
        for k,v in self.__dict__.iteritems():
            return_str += k + '\n'
            if type(v) == type(str()):
                return_str += 'string: len:'+str(len(v)) + '\n'
                return_str += v + '\n'
            elif type(v) == type(bytes()):
                return_str += 'bytearray: len:'+str(len(v)) + '\n'
                return_str += binascii.hexlify(v) + '\n'
            else:
                return_str += str(v) + '\n'
        return return_str
            
    def get_verify_data_for_finished(self,sha_verify=None,md5_verify=None,\
                                     half=1,provided_p_value=None,is_for_client=True):
        if not (sha_verify and md5_verify):
            sha_verify, md5_verify = self.handshake_hash_sha, self.handshake_hash_md5

        #we calculate based on provided hmac by the other party
        return xor(provided_p_value[:12],\
                   self.get_verify_hmac(sha_verify=sha_verify,md5_verify=md5_verify,\
                                        half=half,is_for_client=is_for_client))   
        
    def set_encrypted_pms(self):
        if not (self.enc_first_half_pms and self.enc_second_half_pms and self.server_modulus):
            raise TLSNSSLError("Failed to set encpms")
            
        self.enc_pms =  bi2ba (ba2int(self.enc_first_half_pms) * ba2int(self.enc_second_half_pms) % ba2int(self.server_modulus))
        return self.enc_pms
     
    def set_enc_second_half_pms(self):
        if not self.server_modulus:
            raise TLSNSSLError("Failed to set enc second half pms")
        ones_length = 103+self.server_mod_length-256
        self.pms2 =  self.auditor_secret + (b'\x00' * (24-self.n_auditor_entropy-1)) + b'\x01'
        self.enc_second_half_pms = bi2ba( pow( 
            ba2int(b'\x01'+(b'\x01'*(ones_length))+self.auditor_padding_secret+ (b'\x00'*25)+self.pms2),
            self.server_exponent,
            ba2int(self.server_modulus)))

    def set_auditor_secret(self):
        '''Sets up the auditor's half of the preparatory
        secret material to create the master secret, and
        the encrypted premaster secret.
        'secret' should be a bytearray of length n_auditor_entropy'''
        cr = self.client_random
        sr = self.server_random
        if not cr and sr:
            raise TLSNSSLError("one of client or server random not set")
        if not self.auditor_secret:
            self.auditor_secret = os.urandom(self.n_auditor_entropy)
        if not self.auditor_padding_secret:
            self.auditor_padding_secret =  os.urandom(15)
        label = b'master secret'
        seed = cr + sr
        self.pms2 =  self.auditor_secret + (b'\x00' * (24-self.n_auditor_entropy-1)) + b'\x01'
        self.p_auditor = tls_10_prf(label+seed,second_half = self.pms2)[1]
        return (self.p_auditor)        
    
    def set_master_secret_half(self,half=1,provided_p_value=None):
        #non provision of p value means we use the existing p
        #values to calculate the whole MS
        if not provided_p_value:
            self.master_secret_half_auditor = xor(self.p_auditee[:24],self.p_auditor[:24])
            self.master_secret_half_auditee = xor(self.p_auditee[24:],self.p_auditor[24:])
            return self.master_secret_half_auditor+self.master_secret_half_auditee
        assert half in [1,2], "Must provide half argument as 1 or 2"
        #otherwise the p value must be enough to provide one half of MS
        if not len(provided_p_value)==24:
            raise TLSNSSLError("Wrong length of P-hash value for half MS setting.", provided_p_value)
        if half == 1:
            self.master_secret_half_auditor = xor(self.p_auditor[:24],provided_p_value)
            return self.master_secret_half_auditor
        else:
            self.master_secret_half_auditee = xor(self.p_auditee[24:],provided_p_value)
            return self.master_secret_half_auditee 
    
    def get_p_value_ms(self,ctrprty,garbage=[]):
        '''Provide a list of keys that you want to 'garbageize' so as to hide
        that key from the counterparty, in the array 'garbage', each number is
        an index to that key in the cipher_suites dict        
        '''
        if not (self.server_random and self.client_random and self.chosen_cipher_suite):
            raise TLSNSSLError("server random, client random or cipher suite not set.")
        label = b'key expansion'
        seed = self.server_random + self.client_random
        expkeys_len = tlsn_cipher_suites[self.chosen_cipher_suite][-1]        
        if ctrprty == 'auditor':
            self.p_master_secret_auditor = tls_10_prf(label+seed,req_bytes=expkeys_len,first_half=self.master_secret_half_auditor)[0]
        else:
            self.p_master_secret_auditee = tls_10_prf(label+seed,req_bytes=expkeys_len,second_half=self.master_secret_half_auditee)[1]

        tmp = self.p_master_secret_auditor if ctrprty=='auditor' else self.p_master_secret_auditee
        for k in garbage:
            if k==1:
                start = 0
            else:
                start = sum(tlsn_cipher_suites[self.chosen_cipher_suite][1:k])
            end = sum(tlsn_cipher_suites[self.chosen_cipher_suite][1:k+1])
            #ugh, python strings are immutable, what's the elegant way to do this?
            tmp2 = tmp[:start]+os.urandom(end-start)+tmp[end:]
            tmp = tmp2
        return tmp    
    
    def get_verify_hmac(self,sha_verify=None,md5_verify=None,half=1,is_for_client=True):
        '''returns only 12 bytes of hmac'''
        label = b'client finished' if is_for_client else b'server finished'
        seed = md5_verify + sha_verify
        if half==1:
            return tls_10_prf(label+seed,req_bytes=12,first_half = self.master_secret_half_auditor)[0]
        else:
            return tls_10_prf(label+seed,req_bytes=12,second_half = self.master_secret_half_auditee)[1]              
    
    
def tls_10_prf(seed, req_bytes = 48, first_half=None,second_half=None,full_secret=None):
    '''
    Calculates all or part of the pseudo random function PRF
    as defined in the TLS 1.0 RFC 2246 Section 5. If only first_half or
    second_half are provided, then the appropriate HMAC is returned
    as the first or second element of the returned tuple respectively.
    If both are provided, the full result of PRF is provided also in
    the third element of the returned tuple.
    For maximum clarity, variable names correspond to those used in the RFC.
    Notes:
    The caller should provide one or other but not both of first_half and
    second_half - the alternative is to provide full_secret. This is because
    the algorithm for splitting into two halves as described in the RFC,
    which varies depending on whether the secret length is odd or even,
    cannot be correctly deduced from two halves.
    '''
    #sanity checks, (see choices of how to provide secrets under 'Notes' above)
    if not first_half and not second_half and not full_secret:
        raise TLSNSSLError("Error in TLSPRF: at least one half of the secret is required.")
    if (full_secret and first_half) or (full_secret and second_half):
        raise TLSNSSLError("Error in TLSPRF: both full and half secrets should not be provided.")
    if first_half and second_half:
        raise TLSNSSLError("Error in TLSPRF: please provide the secret in the parameter full_secret.")

    P_MD5 = P_SHA_1 = PRF = None

    #split the secret into two halves if necessary
    if full_secret:
        L_S = len(full_secret)
        L_S1 = L_S2 = int(math.ceil(L_S/2))
        first_half = full_secret[:L_S1]
        second_half = full_secret[L_S2:]

    #To calculate P_MD5, we need at most floor(req_bytes/md5_hash_len) iterations
    #of 'A'. If req_bytes is a multiple of md5_hash_len(16), we will use
    #0 bytes of the final iteration, otherwise we will use 1-15 bytes of it.
    #Note that A[0] is actually A(1) in the RFC, since A(0) in the RFC is the seed.
    if first_half:
        A=[hmac.new(first_half,seed,md5).digest()]
        for i in range(1,int(req_bytes/md5_hash_len)+1):
            A.append(hmac.new(first_half,A[len(A)-1],md5).digest())

        md5_P_hash = bytes()
        for x in A:
            md5_P_hash += hmac.new(first_half,x+seed,md5).digest()

        P_MD5 = md5_P_hash[:req_bytes]

    #To calculate P_SHA_1, we need at most floor(req_bytes/sha1_hash_len) iterations
    #of 'A'. If req_bytes is a multiple of sha1_hash_len(20), we will use
    #0 bytes of the final iteration, otherwise we will use 1-19 bytes of it.
    #Note that A[0] is actually A(1) in the RFC, since A(0) in the RFC is the seed.
    if second_half:
        A=[hmac.new(second_half,seed,sha1).digest()]
        for i in range(1,int(req_bytes/sha1_hash_len)+1):
            A.append(hmac.new(second_half,A[len(A)-1],sha1).digest())

        sha1_P_hash = bytes()
        for x in A:
            sha1_P_hash += hmac.new(second_half,x+seed,sha1).digest()

        P_SHA_1 = sha1_P_hash[:req_bytes]

    if full_secret:
        PRF = xor(P_MD5,P_SHA_1)

    return (P_MD5, P_SHA_1, PRF)

#*********************END TLS CODE***************************************************

