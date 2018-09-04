import struct
import socket
from cryptography.hazmat.primitives.asymmetric import padding as padding_RSA
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import AlreadyFinalized
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as padding_SIMM
from socket import error
def read_cert(certname):
    try:
        with open('./cert/'+certname+'.pem', 'rb') as fc:
            server_cert_text = fc.read()
            #server_cert = x509.load_pem_x509_certificate(server_cert_text, backend=default_backend())
        return server_cert_text
    except IOError:
        return None

def load_priv_key(p_key):
    try:
        with open('./priv_key/'+p_key+'.pem', 'rb') as f:
            prvkey_text = bytes(f.read())
            #print prvkey_text
            prvkey = serialization.load_pem_private_key(
                prvkey_text,
                password=None,
                backend=default_backend()
            )
        return prvkey
    except IOError:
        return None

def send_data(conn,data_to_send):
    msg = struct.pack('>I', len(data_to_send)) + data_to_send
    try:
        conn.sendall(msg)
        return True
    except:
        return False
def recv_data(sock, timeout):
    # Read message length and unpack it into an integer
    
    raw_msglen = recvall(sock, 4, timeout)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    #print "msg len", msglen
    # Read the message data
    return recvall(sock, msglen, timeout)

def recvall(sock, n, timeout):
    # Helper function to recv n bytes or return None if EOF is hit
    data = b''
    while len(data) < n:
        try:
            if timeout != 0:
                sock.settimeout(timeout)
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data += packet
        except error as e:
            print e
            return None
    return data

def secure_cmp(a,b):
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    #print result
    return result is 0

def get_hash(bytes_to_hash, salt = ''):
    
    try:
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(bytes_to_hash+salt)
        t = digest.finalize()
        return t
    except AlreadyFinalized:
        print "get_hash"
        return None

def get_kdf(bytes_, salt):
    try:
        backend = default_backend()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=backend
        )
        key = kdf.derive(bytes_)
        return key
    except (TypeError,AlreadyFinalized):
        print "get_kdf"
        return None

def encrypt_AES(msg, key, IV):
    padder = padding_SIMM.PKCS7(128).padder()
    padded_data = padder.update(bytes(msg))
    padded_data += padder.finalize()
    if len(key) is not 32 or len(IV) is not 16:
        print key, IV
        print len(key), len(IV)
        print 'LEN sbagliata'
        return None 
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)
    try:
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        return ct
    except:
        print "encrypt"
        return None

def decrypt_AES(encrypted_data,key, IV):
    if len(key) is not 32 or len(IV) is not 16:
        print key, IV
        print len(key), len(IV)
        print 'LEN sbagliata'
        return None 
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), default_backend())
    try:
        ctx = cipher.decryptor()
        padded_plaintext = ctx.update(encrypted_data) + ctx.finalize()
        ctx = padding_SIMM.PKCS7(128).unpadder()
        plaintext = ctx.update(padded_plaintext) + ctx.finalize()
        return plaintext
    except:
        print "decrypt"
        return None

def decrypt_RSA(enc_msg, priv_key):
    try:
        plaintext = priv_key.decrypt(
            enc_msg,
            padding_RSA.OAEP(                                   ######OAEP o PKCS1
            mgf=padding_RSA.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )
        return plaintext
    except ValueError:
        print "decrypt_data"
        return None

def print_line():
    print "\n______________________________________________________________________\n"

def print_user_log(user, data):
    print '['+user[0], ' on ', str(user[1])+'] ', data


def unpack_message(pack, dim):
    field = []
    offset = 0
    try:
        while(offset < len(pack)):
            length = struct.unpack_from('>I', pack, offset)[0]
            field.append(pack[offset + dim: offset + dim + length])
            offset = offset + dim + length
        return field
    except:
        return None

def pack_message(*args):
    
    packet  = ''
    for arg in args:
        l= len(arg)
        pack = struct.pack('>I', l) 
        #print pack
        packet = packet+pack+str(arg)
    
    return packet

def concatenate(*args):
    conc = ''
    for arg in args:
        conc = conc+str(arg)
    return conc



def usage():
    print "Command:\tPWD_manager_server.1.py -i -p"
    print "Options:"
    print "\t-i, --address=\t\t\tIPv4 address of the server"
    print "\t-p, --port=\t\t\tport for listening requests"