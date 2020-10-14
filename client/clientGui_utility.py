#! /usr/bin/env python
#  -*- coding: utf-8 -*-
#  Author: Fabio Condomitti
#    Jun 11, 2018 12:54:15 PM

import subprocess
import binascii
import struct
import asymmetric_encryption
import os
import datetime

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import AlreadyFinalized
from cryptography.hazmat.primitives.asymmetric import padding as paddingAsymm

from cryptography import x509
from cryptography.x509.oid import NameOID

try:
    from Tkinter import *
except ImportError:
    from tkinter import *

try:
    import ttk
    py3 = False
except ImportError:
    import tkinter.ttk as ttk
    py3 = True
    
def copy2clip(txt):
    cmd='echo '+ txt.strip() + '|clip'
    return subprocess.check_call(cmd, shell=True)
    
def deleteClipboard(console):
    copy2clip("Try again.")
    console.configure(state='normal')
    console.delete(0, END)
    console.configure(state='disabled')

def cancel(e, username, password, results, password2 = None):
    print('clientGui_utility.cancel')
    username.delete(0, END)
    password.delete(0, END)
    if password2 is not None:
        password2.delete(0, END)
    results.delete(0, END) 
    sys.stdout.flush()

def toggle_password(self, passField, passField2=None):
    if self.var.get():
        passField['show'] = "*"
        if passField2 is not None:
            passField2['show'] = "*"          
    else:
        passField['show'] = ""
        if passField2 is not None:
            passField2['show'] = ""

def reset_toggle_password(self, passField, passField2=None):
    
    self.var.set(True)
    #if self.var.get():
    passField['show'] = "*"
    if passField2 is not None:
        passField2['show'] = "*"          
    
def createRequest(opcode, nounceC, website, pwd = None, newPwd = None):
    string = None

    if opcode != "GET":
        if opcode == "ADD" or opcode == "DEL":
            string = pwd
        elif opcode == "UPD":
            string = pwd + '|' + newPwd
        
        return opcode + '|' + website + '|' + string + '|' + nounceC
    else:
        return opcode + '|' + website + '|' + nounceC

def unhexHash(packet, received):
    received_unhex = binascii.unhexlify(received)
    expected = get_hash(packet, "")

    return expected, received_unhex

def get_hash(bytes_to_hash, salt):
    
    try:
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(bytes_to_hash+salt)
        hash = digest.finalize()
        return hash
    except AlreadyFinalized:
        return None

def checkFields(serverID, serverName, clientID, username, hashExpected, hashReceived, my_nounceC_hashed, received_hash_nounceC):
    result = True

    if secureCompare(serverID, serverName) is False:
        #print "Server names are not equal"
        result = False
    else:
        pass
        #print "Server names are equal"

    if secureCompare(clientID, username) is False:
        #print "Client names are not equal"
        result = False
    else:
        pass
        #print "Client names are equal"
  
    if secureCompare(hashExpected, hashReceived) is False:
        #print "Hashes are not equal"
        result = False
    else:
        pass
        #print "Hashes are equal"

    if secureCompare(my_nounceC_hashed, received_hash_nounceC) is False:
        #print "Hashed nounces are not equal"
        result = False
    else:
        pass
        #print "Hashed nounces are equal"

    return result

def checkRequest(expectedNounce, receivedNounce, expectedHash, receivedHash):
    result = True

    if secureCompare(expectedNounce, receivedNounce) is False:
        print "Nounces are not equal"
        result = False
    else:
        print "Nounces are equal"

    if secureCompare(expectedHash, receivedHash) is False:
        print "Hashes are not equal"
        result = False
    else:
        print "Hashes are equal"
    
    return result

def secureCompare(a, b):
    
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result is 0

def unpackMessage(pack, dim):

    field = []
    offset = 0
    while(offset < len(pack)):
        length = struct.unpack_from('>I', pack, offset)[0]
        field.append(pack[offset + dim : offset + dim + length])
        offset = offset + dim + length

    return field

def packMessage(*args):
    packet  = ''
    for arg in args:
        l= len(arg)
        pack = struct.pack('>I', l) 
        packet = packet + pack + arg

    return packet

def concatenate(*args):
    res = ""
    for arg in args:
        res = res + arg
    return res

import re
def NameValidation(text, ConsoleTextHome):
               
    if re.match(r'[A-Za-z0-9@#$%^&+=]{8,}', text):  # at least 8 characters, A-Z, a-z, 0-9, @#$%^&+= --> no *
        ConsoleTextHome.insert(0, "Ok")
    else:
        ConsoleTextHome.insert(0, "Errore")

def usage():
    print "Command:\tclientGui.py -i -p"
    print "Options:"
    print "\t-i, --address=\t\t\tIPv4 address of the server"
    print "\t-p, --port=\t\t\tport of the request"

def tryint(x):
    try:
        return (True, int(x))
    except ValueError:
        return (False, x)

def usernameOkay(console, text):
    chars = [',', ';', '--', '#', '<-', '\'', '"', '-']

    for c in chars:
        if c in text:
            setConsole(console, "Entered values in the username field are not allowed.")
            return False

    if '-' in text or "'" in text or '"' in text:
        setConsole(console, "Entered values in the username field are not allowed.")
        return False

    if re.match(r'[A-Za-z0-9]{3,}', text):  # at least 3 characters, A-Z, a-z, 0-9
        setConsole(console, "Please insert your account information or sign in.")
        return True
    else:
        setConsole(console, "Error in the username field. At least 3 characters are required.")
    
    return False
        
def passwordOkay(console, text):
    chars = [',', ';', '--', '#', '<-', '\'', '"', '-']

    for c in chars:
        if c in text:
            setConsole(console, "Entered values in the password field are not allowed.")
            return False

    if '-' in text or "'" in text or '"' in text:
        setConsole(console, "Entered values in the password field are not allowed.")
        return False
    
    if re.match(r'[A-Za-z0-9@#$%^&+=]{6,}', text):  # at least 4 characters, A-Z, a-z, 0-9, @#$%^&+= --> no *
        setConsole(console, "Please insert your account information or sign in.")
        return True
    else:
        setConsole(console, "Error in the password field. At least 6 characters are required.")
    
    return False
        
def websiteOkay(console, text, code):

    if '-' in text or "'" in text or '"' in text:
        setConsole(console, "Entered values in the website field are not allowed.")
        return False
    
    if re.match(r'[A-Za-z0-9@#$%^&+=]{2,}', text):  # at least 4 characters, A-Z, a-z, 0-9, @#$%^&+= --> no *
        updateConsole(console, code)
        return True
    else:
        setConsole(console, "Error in the website field. At least 2 characters are required.")
    
    return False

def updateConsole(console, code):
    if code == "GET":
        setConsole(console, "Please insert your account information or sign in.")
    if code == "DEL":
        setConsole(console, "Insert the name of the website and its password to delete it.")
    if code == "UPD":
        setConsole(console, "Insert the name of the website, the old password and the new password to update it.")
    if code == "ADD":
        setConsole(console, "Insert the name of the website and its password to add it.")
            
def setConsole(console, text):
    console.configure(state='normal')
    console.delete(0, END)
    console.insert(0, text)
    console.configure(state='disabled')

def testUsername(console, username):
    userOk = usernameOkay(console, username)
    
    if userOk is False:
        print "__________________________________________________________"
        print("[ERROR] Username entered is not valid.")
        return False
    return True

def testPassword(console, password):
    passwordOk = passwordOkay(console, password)
    if passwordOk is False:
        print "__________________________________________________________"
        print("[ERROR] Passwords entered are not valid.")
        return False
    return True

def testLogin(console, username, password):
    if testLength(console, username, "LOG") is False:
        return False
    if testLength(console, password, "LOG") is False:
        return False

    if testUsername(console, username) is False:
        return False
    
    if testPassword(console, password) is False:
        return False
    return True

def testRegistration(console, username, password, password2):
    if testLength(console, username, "REG") is False:
        return False
    if testLength(console, password, "REG") is False:
        return False
    if testLength(console, password2, "REG") is False:
        return False

    if testUsername(console, username) is False:
        return False
    
    if testPassword(console, password) is False:
        return False
    
    if testPassword(console, password2) is False:
        return False
    return True

def testPasswordEqual(console, password, password2):    
    if password != password2:
        setConsole(console, "Two passwords entered are not equal.")
        return False
    return True

def testWebsite(console, website, code):
    if testLength(console, website, code) is False:
        return False

    websiteOk = websiteOkay(console, website, code)
    if websiteOk is False:
        print "__________________________________________________________"
        print("[ERROR] Website entered is not valid")
        setConsole(console, "Website entered is not valid.")
        return False
    return True

def testDeleteAdd(console, website, password, code):

    if testLength(console, website, code) is False:
        return False
    if testLength(console, password, code) is False:
        return False

    if testWebsite(console, website, code) is False:
        return False
    
    if testPassword(console, password) is False:
        return False
    return True

def testUpdate(console, website, password, password2, code):

    if testLength(console, website, code) is False:
        return False
    if testLength(console, password, code) is False:
        return False
    if testLength(console, password2, code) is False:
        return False

    if testWebsite(console, website, code) is False:
        return False
    
    if testPassword(console, password) is False:
        return False
    
    if testPassword(console, password2) is False:
        return False
    
    return True

def testPasswordDifferent(console, password, password2):

    if password == password2:
        setConsole(console, "Two passwords entered are equal. Please modify one field.")
        return False
    return True

def testLength(console, text, code):
    
    if len(text) > 32:
        setConsole(console, "One or more inputs you have entered are too long. Please modify them.")
        return False
    else:
        updateConsole(console, code)

    return True

def certificateControl(result, serverName, serverNameCert, ca_pubkey, serialNumber):
   
    if secureCompare(serverName, serverNameCert) is False:
        print "[Error] Server name are different"
        return "1050"
    
    if result is False:
        print "[Error] Error in the certificate M2"
        return "1050"
             
    print "\t\tM2: Certificate is valid"

    if checkCRL(ca_pubkey, serialNumber) is False:
        print "[Error] Certificate was revoked"
        return "1050"

    print "\t\tM2: Certificate was not revoked"

    return True
    
def checkCRL(publicKey, serialNumber):

    path = os.path.join('Certification_Authority', 'crl.pem')
    with open(path, 'rb') as f:
        pem_crl_data_text = f.read()
        pem_crl_data = x509.load_pem_x509_crl(
            pem_crl_data_text,
            backend=default_backend()
        )
    valid = pem_crl_data.is_signature_valid(publicKey)
    if valid is False:
        return False
    
    now = datetime.datetime.now()

    if now < pem_crl_data.last_update or now > pem_crl_data.next_update:
        print '[Error] Invalid CRL certificate.'
        sys.exit(1)

    isinstance(pem_crl_data.signature_hash_algorithm, hashes.SHA256)

    revoked_certificates = []
    for i in range(0, len(pem_crl_data)):
        revoked_certificates.append(pem_crl_data[i].serial_number)

    if serialNumber in revoked_certificates:
        return False
    
    return True

def checkCertificate(sgn_cert_text):
    path = os.path.join('Certification_Authority', 'ca_cert.pem')
    with open(path, 'rb') as f:
        ca_cert_text = f.read()
        ca_cert = x509.load_pem_x509_certificate(
            ca_cert_text,
            backend=default_backend()
        )

    now = datetime.datetime.now()
    if now < ca_cert.not_valid_before or now > ca_cert.not_valid_after:
        print '[Error] Invalid CA certificate.'
        sys.exit(1)

    ca_name = ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    print 'Certification Authority:', ca_name
    ca_pubkey = ca_cert.public_key()

    sgn_cert = x509.load_pem_x509_certificate(
        sgn_cert_text,
        backend=default_backend()
    )
    
    server_name = sgn_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

    sgn_cert_issuer_name = sgn_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    if sgn_cert_issuer_name != ca_name:
        print '[Error] Unknown CA: ', sgn_cert_issuer_name
        sys.exit(1)

    if now < sgn_cert.not_valid_before or now > sgn_cert.not_valid_after:
        print '[Error] Invalid file signer certificate.'
        sys.exit(1)

    sgn_cert_public = sgn_cert.public_key()

    serialNumber = sgn_cert.serial_number

    ctx = ca_pubkey.verifier(
        sgn_cert.signature,
        paddingAsymm.PKCS1v15(),
        hashes.SHA256()
    )

    ctx.update(sgn_cert.tbs_certificate_bytes)
    try:
        ctx.verify()
        return True, server_name, sgn_cert_public, serialNumber, ca_pubkey
    except:
        return False

def createPlaintext(code, serverName, username, password, kcs, nounceS, nounceC):

    plaintext = concatenate(code, serverName, username, password, kcs, nounceS, nounceC)
    hash = get_hash(bytes(plaintext), "")
    plaintext = packMessage(code, serverName, username, password, kcs, nounceS, nounceC, hash)

    print "\n PLAINTEXT: ", '[' + code + '|' + serverName + '|' + username + '|' + "password" + '|' + "Kcs" + '|' + "nounceS" + '|' + 'nounceC]'

    return plaintext
