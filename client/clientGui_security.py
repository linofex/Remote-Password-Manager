#! /usr/bin/env python
#  -*- coding: utf-8 -*-
#  Author: Fabio Condomitti
#    Jun 11, 2018 12:54:15 PM

import sys
import socket
import getopt
import struct
import os
import datetime
import binascii
import errno
# import cryptography

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as paddingSymm
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import AlreadyFinalized
from cryptography.hazmat.primitives.asymmetric import padding as paddingAsymm

from cryptography import x509
from cryptography.x509.oid import NameOID

import clientGui_utility
import asymmetric_encryption
import symmetric_encryption
import key_derivation_function as kdfunction

global counter
counter = 0
global connectFlag
connectFlag = True
DIM = 4

class Socket:
    
    def __init__(self, sock=None):
        
        if sock is None:
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            except socket.error:
                print "[Error] Error on socket()"  
        else:
            self.sock = sock

    def connect(self, host, port):
        try:
            self.sock.connect((host, port))
        except socket.error:
            print "[Error] Error on connect()"
            return False

    def secureSend(self, msg):
        lenght = len(msg)
        message = struct.pack('>I', lenght) + msg
        
        sent = self.sock.sendall(message)

        if sent == 0:
            raise RuntimeError("[Error] Socket connection broken")
        
    def secureReceive(self, length):
            chunks = []
            bytes_recd = 0
            while bytes_recd < length:
                chunk = self.sock.recv(min(length - bytes_recd, length))
                if chunk == b'':
                    raise RuntimeError("[Error] Socket connection broken")
                chunks.append(chunk)
                bytes_recd = bytes_recd + len(chunk)
            return b''.join(chunks)

    def sendM1(self, username):
        m1 = clientGui_utility.packMessage(username)
        self.secureSend(m1)
        print "\n[Protocol] M1\n"
        print "\t\t\tM1: [" + username + "]"
        print "C -----------------------------------------------------------> S\n"

    def receiveM2(self):
        lenM2 = self.sock.recv(4)
        length = struct.unpack('>I', lenM2)[0]
        if lenM2 == "":
            print "[Error] Error in the protocol M2 length"
            return "1050"
            #return False
        
        # M2
        response = self.secureReceive(int(length))
        fieldsM1 = clientGui_utility.unpackMessage(response, 4)

        print "\n[Protocol] M2\n"
        print "\tM1: [ServerName, ServerCertificate, NounceS]"
        print "C <----------------------------------------------------------- S\n"

        return fieldsM1

    def sendM3(self, serverPublicKey, plaintext):
        ciphertext = asymmetric_encryption.createCiphertextRSA(serverPublicKey, plaintext)
        self.secureSend(ciphertext)

        print "\n[Protocol] M3\n"
        print "\t\t\tM4: [ciphertext]"
        print "C -----------------------------------------------------------> S\n"

    def receiveM4(self):
            
        firstMessage = self.sock.recv(4)

        if firstMessage == "":
            print "[Error] Error in the protocol --> M4"
            return "1050"
            #return False
        
        # M4
        length = struct.unpack('>I', firstMessage)[0]
        response = self.secureReceive(int(length))
    
        fieldsM4 = clientGui_utility.unpackMessage(response, 4)

        print "\n[Protocol] M4\n"
        print "\t\t\tM4: [cryptogram, serverIV]"
        print "C <----------------------------------------------------------- S\n"

        return fieldsM4

    def registration(self, username, password, code):
        global counter
        if counter >= 4:
            return "1090" # Too many errors in login/sign in phases. Please close the app and try again.

        try:
            global connectFlag
            if connectFlag is True:
                res = self.connect(addr, int(port))
                if res is False:
                    return "1050"
                else:
                    connectFlag = False
            # M1
            try:

                self.sendM1(username)
                
            except socket.error as err:
                print "[Error] Error on M1 ---"
                err_type = err.args[0]
                if err_type in [errno.EBADF, errno.ENOTCONN]:  #   9: Bad file descriptor.
                    print err_type
                
                return "1050"
                
                #return False
            
            # M2
            fieldsM1 = self.receiveM2()

            if len(fieldsM1) != 3:
                print "[Error] Error in the field length"
                return "1050"
            
            serverName = fieldsM1[0]
            serverCertificate = fieldsM1[1]
            nounceS = fieldsM1[2]
            
            result, serverNameCert, serverPublicKey, serialNumber, ca_pubkey = clientGui_utility.checkCertificate(serverCertificate)
        
            if clientGui_utility.certificateControl(result, serverName, serverNameCert, ca_pubkey, serialNumber) == "1050":
                return "1050"

            self.kcs = os.urandom(32)
            nounceC = os.urandom(16)
 
            plaintext = clientGui_utility.createPlaintext(code, serverName, username, password, self.kcs, nounceS, nounceC)

            # M3
            self.sendM3(serverPublicKey, plaintext)

            # M4
            fieldsM4 = self.receiveM4()
            
            if fieldsM4 is False or fieldsM4[0] == "FAIL":
                counter = counter + 1
                return "1050"
            
            if fieldsM4[0] == "COPY":
                counter = counter + 1
                return "1070"

            cryptogram = fieldsM4[0]
            ivServer = fieldsM4[1]

            plaintext = symmetric_encryption.createPlaintextAES(self.kcs, ivServer, cryptogram)
            clearFieldM4 = clientGui_utility.unpackMessage(plaintext, DIM)

            status = clearFieldM4[0]
            serverNameM4 = clearFieldM4[1]
            usernameM4 = clearFieldM4[2]
            nounceCHashed = clearFieldM4[3]
            hashReceived = clearFieldM4[4]

            packet = clientGui_utility.concatenate(status, serverNameM4, usernameM4, nounceCHashed)
            hashExpected = clientGui_utility.get_hash(bytes(packet), "")

            my_nounceC_hashed = clientGui_utility.get_hash(bytes(nounceC), "")

            if clientGui_utility.checkFields(serverNameM4, serverName, usernameM4, username, hashExpected, hashReceived, my_nounceC_hashed, nounceCHashed) is False:
                return "1050"
        
            print " RESPONSE: ", '[' + code + '|' + status + ']'

            if int(status) == 100:
                counter = 0
            else:
                return "1050"

            if kdfunction.kdf(password) is None:
                return "1050"
            else:
                self.kdfPassword = kdfunction.kdf(password) 

            return True
    
        except socket.error as err:
            
            print "[Error] Error on registration or login"
            err_type = err.args[0]
            if err_type in [errno.EBADF, errno.ENOTCONN]:  #   9: Bad file descriptor.
                return "1050"
            return "1050"

    def sendM1Request(self, website):

        nounceIV = os.urandom(16)
        specialOpcode = "IV"
        plaintext = clientGui_utility.concatenate(specialOpcode, website, nounceIV)  

        hash = clientGui_utility.get_hash(bytes(plaintext), "")
        plaintext = clientGui_utility.packMessage(specialOpcode, website, nounceIV, hash)

        iv = os.urandom(16)
        ciphertext = symmetric_encryption.encrypt_AES(plaintext, self.kcs, iv)

        message = clientGui_utility.packMessage(ciphertext, iv)
        self.secureSend(message)

        print "\n[Protocol] M1 IV\n"
        print "\t\t\tM1 IV: [IV, website, nounceIV]"
        print "C -----------------------------------------------------------> S\n"

        return nounceIV

    def receiveM2Request(self):

        # M2 length
        firstMessage = self.sock.recv(4)

        if firstMessage == "":
            print "[Error] Error in the protocol --> M2"
            return False
        
        # M2
        length = struct.unpack('>I', firstMessage)[0]
        response = self.secureReceive(int(length))
        
        packet = clientGui_utility.unpackMessage(response, 4)
        cryptogram = packet[0]
        ivServer = packet[1]
        plaintextReceived = symmetric_encryption.decrypt_AES(cryptogram, self.kcs, ivServer)


        fieldsM2 = clientGui_utility.unpackMessage(plaintextReceived, 4)
        
        print "\n[Protocol] M2 IV\n"
        print "\tM1 IV: [cryptogram, serverIV]"
        print "C <----------------------------------------------------------- S\n"

        return fieldsM2
        
    def sendM3Request(self, opcode, password, newPassword, website, nounceC, ivReceived):

        if opcode != "GET" and password is not None:
                    
            if opcode == "ADD":
                ivAddADD = os.urandom(16)
                encryptedPassword = symmetric_encryption.encrypt_AES(password, self.kdfPassword, ivAddADD)
            
            if opcode == "DEL":
                #print "del m3"
                encryptedPassword = symmetric_encryption.encrypt_AES(password, self.kdfPassword, ivReceived)

            if opcode == "UPD" and newPassword is not None:
                ivAddUPD = os.urandom(16)
                encryptedPassword = symmetric_encryption.encrypt_AES(password, self.kdfPassword, ivReceived)
                encryptedNewPassword = symmetric_encryption.encrypt_AES(newPassword, self.kdfPassword, ivAddUPD)
            
        plaintext = None
        
        if opcode == "ADD":
            #print "del m3 2"
            plaintext = clientGui_utility.concatenate(opcode, website, encryptedPassword, ivAddADD, nounceC)
        elif opcode == "DEL":
            plaintext = clientGui_utility.concatenate(opcode, website, encryptedPassword, nounceC)
        elif opcode == "GET":
            plaintext = clientGui_utility.concatenate(opcode, website, nounceC)
        elif opcode == "UPD":
            plaintext = clientGui_utility.concatenate(opcode, website, encryptedPassword, encryptedNewPassword, ivAddUPD, nounceC)

        hash = clientGui_utility.get_hash(bytes(plaintext), "")

        if opcode == "ADD":
            plaintext = clientGui_utility.packMessage(opcode, website, encryptedPassword, ivAddADD, nounceC, hash)
        elif opcode == "DEL":
            plaintext = clientGui_utility.packMessage(opcode, website, encryptedPassword, nounceC, hash)
        elif opcode == "GET":
            plaintext = clientGui_utility.packMessage(opcode, website, nounceC, hash)
        elif opcode == "UPD":
            plaintext = clientGui_utility.packMessage(opcode, website, encryptedPassword, encryptedNewPassword, ivAddUPD, nounceC, hash)

        #return plaintext
        iv = os.urandom(16)
        
        ciphertext = symmetric_encryption.encrypt_AES(plaintext, self.kcs, iv)
        message = clientGui_utility.packMessage(ciphertext, iv)

        self.secureSend(message)

        print "\n[Protocol] M3\n"
        print "\t\t\tM3: [" + opcode + ", " + website +", ********, IV, nounceC"
        print "C -----------------------------------------------------------> S\n"


    def receiveM4Request(self):
        firstMessage = self.sock.recv(4)

        if firstMessage == "" or firstMessage == "FAIL":
            print "[Error] Error in the protocol M4 length"
            return False, None
        
        # M4
        length = struct.unpack('>I', firstMessage)[0]
        response = self.secureReceive(int(length))

        cryptogram, ivServer = clientGui_utility.unpackMessage(response, 4)

        plaintextReceived = symmetric_encryption.decrypt_AES(cryptogram, self.kcs, ivServer)

        fieldsM4 = clientGui_utility.unpackMessage(plaintextReceived, 4)
            
        print "\n[Protocol] M4\n"
        print "\t\t\tM4: [cryptogram, serverIV]"
        print "C <----------------------------------------------------------- S\n"

        return fieldsM4, plaintextReceived

    def requestResource(self, opcode, website, password = None, newPassword = None):
        
        try:
            # M1
            try:
                
                nounceC = os.urandom(16)
                ivReceived = None
                iv = None
                if (opcode == "UPD" or opcode == "DEL") and password is not None:
                    nounceIV = self.sendM1Request(website)
                    
                    fieldsM2 = self.receiveM2Request()

                    if fieldsM2 is False:
                        return False
                    
                    status = fieldsM2[0]
                    if int(status) != 100:
                        print "[Error] Error in the response status"
                        return False
                    
                    data = ''.join(fieldsM2[:-1])
                    hashTest = clientGui_utility.get_hash(bytes(data), "")
                    if (clientGui_utility.secureCompare(hashTest, fieldsM2[-1])) is False:
                        print "[Error] Hashes are not equal M2"
                        return False
                    
                    ivReceived = fieldsM2[1]
                    nounceReceived = fieldsM2[2]

                    if (clientGui_utility.secureCompare(nounceIV, nounceReceived)) is False:
                        print "[Error] Nounces are not equal M2"
                        return False

                #print "m2"
                # M3

                self.sendM3Request(opcode, password, newPassword, website, nounceC, ivReceived)
                
            except socket.error as err:
                print "[Error] Error on M1"
                err_type = err.args[0]
                if err_type in [errno.EBADF, errno.ENOTCONN]:  #   9: Bad file descriptor.
                    print err_type
                
                return False
            
            # M4 length
            fieldsM4, plaintextReceived = self.receiveM4Request()
            if fieldsM4 is False:
                return False
       
            if plaintextReceived is None:
                print "[Error] No plaintext obtained"
                return False

            status = fieldsM4[0]
            if int(status) != 100:
                if int(status) == 1103:
                    return "1103"
                return False
            
            data = ''.join(fieldsM4[:-1])
            hashTest = clientGui_utility.get_hash(bytes(data), "")
            if clientGui_utility.secureCompare(hashTest, fieldsM4[-1]) is False:
                print "[Error] Hashes are not equal M4"
                return False
            
            nounceReceived = None
            if (opcode == "ADD" or opcode == "DEL" or opcode == "UPD") and len(fieldsM4) == 3: 
                nounceReceived = fieldsM4[1]
            elif opcode == "GET":
                if len(fieldsM4) == 5:
                    passwordReceived = fieldsM4[1]
                    ivReceived = fieldsM4[2]
                    nounceReceived = fieldsM4[3]  
                else:
                    ivReceived = fieldsM4[1]
                    nounceReceived = fieldsM4[2]
            
            if clientGui_utility.secureCompare(nounceC, nounceReceived) is False:
                print "[Error] Nounces are not equal M4"
                return False
            
            print " RESPONSE: ", '[' + opcode + '|' + status + ']'

            if status == "YES" or int(status) == 100:
                counter = 0
        
            decryptedPassword = None
            if opcode == "GET" and passwordReceived is not None:
                decryptedPassword = symmetric_encryption.decrypt_AES(passwordReceived, self.kdfPassword, ivReceived)

            result = None
            if opcode == "GET" and int(status) == 100 and decryptedPassword is not None:
                return str(decryptedPassword)
            else:
                if int(status) == 100:
                    return True
                elif int(status) == 1103:
                    return "1103"
                else:
                    return False

            return result
           
        except socket.error as err:
            
            print "[Error] Error on registration or login"
            err_type = err.args[0]
            if err_type in [errno.EBADF, errno.ENOTCONN]:  #   9: Bad file descriptor.
                return False  
    
            return (False, None)
    
    def secureClose(self):
        self.sock.close()
        del self.kcs
        del self.kdfPassword

def init():
    global addr
    global port

    addr = None
    port = None
    
    #sock = None

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hi:i:p:", ["help", "address=", "port="])
    except getopt.GetoptError as err:
        # print help information and exit:
        print str(err)  # will print something like "option -a not recognized"
        clientGui_utility.usage()
        sys.exit(2)

    for o, a in opts:
        if o in ("-i", "--address"):
            addr = a
        elif o in ("-p", "--port"):
            port = a
        elif o in ("-h", "--help"):
            clientGui_utility.usage()
            sys.exit()
        else:
            clientGui_utility.usage()
            sys.exit(2)

    if addr is None:
        print "[Error] Address must be specified"
        clientGui_utility.usage()
        sys.exit(2)

    if port is None:
        print "[Error] Port must be specified"
        clientGui_utility.usage()
        sys.exit(2)

    print addr, port
    socket = None
    
    socket = Socket()

    return socket

if __name__ == '__main__':
    init()