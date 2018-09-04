# -*- coding: utf-8 -*-
# PROJECT - Remote password manager
# Author: Fabio Condomitti - 
#         Alessandro Noferi - alessandro.noferi@gmail.com
# 
# Server side
# Server listens for new user requests. Each time a user connects to the server, 
# the server starts the 'key_establishment_protocol'. This method allows a user to 
# login or sign in the database. At the end,  if all is fine, a session symmetric
# key is established through them.
# The protocol is composed of 4 messages:
# M1 C -> S: Client_ID
# M2 S -> C: Server_ID, Client_ID, Cert_S, Nonce_s
# M3 C -> S: {OPCODE,Client_ID, Server_ID, Client_password, Kcs, Nonce_s, Nonce_c}pubk_s
# M4 S -> C: {H(Nonce_c)}Kcs
#
# Where OPCODE: 
# LOG: Login
# REG: Sign in
#
# This session key will be used to communicate later when the user will ask for an operation, like:
# 'GET': get the password for a site
# 'ADD': add a password for a site
# 'UPD': change the password for a site
# 'DEL': delete a password of a site

import SocketServer
import os
import threading
import utility
import DB_2_1T as DB
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

from cryptography import x509
from cryptography.x509.oid import NameOID
import socket
from binascii import hexlify, unhexlify
import getopt
import sys
class PasswordManager(SocketServer.BaseRequestHandler):
    ''' def __init__(self, request, client_address, server):
        '''
    def setup(self):
        #print "SETUP"
        pass

    def message_M1(self):
        utility.print_user_log(self.client_address,"Waiting for M1...")
        response_m1 = utility.recv_data(self.request, 0)
        #print response_m1
        if response_m1 is None:
            utility.print_user_log(self.client_address,"client disconnected")
            return 201
        #print "...OK"
        unpack_m1 = utility.unpack_message(response_m1, 4)
        if len(unpack_m1) != 1:
            return None
        #utility.print_user_log(self.client_address, 'UNPACK M1 '+unpack_m1)
        self.client_ID = unpack_m1[0]
        print 'ClientID: ',self.client_ID,'is connecting from: ', self.client_address
        return True
    
    def message_M2(self):
        utility.print_user_log(self.client_address, "Sending M2..")
        # generate Nonce
        self.nonce_s = os.urandom(16)
        # print "nonce: ", nonce_s
        # read certificate
        cert = utility.read_cert('server_cert_1') # server_cert_1
        
        if cert is None:
            utility.print_user_log(self.client_address,'[ERROR] Some errors occured reading  the certificate')
            return None
        utility.print_user_log(self.client_address, 'Server certificate loaded')

        data_to_send = utility.pack_message(self.server_ID, cert, self.nonce_s)
        return data_to_send
    
    def message_M3(self):
        priv_key = utility.load_priv_key('server_prvkey_1')
        if priv_key is None:
            utility.print_user_log(self.client_address,'[ERROR]Some errors occured reading  the key')
            return None
        utility.print_user_log(self.client_address,'Private key loaded')
        # waiting for M3
        utility.print_user_log(self.client_address,"Waiting for M3...")
        data_recv = utility.recv_data(self.request,0)
        if data_recv is None:
            utility.print_user_log(self.client_address, "[ERROR] Client disconnected during M3")
            return None
        utility.print_user_log(self.client_address, "Received M3..")

        encrypted_data = bytes(data_recv)
        decrypted_data = utility.decrypt_RSA(encrypted_data, priv_key)
        if decrypted_data is None:
            utility.print_user_log(self.client_address, '[ERROR] some errors occured decrypting the data')
            return None
        try:
            ''' print '_____________________________________'
            print decrypted_data
            print '_____________________________________' '''
            fields = utility.unpack_message(decrypted_data, 4)
            #print fields
            if len(fields) != 8:
                return None
        # Manca TYPE | ...
            opcode, server_prot_ID,client_prot_ID, client_pass,session_key, nonce_prot_s, self.nonce_prot_c, hashed_data_c = fields
        except IndexError:
            utility.print_user_log(self.client_address, '[ERROR] incorrect message format')
            return None
        ''' for i in fields:
            print hexlify( i),  "\n" '''
        data_to_hash = ''.join(fields[0:7]) 
        hashed_data = utility.get_hash(data_to_hash)
        ret = utility.secure_cmp(hashed_data, hashed_data_c)
        #print hexlify(hashed_data)
        #print hexlify(hashed_data_c)
        if (ret is False):
            utility.print_user_log(self.client_address, '[ERROR] Packet Hashes do not match')
            del session_key
            return None
        ret = utility.secure_cmp(self.nonce_s, nonce_prot_s)
        if(ret is False):
            utility.print_user_log(self.client_address, '[ERROR] Server Nonce is not fresh!')
            del session_key
            return None
        #print '1'
        ret = utility.secure_cmp(self.client_ID, client_prot_ID)
        if(ret is False):
            utility.print_user_log(self.client_address, '[ERROR] Client IDs do not match')
            del session_key
            return None
        #print '2'
        ret = utility.secure_cmp(self.server_ID, server_prot_ID)
        if(ret is False):
            utility.print_user_log(self.client_address, '[ERROR] Serve IDs do not match')
            del session_key
            return None
        #return (opcode, session_key, nonce_prot_c, client_pass)
        

        # =================================================================
        if opcode == 'LOG':
            utility.print_user_log(self.client_address, "LOGIN REQUEST")
        # KDF(salted) e ricerca hash in database
            db = DB.Database()
            ret = db.connect()
            if ret[0] == False:
                utility.print_user_log(self.client_address, '[ERROR] Error during connecting to DB '+ str(ret[1]))
                del session_key
                return None
            user_config = db.find_user_config(self.client_ID, 'users')
            db.disconnect()
            if user_config == None:
                utility.print_user_log(self.client_address, '[ERROR] No user config found with ID: %s' % self.client_ID )
                del session_key
                return None
            ID, hash_pwd, salt_hash = user_config
            hashed_pwd = bytes(hash_pwd)
            #print hash_pwd, hashed_pwd
            #print hexlify(hashed_pwd)
            #kdf = utility.get_kdf(client_pass, salt_kdf)
            #hashed_kdf =  utility.get_hash(kdf, salt_hash)
            #if hashed_kdf == None:
            #    utility.print_user_log(self.client_address, '[ERROR] Error during KDF creation')
            #    del session_key
            #   return None
            # Check importante, hashed_kdf é l'hash della kdf della password che mi invia l'utente
            #                   hashed_pwd é l'hash della kdf della password che ho nel DB
            hash_pwd_c = utility.get_hash(client_pass, salt_hash)
            ret = utility.secure_cmp(hashed_pwd, hash_pwd_c)
            if ret == False:
                utility.print_user_log(self.client_address, '[ERROR] Password hashes do not match')
                del session_key
                return None
        # =====================================================================
        # REG ===============================================================
        elif opcode == 'REG':
            utility.print_user_log(self.client_address,'SIGNIN REQUEST')
            db = DB.Database()
            ret = db.connect()
            if ret[0] == False:
                utility.print_user_log(self.client_address,'[ERROR CONNECT] '+ str(ret[0]))
                del session_key
                return None
            user_config = db.find_user_config(self.client_ID, 'users')
            db.disconnect()
            if user_config != None:
                utility.print_user_log(self.client_address,'[ERROR CONFIG] User: ' + str(user_config[0])+ ' already present')
                del session_key
                return 203
            # bytes salts
            salt_hash = os.urandom(16)
            #kdf = utility.get_kdf(client_pass, salt_kdf)
            #hashed_kdf =  utility.get_hash(kdf, salt_hash)
            hashed_pwd = utility.get_hash(client_pass, salt_hash)
            #print hashed_kdf
            ''' if hashed_kdf == None:
                utility.print_user_log(self.client_address,'[ERROR] Error during KDF creation')
                del session_key
                return None '''
            ret = db.connect()
            if ret[0] == False:
                utility.print_user_log(self.client_address,'[ERROR] Error during connecting to DB '+ str(ret[1]))
                del session_key
                return None
            ret = db.add_user('users',self.client_ID, hashed_pwd, salt_hash)
            db.disconnect()
            if ret[0] == False:
                utility.print_user_log(self.client_address,'[ERROR] Error during user add ' + ret[1])
                del session_key
                return None

        else:
            del session_key
            return None
        self.session_key = session_key
        #self.client_key = kdf
        self.database = db
        self.nonces = [] 
        return True 
    
    def message_M4(self, nonce_prot_c):
        utility.print_user_log(self.client_address,'Sending M4...')

        hash_nonce_c = utility.get_hash(nonce_prot_c)
        data_to_pack = utility.concatenate('100', self.server_ID, self.client_ID, hash_nonce_c)
        hash_data = utility.get_hash(data_to_pack)
        data = utility.pack_message('100', self.server_ID, self.client_ID, hash_nonce_c, hash_data)
        IV = os.urandom(16)
        enc_data = utility.encrypt_AES(data, self.session_key, IV)
        if enc_data is None:
            utility.print_user_log(self.client_address, '[ERROR] Error during encryption')
            return None
        data_to_send = utility.pack_message(enc_data, IV)
        return data_to_send
    
    def key_establishment_protocol(self):
            
        self.server_ID = 'RPM_server'
            
        #print self.server_ID 
        # M1 ------------------------------------------------------------------------------
        response_m1 = self.message_M1()
        if response_m1 is None:
            return None
        if response_m1 == 201:
            return  response_m1
        # M2 ------------------------------------------------------------------------------
        data_to_send = self.message_M2()
        ret = utility.send_data(self.request,data_to_send)
        if ret is False:
            utility.print_user_log(self.client_address,"[ERROR] Error during sending data ")
            return None

        utility.print_user_log(self.client_address, "Message M2 sent")
        #-------------------------------------------------------------------------------------
        # M3 --------------------------------------------------------------------------------
        ret = self.message_M3()
        if ret is None:
            utility.print_user_log(self.client_address, "[ERROR] Error during M3")
            return ret    
        if ret == 203:
            return ret    
     # M4-----------------------------------------------------------------------------------------
        data_to_send = self.message_M4(self.nonce_prot_c)
        if data_to_send is None:
            utility.print_user_log(self.client_address, '[ERROR]Errors occured during M4')
            return None
        ret = utility.send_data(self.request, data_to_send)
        if ret is False:
            utility.print_user_log(self.client_address,"[ERROR] Error during sending data on M4")
            return None
        utility.print_user_log(self.client_address, 'M4 sent')
        return True
     # -----------------------------------------------------------------------------------------------       
    
    def execute_query(self, fields):
        #print len(fields)
        utility.print_user_log(self.client_address, "Executing query...")
        self.database.connect()
        opcode = fields[0]
        #print fields
        #va bene se invia IV anche i DEL, non necessario per
        if opcode == 'ADD' and len(fields) == 4: 
            site , password, IV = fields[1:]
            utility.print_user_log(self.client_address, "PWD LEN: %d" % len(password))
            #print "IV ADD: ", hexlify(IV)
            ret = self.database.add_password(self.client_ID, site, password, IV)
        
        elif opcode == 'DEL' and len(fields) == 3:
            site , password = fields[1:]
            ret = self.database.delete_password(self.client_ID, site,password)
            ''' if (opcode == 'ADD' or opcode == 'DEL') and len(fields) == 4+1: # +1 nonce                                 
            site , password, IV = fields[1:-1]
            if opcode == 'ADD':
                ret = self.database.add_password(self.client_ID, site, password, IV)
            else:
                ret = self.database.delete_password(self.client_ID, site,password)
         '''
        elif opcode == 'IV' and len(fields)== 2:
            site = fields[1]
            ret = self.database.find_IV(self.client_ID, site)
        elif opcode == 'UPD' and len(fields) == 5:

            site , old_pwd, new_pwd, new_IV = fields[1:]
            #print "IV ADD: ", hexlify(new_IV)

            ret= self.database.change_password(self.client_ID, site, old_pwd, new_pwd, new_IV)
        
        elif opcode == 'GET' and len(fields) == 2:
            site = fields[1]
            ret = self.database.find_password(self.client_ID, site)
            
        else:
            #print "ERROR"
            ret = (False, 105)
        
        self.database.disconnect()
        
        if opcode == 'GET' and ret[0] is True:
            #print  "PASSWORD: ",ret[1]
            #print "IV ADD: ", hexlify(ret[2])
            response_fields = ["100" , ret[1], ret[2]]
        elif opcode == 'IV' and ret[0] is True:
            #print hexlify(ret[1])
            response_fields = ['100', ret[1]]
        else:
            response_fields = [str(ret[1])]
        
        return response_fields
    
    def manage_request(self, data):
        # quello che mi arriva  è del tipo [OPCODE|S|C|sito|...|nonce|hash]kcs | IV   
        unpacked_data = utility.unpack_message(data, 4)
        if(unpacked_data is None or len(unpacked_data) != 2):
            utility.print_user_log(self.client_address,"Bad packet format")
            return (False, 109)
        encrypted_data , IV = unpacked_data
        decrypted_data = utility.decrypt_AES(encrypted_data, self.session_key, IV)
        if decrypted_data is None:
            return (False, 102)
        #print decrypted_data
        decrypted_fields = utility.unpack_message(decrypted_data, 4)
        if decrypted_data is None:
            utility.print_user_log(self.client_address,"Bad packet format")
            return (False, 109)
        data_to_hash = ''.join(decrypted_fields[:-1])
        hashed_data_c = decrypted_fields[-1]
        hashed_data = utility.get_hash(data_to_hash)
        ret = utility.secure_cmp(hashed_data_c, hashed_data)
        utility.print_user_log(self.client_address,"Request: %s" % decrypted_fields[0])
        if ret is False:
            print hexlify(hashed_data_c)
            print hexlify(hashed_data)
            utility.print_user_log(self.client_address,"Different hashes")
            return (False, 103)
        #print fields
        nonce = decrypted_fields[-2]
        if nonce in self.nonces:
            utility.print_user_log(self.client_address, "No fresh nonce!!")
            return (False, 104)
        self.nonces.append(nonce)
        #print fields
        
        #execute query
        response_fields = self.execute_query(decrypted_fields[:-2])   # è una lista [:-2] tutto tranne nonce hash
        
        response_fields.append(nonce) # aggiungo nonce alla lista
        response = utility.concatenate(*response_fields)
        hashed_response = utility.get_hash(response)               
        #print "hash,", hashed_response
        #data_to_pack = utility.concatenate((response, hashed_response)) # concateno hash alla risposta
        response_fields.append(hashed_response)
        #print "RF: ",response_fields
        packed_message = utility.pack_message(*response_fields)
        #print packed_message
        IV = os.urandom(16)
        data_to_send = utility.encrypt_AES(packed_message, self.session_key, IV)
        if data_to_send is None:
            return (False, 106)
        data_to_send = utility.pack_message(data_to_send, IV)
        #print "DATA TO SEND \n", data_to_send
        #un = utility.unpack_message(data_to_send, 4)
        #print "ENC",un[0]
        #print "IV", un[1]
        utility.print_user_log(self.client_address, 'Response: '+ response_fields[0])
        return (True, data_to_send)
    
    def handle(self):
        print "New Connection from: " + self.client_address[0], ', on port: ' , self.client_address[1]
        # M1
        i = 0
        while(i < 4):
            utility.print_user_log(self.client_address, "KEY ESTABLISHMENT PROTOCOL")
            self.key_est_result = self.key_establishment_protocol()
            if self.key_est_result is None:
                i = i + 1
                utility.print_user_log(self.client_address, "Errors during protocol number: %d" %i)
                fail = utility.pack_message('FAIL')
                ret = utility.send_data(self.request, fail)
                if ret is False:
                    utility.print_user_log(self.client_address,"[ERROR] Error during sending data ")
                    return None
                #self.request.close()
            elif self.key_est_result == 201:
                #utility.print_user_log(self.client_address, 'DISC')
                utility.print_user_log(self.client_address, "Client Disconnected")
                return None
            elif self.key_est_result == 203:
                i = i + 1
                utility.print_user_log(self.client_address, "Errors during protocol number: %d" %i)
                fail = utility.pack_message('COPY')
                ret = utility.send_data(self.request, fail)

            else:
                utility.print_user_log(self.client_address,"Key establishment protocol has done correctly \n")
                i = 0
                break
        if (i >= 2):
            utility.print_user_log(self.client_address, "To many errors! Disconnecting...")
            return None
             # after return, finish() will be called
        
        while(True):
            utility.print_line()
            utility.print_user_log(self.client_address, "Listening for requests...")
            data = utility.recv_data(self.request, 0) 
            #print data
            if not data or data is None:
                utility.print_user_log(self.client_address, 'Client Disconnected' )      
                break
                # after return, finish() will be called
            data_to_send = self.manage_request(data)
            if data_to_send[0] is False:
                utility.print_user_log(self.client_address,"[ERROR] Unable to manage the request ")
                ret = utility.send_data(self.request, "FAIL") 
                if ret is False:
                    utility.print_user_log(self.client_address,"[ERROR] Error during sending data ")
            else:
                #print data_to_send[1]
                ret = utility.send_data(self.request, data_to_send[1]) 
                if ret is False:
                    utility.print_user_log(self.client_address,"[ERROR] Error during sending data ")
    
    def finish(self):
        #utility.print_user_log(self.client_address,"Finish function"  )
        utility.print_user_log(self.client_address,"Cleaning the connection..."  )
        self.request.close()
        if hasattr(self, 'session_key'):
            utility.print_user_log(self.client_address, "Deleting secret information...")
            del self.session_key
            #del self.client_key
            self.database.disconnect()
            del self.database     
        utility.print_user_log(self.client_address,"Cleaning completed" )
        utility.print_line()

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass
    
    
if __name__ == "__main__":
    
    #HOST, PORT = '192.168.1.102', 9999

    HOST = None
    PORT = None
    
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hi:i:p:", ["help", "address=", "port="])
    except getopt.GetoptError as err:
        # print help information and exit:
        print str(err)  # will print something like "option -a not recognized"
        usage()
        sys.exit(2)

    for o, a in opts:
        if o in ("-i", "--address"):
            HOST = a
        elif o in ("-p", "--port"):
            PORT = int(a)
        elif o in ("-h", "--help"):
            utility.usage()
            sys.exit()
        else:
            utility.usage()
            sys.exit(2)

    if HOST is None:
        print "Address must be specified"
        utility.usage()
        sys.exit(2)

    if PORT is None:
        print "Port must be specified"
        utility.usage()
        sys.exit(2)

    SocketServer.ThreadingTCPServer.allow_reuse_address = True
    SocketServer.TCPServer.allow_reuse_address = True
    server = ThreadedTCPServer((HOST, PORT), PasswordManager)
    ip, port = server.server_address
    server_thread = threading.Thread(target=server.serve_forever)
    #Exit the server thread when the main thread terminates
    #server_thread.daemon = True
    server_thread.start()
    print "Server with IP: %s is running on port: " % ip, port
