# PROJECT - Remote password manager
# Author: Fabio Condomitti - 
#         Alessandro Noferi - alessandro.noferi@gmail.com
# 
# Database  
#

import MySQLdb as mdb
import ConfigParser
import os
import binascii

def get_db_config():
    config = {}
    configParser = ConfigParser.RawConfigParser()   
    configFilePath = r'path to the file'
    configParser.read(configFilePath)
    config["user_name"] = configParser.get('credentials', 'user_name')
    config["password"] = configParser.get('credentials', 'password')
    config["location"] = configParser.get('credentials', 'location')
    config["db_name"] = configParser.get('credentials', 'db_name')
    return config

class Database:
    def __init__(self):
        self.config = get_db_config()
        pass
    
    def connect(self):
        try:
            config = self.config
            self.conn= mdb.connect(config["location"], config["user_name"], config["password"], config["db_name"])
            self.cursor = self.conn.cursor()
            self.state = True
            print "Connecting to databse...",
            print "OK"
            return (True, 100)
        except mdb.Error, e:
            print "Error %d: %s" % (e.args[0],e.args[1])
            return (False, e.args[0])
    
    def disconnect(self):
        if hasattr(self, 'state') and self.state is True:
            print "Disconnecting database...",
            self.cursor.close()
            self.conn.close()
            self.state = False
            print "OK"

    def add_user(self, id_table, user, hash_pwd, salt_hash):
        if user == '' or hash_pwd == '' or salt_hash == '':
            return(False, 1078)
        try:
            query = "INSERT INTO "+ id_table + " VALUES (%s,%s,%s)"
            self.cursor.execute(query, [user, hash_pwd, salt_hash])
            self.conn.commit()
            return (True, 100)

        except mdb.Error, e:
            if self.conn:
                self.conn.rollback()
                print "Error %d: %s" % (e.args[0],e.args[1])
            print "Error  %d: %s" % (e.args[0],e.args[1])
            return (False, e.args[0])
        
    def delete_user(self, id_table, user, hash_pwd):
        try:
            query = "DELETE FROM "+id_table+" WHERE ID = %s AND CAST(hash_password AS CHAR(100)) = %s"
            self.cursor.execute(query, [user, hash_pwd])
            query = "DROP TABLE " + user+"_table"
            self.cursor.execute(query)
            self.conn.commit()
            return (True, 100)
        except mdb.Error, e:
            if self.conn:
                self.conn.rollback()
            print "Error %d: %s" % (e.args[0],e.args[1])
            return (False, e.args[0])

    def find_user(self, user_ID, table):
        try:
            query = "SELECT COUNT(ID) FROM " + table + " WHERE ID = %s"
            self.cursor.execute(query, [user_ID])
            if self.cursor.fetchone()[0] == 1:
                return (True,100)
            else:
                print "Error 102: No user %s in %s_table" % (user_ID,table)
                return (False, 102) #102 NO USER
        except mdb.Error, e:
            print "Error %d: %s" % (e.args[0],e.args[1])
            return (False, e.args[0])

    def find_user_config(self, user_id, table):
        try:
        #query = "SET block_encryption_mode = 'aes-256-cbc'"
        #self.cursor.execute(query)
            query = "SELECT ID, hash_password, salt  FROM "+table+ " WHERE ID = %s"
            self.cursor.execute(query, [user_id])
            #print self.cursor.rowcount
            if self.cursor.rowcount == 1:
                return self.cursor.fetchone()
            else:
                return None

        except mdb.Error, e:
            print "Error %d: %s" % (e.args[0],e.args[1])
            return None 
    
    def get_salts(self, user_id, table):
        try:
        #query = "SET block_encryption_mode = 'aes-256-cbc'"
        #self.cursor.execute(query)
            query = "SELECT salt_kdf, salt_hash FROM "+table+ " WHERE ID = %s"
            self.cursor.execute(query, [user_id])
            print self.cursor.rowcount
            if self.cursor.rowcount == 1:
                
                return self.cursor.fetchone()
            else:
                return None

        except mdb.Error, e:
            print "Error %d: %s" % (e.args[0],e.args[1])
            return None  
    
    def find_password(self,client,site):
        try:
            query = "SELECT password, IV   FROM passwords WHERE  ID = %s AND sites = %s"
            self.cursor.execute(query,  [client, site])
            #print self.cursor.rowcount
            if self.cursor.rowcount == 1:
                user_password, IV = self.cursor.fetchone()
                if user_password is None:
                    print "Error 1112: Password not found" 
                    return (False, 1112)
                return (True,user_password, IV)
            else:
                print "Error 1103: site: %s does not exist" %site
                return (False, 1103)  #103 sito non esiste

        except mdb.Error, e:
            print "Error %d: %s" % (e.args[0],e.args[1])
            return (False, e.args[0])   

    def delete_password(self, client, site, password):
        try:
            query = "DELETE FROM passwords WHERE ID = %s AND sites = %s AND password = %s"
            rows = self.cursor.execute(query,  [client, site,password])
            self.conn.commit()
            if rows == 1:
                return (True, 100)
            else:
                print "Error 1019: Password does not match with site: %s" % site
                return (False, 1019)

        except mdb.Error, e:
            if self.conn:
                self.conn.rollback()
                print "Error %d: %s" % (e.args[0],e.args[1])
                return (False, e.args[0])
    
    def change_password(self, client, site, old_password, new_password, new_IV):
        if site == '' or old_password == '' or new_IV == '' or new_password == '':
            return(False, 1078)
        try:
            query = "UPDATE passwords SET password = %s, IV = %s \
                     WHERE sites = %s AND  password = %s and ID = %s"
            #print query % (new_password, key, new_IV, new_IV,site,key , IV, old_password)
            rows = self.cursor.execute(query, (new_password, new_IV,site,old_password, client))
            self.conn.commit()
            if rows == 1:
                return (True, 100)
            else:
                print "Error 1017: Old password does not match with site: %s" % site
                return (False, 1017)
        except mdb.Error, e:
            if self.conn:
                self.conn.rollback()
                print "Error %d: %s" % (e.args[0],e.args[1])
                return (False, e.args[0])

    def add_password(self, client, site, password, IV):
        if site == '' or password == '' or IV == '':
            return(False, 1078)
        try:
            query = "INSERT INTO  passwords (ID, sites, password, iv) VALUES (%s, %s, %s, %s)"
            self.cursor.execute(query, (client, site, password, IV))
            self.conn.commit()
            return (True, 100)

        except mdb.Error, e:
            if self.conn:
                self.conn.rollback()
                print "Error %d: %s" % (e.args[0],e.args[1])
                return (False, e.args[0])
    
    def find_IV(self, client, site):
        try:
            query = "SELECT IV  FROM passwords WHERE ID = %s AND sites = %s"
            self.cursor.execute(query,  [client, site])
            #print self.cursor.rowcount
            if self.cursor.rowcount == 1:
                IV = self.cursor.fetchone()[0]
                if IV is None:
                    print "Error 1112: Password not found" 
                    return (False, 1112)
                return (True, IV)
            else:
                print "Error 1103: site: %s does not exist" %site
                return (False, 1103)  #103 sito non esiste

        except mdb.Error, e:
            print "Error %d: %s" % (e.args[0],e.args[1])
            return (False, e.args[0])   

        

''' key = binascii.hexlify(os.urandom(16))

key= 'dc400d0924e185986de173665c3a645d'
#key = binascii.unhexlify(key_)
kdf = os.urandom(16)
hash_ = os.urandom(16)

print (kdf)
print (hash_)

db = Database()
db.connect()

#ret = db.add_user('users', 'fabiovregoiregtr;gj;hjtr;oijeoihjtrkgtjhgjtoihjwirligfiueghfiuhe', 'cenbfrlvne','ewfe')
#print ret

ret = db.add_user('users', '2wile', 'cenbfrlvne','ewfe')
print ret
ret = db.add_password("2wile", "dddd", "amoddddre mio", 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffrewgre')
print ret
#db.add_password("celia_table", "ebayn", "cas", key)

var = 'amazon\';DROP TABLE users'
ret = db.find_password('fabio',var)
print ret

#ret = db.delete_password('fabio', 'amazon','amoddddre mio', key )
#ret = db.delete_password('celia_table', 'amazon', 'ciao', key)
#ret = db.find_user('alse', 'users')

#ret = db.change_password('celia_table', 'amazon', 'TIAMO', key, 'CECILIATIAMO')
#ret = db.find_password('eh', 'celia_table', key)
#ret = db.delete_user('users', 'celia', 'cenbfrlvne')
#et = db.find_user_pwd('celia', 'users')
#ret = db.get_salts('fabio', 'users')
print  ret 

db = Database()
db.connect()
#ret = db.add_user('users', 'alessandro', 'cenbfrlvne','ewfe')
db.add_password("fabio", "amazon", os.urandom(32), os.urandom(16))
'''
