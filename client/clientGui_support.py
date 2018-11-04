#! /usr/bin/env python
#  -*- coding: utf-8 -*-
#  Author: Fabio Condomitti
#    Jun 11, 2018 12:54:15 PM

import clientGui_security
import clientGui_utility

import sys
from threading import Timer

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
    
#global loggedIn
#loggedIn = False

global flagLogin
flagLogin = True

def login(login, cancel, username, password, console, logout, register, page):
    
    if clientGui_utility.testLogin(console, username.get(), password.get()) is False:
        return

    print('LOGIN')
    print '\tUsername: ' + username.get() + " Password: *********"

    global flagLogin
    global socket

    if flagLogin is True:
        socket = clientGui_security.init()
    code = "LOG"

    res = socket.registration(username.get(), password.get(), code)

    if int(res) != 1050 and int(res) != 1090:
        print "Connection accepted"

        cancel.configure(state='disabled')
        username.configure(state='disabled')
        password.delete(0,END)
        password.configure(state='disabled')

        register.configure(state='disabled')

        console.configure(state='normal')
        console.delete(0, END)
        console.insert(0, "Succesfully logged in. Choose an option.")
        console.configure(state='disabled')
        
        login.configure(state='disabled')
        logout.configure(state='active')

        flagLogin = True
        page.do_button(1)
    
    else:
        flagLogin = False
        console.configure(state='normal')
        console.delete(0, END)

        if int(res) == 1090:
            console.insert(0, "Too many errors in login/sign in phases. Please close the app and try again.")
            print "[Error] Too many attempts. Close the app and try again"
        else:
            console.insert(0, "Error in the login/registration phase. Please try again.")
            print "[Error] Error in the login/registration process"
        console.configure(state='disabled')

    sys.stdout.flush()

def logout(logout, cancel, username, password, console, login, register):

    print "__________________________________________________________"
    print('LOGOUT')
    print '\tUsername: ' + username.get() + " Password: *********"
    
    global flagLogin
    flagLogin = True
    cancel.configure(state='active')
    register.configure(state='active')

    username.configure(state='normal')
    username.delete(0,END)
    password.delete(0,END)
    password.configure(state='normal')

    console.configure(state='normal')
    console.delete(0, END)
    console.insert(0, "Succesfully logged out.")
    console.configure(state='disabled')
    
    login.configure(state='active')
    logout.configure(state='disabled')

    global socket
    socket.secureClose()

    clientGui_security.connectFlag = True

    print "Succesfully logged out"
    
def register(thisPage, register, cancel, username, password, console, password2 = None):
    
    if clientGui_utility.testRegistration(console, username.get(), password.get(), password2.get()) is False:
        return
    if clientGui_utility.testPasswordEqual(console, password.get(), password2.get()) is False:
        return

    print "__________________________________________________________"
    print('REGISTRATION')
    print '\tUsername: ' + username.get() + " Password1: *********" + " Password2: *********"
    
    global flagLogin
    global socket

    if flagLogin is True:
        socket = clientGui_security.init()

    code = "REG"
    res = socket.registration(username.get(), password.get(), code)
    
    if int(res) != 1050 and int(res) != 1070 and int(res) != 1090:
        print "Connection accepted"

        cancel.configure(state='disabled')

        username.configure(state='disabled')
        password.delete(0,END)
        password.configure(state='disabled')
        password2.delete(0,END)
        password2.configure(state='disabled')

        console.configure(state='normal')
        console.delete(0, END)
        console.insert(0, "Succesfully registration. Choose an option.")
        console.configure(state='disabled')
        
        register.configure(state='disabled')
 
        flagLogin = True

        thisPage.do_button()

        clearRegisterFields(username, password, password2, console, register, cancel)
    
    else:

        flagLogin = False
        console.configure(state='normal')
        console.delete(0, END)
        print "__________________________"
        print res
        if int(res) != 1070 and int(res) != 1090:
            console.insert(0, "Error in the registration phase. Please try again.")
            print "[Error] Error in the registration process"
        elif int(res) == 1090:
            console.insert(0, "Too many errors in login/sign in phases. Please close the app and try again.")
            print "[Error] Too many attempts. Close the app and try again"
        elif int(res) == 1070:
            console.insert(0, "The username you are trying to register is already used. Please change it.")
            print "[Error] Username already used. Try login or change it"
        
        console.configure(state='disabled')

    sys.stdout.flush()

def getpassword(e, website, console):

    if clientGui_utility.testWebsite(console, website.get(), "GET") is False:
        return

    print "__________________________________________________________"
    print('clientGui_support.getpassword')
    import clientGui
    user = clientGui.username
    print "User: " + user + " Website: " + website.get()

    global socket
    code = "GET"
    result = socket.requestResource(code, website.get())

    isInt, val = clientGui_utility.tryint(result)
    
    if result is not None and result is not False and result is not True and isInt is False:
        console.configure(state='normal')
        console.delete(0, END)
        console.insert(0, "The password for " + website.get() + " will be available in your clipboard for 5 seconds.")
        print "Password copied in the clipboars for 5 seconds"
        console.configure(state='disabled')

        website.delete(0, END)
        clientGui_utility.copy2clip(result)
        t = Timer(5.0, clientGui_utility.deleteClipboard, [console])
        t.start()

    elif val == 1103 and isInt is True:
        console.configure(state='normal')
        console.delete(0, END)
        console.insert(0, "The website you are looking for it is not stored. Please try again with another website.")
        print "[Error] The website is not stored"
        console.configure(state='disabled')
    else:
        console.configure(state='normal')
        console.delete(0, END)
        console.insert(0, "An error occurred during the retrieving process. Please try again.")
        print "[Error] Error during the retrieving process"
        console.configure(state='disabled')

    sys.stdout.flush()

def deletepassword(e, website, password, console):
    
    if clientGui_utility.testDeleteAdd(console, website.get(), password.get(), "DEL") is False:
        return

    print "__________________________________________________________"
    print('clientGui_support.deletepassword')
    import clientGui
    user = clientGui.username

    code = "DEL"
    global socket
    result = socket.requestResource(code, website.get(), password.get())

    website.delete(0, END)
    password.delete(0, END)

    console.configure(state='normal')
    console.delete(0, END)
    if result is True:       
        console.insert(0, "The password of " + website.get() + " is no longer stored now.")
    else:
        console.insert(0, "An error occurred during the elimination process. Please try again.")
    console.configure(state='disabled')

    sys.stdout.flush()

def addpassword(e, website, password, console):

    if clientGui_utility.testDeleteAdd(console, website.get(), password.get(), "ADD") is False:
        return
    print "__________________________________________________________"
    print('clientGui_support.addpassword')
    import clientGui
    user = clientGui.username
    code = "ADD"
    global socket
    result = socket.requestResource(code, website.get(), password.get())

    console.configure(state='normal')
    console.delete(0, END)

    website.delete(0, END)
    password.delete(0, END)

    if result is True:       
        console.insert(0, "You have added a password for the website:  " + website.get())
    else:
        console.insert(0, "An error occurred during the insertion process. Please try again.")
    console.configure(state='disabled')

    sys.stdout.flush()

def updatepassword(e, website, oldPass, newPass, console):

    if clientGui_utility.testUpdate(console, website.get(), oldPass.get(), newPass.get(), "UPD") is False:
        return

    if clientGui_utility.testPasswordDifferent(console, oldPass.get(), newPass.get()) is False:
        return

    print "__________________________________________________________"
    print('clientGui_support.updatepassword')
    import clientGui
    user = clientGui.username

    code = "UPD"
    global socket
    result = socket.requestResource(code, website.get(), oldPass.get(), newPass.get())
        
    website.delete(0, END)
    oldPass.delete(0, END)
    newPass.delete(0, END)
    console.configure(state='normal')
    console.delete(0, END)
    if result is True:       
        console.insert(0, "The password of " + website.get() + " has been correctly updated.")
    else:
        console.insert(0, "An error occurred during the update process. Please try again.")
    console.configure(state='disabled')

    sys.stdout.flush()


def clearFields(thisPage, website, password = None, passwordN = None):

    website.delete(0, END)
    if password is not None:
        password.delete(0, END)
    if passwordN is not None:
        passwordN.delete(0, END)
    thisPage.do_button()
    
def clearRegisterFields(username, password, password2, console, register, cancel):

    username.configure(state='normal')
    username.delete(0, END)
    password.configure(state='normal')
    password.delete(0, END)
    password2.configure(state='normal')
    password2.delete(0, END)
    console.configure(state='normal')
    console.delete(0, END)
    console.insert(0, "Insert a username and a password in order to register yourself.")
    console.configure(state='disabled')

    register.configure(state='active')
    cancel.configure(state='active')
