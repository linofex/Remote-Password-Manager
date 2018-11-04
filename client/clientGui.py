#! /usr/bin/env python
#  -*- coding: utf-8 -*-
#  Author: Fabio Condomitti
#    Jun 11, 2018 12:54:06 PM

import sys

try:
    from Tkinter import *
except ImportError:
    from tkinter import *
import Tkinter as tk
try:
    import ttk
    py3 = False
except ImportError:
    import tkinter.ttk as ttk
    py3 = True

import clientGui_support
import clientGui_utility
import clientGui_security

global username
username = ""

backgroundColor = '#d9d9d9'

def vp_start_gui():
    '''Starting point when module is the main routine.'''
    global val, w, root
    root = Tk()
    top = Client (root)
    root.mainloop()

w = None
def create_Client(root, *args, **kwargs):
    '''Starting point when module is imported by another program.'''
    global w, w_win, rt
    rt = root
    w = Toplevel (root)
    top = Client (w)
    #clientGui_support.init(w, top, *args, **kwargs)
    return (w, top)

def destroy_Client():
    global w
    w.destroy()
    w = None

class Client(tk.Tk):
    def __init__(self, *args, **kwargs):
        '''This class configures and populates the toplevel window.
           top is the toplevel containing window.'''
        tk.Tk.__init__(self, *args, **kwargs)

        #global  container
        container = tk.Frame(self)

        container.pack(side="top", fill="both", expand=True)

        container.grid_rowconfigure(0, weight=1)  # 0: minimum size, weight is like a priority
        container.grid_columnconfigure(0, weight=1)


        self.frames = {}  # dictionary
        
        for F in (HomePage, GetPasswordPage, DeletePasswordPage, UpdatePasswordPage, RegisterPage, AddPasswordPage):#, StartingPage):
            frame = F(container, self)  # user interacts with one(the "upper") frame(acts like a window)

            self.frames[F] = frame

            frame.grid(row=0, column=0, sticky="nsew")  # assign frames to grid. sticky = alignment + stretch ->North South East West

        self.show_frame(HomePage)
        
    def show_frame(self, cont):
        frame = self.frames[cont]  # cont = controller to access frames
        frame.tkraise()  # tkraise -> raise it to the front

    def get_page(self, page_class):
        return self.frames[page_class]

class HomePage(tk.Frame):
    
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        tk.Frame.configure(self, bg=backgroundColor)

        self.controller = controller
        
        font16 = "-family {Courier New} -size 16 -weight normal -slant"  \
            " roman -underline 0 -overstrike 0"
        font9 = "-family {Segoe UI} -size 9 -weight normal -slant "  \
            "roman -underline 0 -overstrike 0"

        NameLabelHome = tk.LabelFrame(self)
        NameLabelHome.place(relx=0.08, rely=0.15, relheight=0.17, relwidth=0.68)
        NameLabelHome.configure(relief=GROOVE)
        NameLabelHome.configure(foreground="black")
        NameLabelHome.configure(text='''Username''')
        NameLabelHome.configure(background="#d9d9d9")
        NameLabelHome.configure(highlightbackground="#d9d9d9")
        NameLabelHome.configure(highlightcolor="black")
        NameLabelHome.configure(width=410)

        global NameTextHome
        NameTextHome = tk.Entry(NameLabelHome)
        NameTextHome.place(relx=0.37, rely=0.25,height=26, relwidth=0.6)
        NameTextHome.configure(background="white")
        NameTextHome.configure(disabledforeground="#a3a3a3")
        NameTextHome.configure(font=font16)
        NameTextHome.configure(foreground="#000000")
        NameTextHome.configure(highlightbackground="#d9d9d9")
        NameTextHome.configure(highlightcolor="black")
        NameTextHome.configure(insertbackground="black")
        NameTextHome.configure(selectbackground="#c4c4c4")
        NameTextHome.configure(selectforeground="black")

        PasswordLabelHome = tk.LabelFrame(self)
        PasswordLabelHome.place(relx=0.08, rely=0.37, relheight=0.17, relwidth=0.68)
        PasswordLabelHome.configure(relief=GROOVE)
        PasswordLabelHome.configure(foreground="black")
        PasswordLabelHome.configure(text='''Password''')
        PasswordLabelHome.configure(background="#d9d9d9")
        PasswordLabelHome.configure(highlightbackground="#d9d9d9")
        PasswordLabelHome.configure(highlightcolor="black")
        PasswordLabelHome.configure(width=410)

        global PasswordTextHome
        PasswordTextHome = tk.Entry(PasswordLabelHome)
        PasswordTextHome.place(relx=0.37, rely=0.25,height=26, relwidth=0.6)
        PasswordTextHome.configure(background="white")
        PasswordTextHome.configure(disabledforeground="#a3a3a3")
        PasswordTextHome.configure(font=font16)
        PasswordTextHome.configure(foreground="#000000")
        PasswordTextHome.configure(highlightbackground="#d9d9d9")
        PasswordTextHome.configure(highlightcolor="black")
        PasswordTextHome.configure(insertbackground="black")
        PasswordTextHome.configure(selectbackground="#c4c4c4")
        PasswordTextHome.configure(selectforeground="black")
        PasswordTextHome.configure(show="*")
        PasswordTextHome.configure(justify="left")

        global checkbuttonHome
        checkbuttonHome = tk.Checkbutton(self)
        checkbuttonHome.place(relx=0.39, rely=0.55,height=26, relwidth=0.6)
        checkbuttonHome.configure(text="Hide password")
        checkbuttonHome.configure(activebackground="#d9d9d9")
        checkbuttonHome.configure(background="#d9d9d9")
        checkbuttonHome.configure(onvalue=True)
        checkbuttonHome.configure(offvalue=False)
        checkbuttonHome.configure(command=lambda widget="checkbutton1": clientGui_utility.toggle_password(checkbuttonHome, PasswordTextHome))
        checkbuttonHome.var = tk.BooleanVar(value=True)
        checkbuttonHome['variable'] = checkbuttonHome.var
        
        global CancelButtonHome
        CancelButtonHome = tk.Button(self)
        CancelButtonHome.place(relx=0.84, rely=0.19, height=42, width=66)
        CancelButtonHome.configure(activebackground="#d9d9d9")
        CancelButtonHome.configure(activeforeground="#000000")
        CancelButtonHome.configure(background="#d9d9d9")
        CancelButtonHome.configure(disabledforeground="#a3a3a3")
        CancelButtonHome.configure(foreground="#000000")
        CancelButtonHome.configure(highlightbackground="#d9d9d9")
        CancelButtonHome.configure(highlightcolor="black")
        CancelButtonHome.configure(pady="0")
        CancelButtonHome.configure(text='''Cancel''')
        CancelButtonHome.bind('<Button-1>', lambda e:clientGui_utility.cancel(e, NameTextHome, PasswordTextHome, ConsoleTextHome))
    
        global LoginButtonHome
        LoginButtonHome = tk.Button(self)
        LoginButtonHome.place(relx=0.79, rely=0.41, height=42, width=66)
        LoginButtonHome.configure(activebackground="#d9d9d9")
        LoginButtonHome.configure(activeforeground="#000000")
        LoginButtonHome.configure(background="#d9d9d9")
        LoginButtonHome.configure(disabledforeground="#a3a3a3")
        LoginButtonHome.configure(foreground="#000000")
        LoginButtonHome.configure(highlightbackground="#d9d9d9")
        LoginButtonHome.configure(highlightcolor="black")
        LoginButtonHome.configure(pady="0")
        LoginButtonHome.configure(text='''Login''')    
        LoginButtonHome.configure(command=lambda: clientGui_support.login(LoginButtonHome, CancelButtonHome, NameTextHome, PasswordTextHome,
                    ConsoleTextHome, LogoutButtonHome, SignInButtonHome, self))
    
        global LogoutButtonHome
        LogoutButtonHome = tk.Button(self)
        LogoutButtonHome.place(relx=0.89, rely=0.41, height=42, width=66)
        LogoutButtonHome.configure(activebackground="#d9d9d9")
        LogoutButtonHome.configure(activeforeground="#000000")
        LogoutButtonHome.configure(background="#d9d9d9")
        LogoutButtonHome.configure(disabledforeground="#a3a3a3")
        LogoutButtonHome.configure(foreground="#000000")
        LogoutButtonHome.configure(highlightbackground="#d9d9d9")
        LogoutButtonHome.configure(highlightcolor="black")
        LogoutButtonHome.configure(pady="0")
        LogoutButtonHome.configure(text='''Logout''')
        LogoutButtonHome.configure(command=lambda: clientGui_support.logout(LogoutButtonHome, CancelButtonHome, NameTextHome, PasswordTextHome,
                    ConsoleTextHome, LoginButtonHome, SignInButtonHome))
        LogoutButtonHome.configure(state='disabled')
        
        global SignInButtonHome
        SignInButtonHome = tk.Button(self)
        SignInButtonHome.place(relx=0.4, rely=0.66, height=42, width=123)
        SignInButtonHome.configure(activebackground="#d9d9d9")
        SignInButtonHome.configure(activeforeground="#000000")
        SignInButtonHome.configure(background="#d9d9d9")
        SignInButtonHome.configure(disabledforeground="#a3a3a3")
        SignInButtonHome.configure(foreground="#000000")
        SignInButtonHome.configure(highlightbackground="#d9d9d9")
        SignInButtonHome.configure(highlightcolor="black")
        SignInButtonHome.configure(pady="0")
        SignInButtonHome.configure(text='''Sign In''')
        SignInButtonHome.configure(command=lambda: controller.show_frame(RegisterPage))

        global ConsoleTextHome
        ConsoleTextHome = tk.Entry(self)
        ConsoleTextHome.place(relx=0.3, rely=0.84,height=26, relwidth=0.62)
        ConsoleTextHome.configure(background="white")
        ConsoleTextHome.configure(disabledforeground="#000000")
        ConsoleTextHome.configure(font=font9)
        ConsoleTextHome.configure(foreground="#000000")
        ConsoleTextHome.configure(highlightbackground="#d9d9d9")
        ConsoleTextHome.configure(highlightcolor="black")
        ConsoleTextHome.configure(insertbackground="black")
        ConsoleTextHome.configure(selectbackground="#c4c4c4")
        ConsoleTextHome.configure(selectforeground="black")
        ConsoleTextHome.insert(0, "Please insert your account information or sign in.")
        ConsoleTextHome.configure(state='disabled')

        ConsoleLabelHome = tk.Label(self)
        ConsoleLabelHome.place(relx=0.08, rely=0.82, height=41, width=82)
        ConsoleLabelHome.configure(activebackground="#f9f9f9")
        ConsoleLabelHome.configure(activeforeground="black")
        ConsoleLabelHome.configure(background="#d9d9d9")
        ConsoleLabelHome.configure(disabledforeground="#a3a3a3")
        ConsoleLabelHome.configure(foreground="#000000")
        ConsoleLabelHome.configure(highlightbackground="#d9d9d9")
        ConsoleLabelHome.configure(highlightcolor="black")
        ConsoleLabelHome.configure(text='''Console''')

    def resetHome(self):
        ConsoleTextHome.configure(state='normal')
        ConsoleTextHome.delete(0 ,END)
        ConsoleTextHome.insert(0, "Please insert your account information or sign in.")
        ConsoleTextHome.configure(state='disabled')
        NameTextHome.delete(0 ,END)
        NameTextHome.insert(0, "")
        PasswordTextHome.delete(0 ,END)
        PasswordTextHome.insert(0, "")
    
    """def resetPages(self):
        for F in (HomePage, GetPasswordPage, DeletePasswordPage, UpdatePasswordPage, RegisterPage, AddPasswordPage):
            F.reset()"""

    def do_button(self, code):
        
        #if code is 1:
        page = self.controller.get_page(HomePage)
        ####page.resetHome()
        #elif code is None:
            #page = self.controller.get_page(GetPasswordPage)

        page.goHome(self.controller, code)
    
    def goHome(self, c, code):
        #c.show_frame(StartingPage)
        if code is None:
            c.show_frame(HomePage)
        elif code is 1:
            c.show_frame(GetPasswordPage)

    def reset(self):
        clientGui_support.logout(LogoutButtonHome, CancelButtonHome, NameTextHome, PasswordTextHome,
                     ConsoleTextHome, LoginButtonHome, SignInButtonHome)
        clientGui_utility.reset_toggle_password(checkbuttonHome, PasswordTextHome)
        self.resetHome()
    
    def resetFields(self):
        clientGui_utility.reset_toggle_password(checkbuttonHome, PasswordTextHome)
        self.resetHome()

class GetPasswordPage(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        tk.Frame.configure(self, bg=backgroundColor)
        
        self.controller = controller

        font16 = "-family {Courier New} -size 16 -weight normal -slant"  \
            " roman -underline 0 -overstrike 0"
        font9 = "-family {Segoe UI} -size 9 -weight normal -slant "  \
            "roman -underline 0 -overstrike 0"

        WebsiteLabelGet = tk.LabelFrame(self)
        WebsiteLabelGet.place(relx=0.08, rely=0.15, relheight=0.17, relwidth=0.68)
        WebsiteLabelGet.configure(relief=GROOVE)
        WebsiteLabelGet.configure(foreground="black")
        WebsiteLabelGet.configure(text='''Website''')
        WebsiteLabelGet.configure(background="#d9d9d9")
        WebsiteLabelGet.configure(highlightbackground="#d9d9d9")
        WebsiteLabelGet.configure(highlightcolor="black")
        WebsiteLabelGet.configure(width=410)

        global WebsiteTextGet
        WebsiteTextGet = tk.Entry(WebsiteLabelGet)
        WebsiteTextGet.place(relx=0.37, rely=0.25,height=26, relwidth=0.6)
        WebsiteTextGet.configure(background="white")
        WebsiteTextGet.configure(disabledforeground="#a3a3a3")
        WebsiteTextGet.configure(font=font16)
        WebsiteTextGet.configure(foreground="#000000")
        WebsiteTextGet.configure(highlightbackground="#d9d9d9")
        WebsiteTextGet.configure(highlightcolor="black")
        WebsiteTextGet.configure(insertbackground="black")
        WebsiteTextGet.configure(selectbackground="#c4c4c4")
        WebsiteTextGet.configure(selectforeground="black")

        GetPasswordButtonGet = tk.Button(self)
        GetPasswordButtonGet.place(relx=0.80, rely=0.19, height=42, width=123)
        GetPasswordButtonGet.configure(activebackground="#d9d9d9")
        GetPasswordButtonGet.configure(activeforeground="#000000")
        GetPasswordButtonGet.configure(background="#d9d9d9")
        GetPasswordButtonGet.configure(disabledforeground="#a3a3a3")
        GetPasswordButtonGet.configure(foreground="#000000")
        GetPasswordButtonGet.configure(highlightbackground="#d9d9d9")
        GetPasswordButtonGet.configure(highlightcolor="black")
        GetPasswordButtonGet.configure(pady="0")
        GetPasswordButtonGet.configure(text='''Get Password''')
        GetPasswordButtonGet.bind('<Button-1>', lambda e: clientGui_support.getpassword(e, WebsiteTextGet, ConsoleTextGet))
    
        LogoutButtonGet = tk.Button(self)
        LogoutButtonGet.place(relx=0.05, rely=0.68, height=42, width=123)
        LogoutButtonGet.configure(activebackground="#d9d9d9")
        LogoutButtonGet.configure(activeforeground="#000000")
        LogoutButtonGet.configure(background="#d9d9d9")
        LogoutButtonGet.configure(disabledforeground="#a3a3a3")
        LogoutButtonGet.configure(foreground="#000000")
        LogoutButtonGet.configure(highlightbackground="#d9d9d9")
        LogoutButtonGet.configure(highlightcolor="black")
        LogoutButtonGet.configure(pady="0")
        LogoutButtonGet.configure(text='''Logout''')
        LogoutButtonGet.configure(command=lambda: clientGui_support.clearFields(self, WebsiteTextGet))

        AddPasswordButtonGet = tk.Button(self)
        AddPasswordButtonGet.place(relx=0.30, rely=0.68, height=42, width=123)
        AddPasswordButtonGet.configure(activebackground="#d9d9d9")
        AddPasswordButtonGet.configure(activeforeground="#000000")
        AddPasswordButtonGet.configure(background="#d9d9d9")
        AddPasswordButtonGet.configure(disabledforeground="#a3a3a3")
        AddPasswordButtonGet.configure(foreground="#000000")
        AddPasswordButtonGet.configure(highlightbackground="#d9d9d9")
        AddPasswordButtonGet.configure(highlightcolor="black")
        AddPasswordButtonGet.configure(pady="0")
        AddPasswordButtonGet.configure(text='''Add Password''')
        AddPasswordButtonGet.bind('<Button-1>', lambda e: controller.show_frame(AddPasswordPage))

        DeletePasswordButtonGet = tk.Button(self)
        DeletePasswordButtonGet.place(relx=0.55, rely=0.68, height=42, width=123)
        DeletePasswordButtonGet.configure(activebackground="#d9d9d9")
        DeletePasswordButtonGet.configure(activeforeground="#000000")
        DeletePasswordButtonGet.configure(background="#d9d9d9")
        DeletePasswordButtonGet.configure(disabledforeground="#a3a3a3")
        DeletePasswordButtonGet.configure(foreground="#000000")
        DeletePasswordButtonGet.configure(highlightbackground="#d9d9d9")
        DeletePasswordButtonGet.configure(highlightcolor="black")
        DeletePasswordButtonGet.configure(pady="0")
        DeletePasswordButtonGet.configure(text='''Delete Password''')
        DeletePasswordButtonGet.bind('<Button-1>', lambda e: controller.show_frame(DeletePasswordPage))

        UpdatePasswordButtonGet = tk.Button(self)
        UpdatePasswordButtonGet.place(relx=0.8, rely=0.68, height=42, width=123)
        UpdatePasswordButtonGet.configure(activebackground="#d9d9d9")
        UpdatePasswordButtonGet.configure(activeforeground="#000000")
        UpdatePasswordButtonGet.configure(background="#d9d9d9")
        UpdatePasswordButtonGet.configure(disabledforeground="#a3a3a3")
        UpdatePasswordButtonGet.configure(foreground="#000000")
        UpdatePasswordButtonGet.configure(highlightbackground="#d9d9d9")
        UpdatePasswordButtonGet.configure(highlightcolor="black")
        UpdatePasswordButtonGet.configure(pady="0")
        UpdatePasswordButtonGet.configure(text='''Update Password''')
        UpdatePasswordButtonGet.bind('<Button-1>', lambda e: controller.show_frame(UpdatePasswordPage))

        global ConsoleTextGet
        ConsoleTextGet = tk.Entry(self)
        ConsoleTextGet.place(relx=0.3, rely=0.84,height=26, relwidth=0.62)
        ConsoleTextGet.configure(background="white")
        ConsoleTextGet.configure(disabledforeground="#000000")
        ConsoleTextGet.configure(font=font9)
        ConsoleTextGet.configure(foreground="#000000")
        ConsoleTextGet.configure(highlightbackground="#d9d9d9")
        ConsoleTextGet.configure(highlightcolor="black")
        ConsoleTextGet.configure(insertbackground="black")
        ConsoleTextGet.configure(selectbackground="#c4c4c4")
        ConsoleTextGet.configure(selectforeground="black")
        ConsoleTextGet.insert(0, "Insert the name of the website to retrieve its password.")
        ConsoleTextGet.configure(state='disabled')
        
        ConsoleLabelGet = tk.Label(self)
        ConsoleLabelGet.place(relx=0.08, rely=0.82, height=41, width=82)
        ConsoleLabelGet.configure(activebackground="#f9f9f9")
        ConsoleLabelGet.configure(activeforeground="black")
        ConsoleLabelGet.configure(background="#d9d9d9")
        ConsoleLabelGet.configure(disabledforeground="#a3a3a3")
        ConsoleLabelGet.configure(foreground="#000000")
        ConsoleLabelGet.configure(highlightbackground="#d9d9d9")
        ConsoleLabelGet.configure(highlightcolor="black")
        ConsoleLabelGet.configure(text='''Console''')

    def reset(self):
        ConsoleTextGet.configure(state='normal')
        ConsoleTextGet.delete(0 ,END)
        ConsoleTextGet.insert(0, "Insert the name of the website to retrieve its password.")
        ConsoleTextGet.configure(state='disabled')
        WebsiteTextGet.delete(0 ,END)
        WebsiteTextGet.insert(0, "")

    def goHome(self, c):
        c.show_frame(HomePage)
            
    def do_button(self):
        page = self.controller.get_page(GetPasswordPage)
        page.goHome(self.controller)
        page.reset()

        upd = self.controller.get_page(UpdatePasswordPage)
        upd.reset()
        dlt = self.controller.get_page(DeletePasswordPage)
        dlt.reset()
        add = self.controller.get_page(AddPasswordPage)
        add.reset()
        reg = self.controller.get_page(RegisterPage)
        reg.reset()
        home = self.controller.get_page(HomePage)
        home.reset()

class RegisterPage(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        tk.Frame.configure(self, bg=backgroundColor)
        self.controller = controller
        
        font16 = "-family {Courier New} -size 16 -weight normal -slant"  \
            " roman -underline 0 -overstrike 0"
        font9 = "-family {Segoe UI} -size 9 -weight normal -slant "  \
            "roman -underline 0 -overstrike 0"

        NameLabelRegister = tk.LabelFrame(self)
        NameLabelRegister.place(relx=0.08, rely=0.15, relheight=0.17, relwidth=0.68)
        NameLabelRegister.configure(relief=GROOVE)
        NameLabelRegister.configure(foreground="black")
        NameLabelRegister.configure(text='''Username''')
        NameLabelRegister.configure(background="#d9d9d9")
        NameLabelRegister.configure(highlightbackground="#d9d9d9")
        NameLabelRegister.configure(highlightcolor="black")
        NameLabelRegister.configure(width=410)

        global NameTextRegister
        NameTextRegister = tk.Entry(NameLabelRegister)
        NameTextRegister.place(relx=0.37, rely=0.25,height=26, relwidth=0.6)
        NameTextRegister.configure(background="white")
        NameTextRegister.configure(disabledforeground="#a3a3a3")
        NameTextRegister.configure(font=font16)
        NameTextRegister.configure(foreground="#000000")
        NameTextRegister.configure(highlightbackground="#d9d9d9")
        NameTextRegister.configure(highlightcolor="black")
        NameTextRegister.configure(insertbackground="black")
        NameTextRegister.configure(selectbackground="#c4c4c4")
        NameTextRegister.configure(selectforeground="black")

        PasswordLabelRegister1 = tk.LabelFrame(self)
        PasswordLabelRegister1.place(relx=0.08, rely=0.37, relheight=0.17, relwidth=0.68)
        PasswordLabelRegister1.configure(relief=GROOVE)
        PasswordLabelRegister1.configure(foreground="black")
        PasswordLabelRegister1.configure(text='''Password''')
        PasswordLabelRegister1.configure(background="#d9d9d9")
        PasswordLabelRegister1.configure(highlightbackground="#d9d9d9")
        PasswordLabelRegister1.configure(highlightcolor="black")
        PasswordLabelRegister1.configure(width=410)

        global PasswordTextRegister1
        PasswordTextRegister1 = tk.Entry(PasswordLabelRegister1)
        PasswordTextRegister1.place(relx=0.37, rely=0.25,height=26, relwidth=0.6)
        PasswordTextRegister1.configure(background="white")
        PasswordTextRegister1.configure(disabledforeground="#a3a3a3")
        PasswordTextRegister1.configure(font=font16)
        PasswordTextRegister1.configure(foreground="#000000")
        PasswordTextRegister1.configure(highlightbackground="#d9d9d9")
        PasswordTextRegister1.configure(highlightcolor="black")
        PasswordTextRegister1.configure(insertbackground="black")
        PasswordTextRegister1.configure(selectbackground="#c4c4c4")
        PasswordTextRegister1.configure(selectforeground="black")
        PasswordTextRegister1.configure(show="*")
        PasswordTextRegister1.configure(justify="left")

        PasswordLabelRegister2 = tk.LabelFrame(self)
        PasswordLabelRegister2.place(relx=0.08, rely=0.59, relheight=0.17, relwidth=0.68)
        PasswordLabelRegister2.configure(relief=GROOVE)
        PasswordLabelRegister2.configure(foreground="black")
        PasswordLabelRegister2.configure(text='''Repeat Password''')
        PasswordLabelRegister2.configure(background="#d9d9d9")
        PasswordLabelRegister2.configure(highlightbackground="#d9d9d9")
        PasswordLabelRegister2.configure(highlightcolor="black")
        PasswordLabelRegister2.configure(width=410)

        global PasswordTextRegister2
        PasswordTextRegister2 = tk.Entry(PasswordLabelRegister2)
        PasswordTextRegister2.place(relx=0.37, rely=0.25,height=26, relwidth=0.6)
        PasswordTextRegister2.configure(background="white")
        PasswordTextRegister2.configure(disabledforeground="#a3a3a3")
        PasswordTextRegister2.configure(font=font16)
        PasswordTextRegister2.configure(foreground="#000000")
        PasswordTextRegister2.configure(highlightbackground="#d9d9d9")
        PasswordTextRegister2.configure(highlightcolor="black")
        PasswordTextRegister2.configure(insertbackground="black")
        PasswordTextRegister2.configure(selectbackground="#c4c4c4")
        PasswordTextRegister2.configure(selectforeground="black")
        PasswordTextRegister2.configure(show="*")
        PasswordTextRegister2.configure(justify="left")

        global checkbuttonRegister
        checkbuttonRegister = tk.Checkbutton(self)
        checkbuttonRegister.place(relx=0.39, rely=0.77,height=26, relwidth=0.6)
        checkbuttonRegister.configure(text="Hide password")
        checkbuttonRegister.configure(background="#d9d9d9")
        checkbuttonRegister.configure(activebackground="#d9d9d9")
        checkbuttonRegister.configure(onvalue=True)
        checkbuttonRegister.configure(offvalue=False)
        checkbuttonRegister.configure(command=lambda widget="checkbuttonRegister": clientGui_utility.toggle_password(checkbuttonRegister, PasswordTextRegister1, PasswordTextRegister2))
        
        checkbuttonRegister.var = tk.BooleanVar(value=True)
        checkbuttonRegister['variable'] = checkbuttonRegister.var

        CancelButtonRegister = tk.Button(self)
        CancelButtonRegister.place(relx=0.84, rely=0.19, height=42, width=66)
        CancelButtonRegister.configure(activebackground="#d9d9d9")
        CancelButtonRegister.configure(activeforeground="#000000")
        CancelButtonRegister.configure(background="#d9d9d9")
        CancelButtonRegister.configure(disabledforeground="#a3a3a3")
        CancelButtonRegister.configure(foreground="#000000")
        CancelButtonRegister.configure(highlightbackground="#d9d9d9")
        CancelButtonRegister.configure(highlightcolor="black")
        CancelButtonRegister.configure(pady="0")
        CancelButtonRegister.configure(text='''Cancel''')
        CancelButtonRegister.bind('<Button-1>', lambda e:clientGui_utility.cancel(e, NameTextRegister, PasswordTextRegister1, ConsoleTextRegister, PasswordTextRegister2))

        RegisterButtonRegister = tk.Button(self)
        RegisterButtonRegister.place(relx=0.80, rely=0.41, height=42, width=123)
        RegisterButtonRegister.configure(activebackground="#d9d9d9")
        RegisterButtonRegister.configure(activeforeground="#000000")
        RegisterButtonRegister.configure(background="#d9d9d9")
        RegisterButtonRegister.configure(disabledforeground="#a3a3a3")
        RegisterButtonRegister.configure(foreground="#000000")
        RegisterButtonRegister.configure(highlightbackground="#d9d9d9")
        RegisterButtonRegister.configure(highlightcolor="black")
        RegisterButtonRegister.configure(pady="0")
        RegisterButtonRegister.configure(text='''Sign In''')
        RegisterButtonRegister.configure(command=lambda: clientGui_support.register(self, RegisterButtonRegister, CancelButtonRegister, NameTextRegister, PasswordTextRegister1,
                     ConsoleTextRegister, PasswordTextRegister2))
                     
        global LoginButtonRegister
        LoginButtonRegister = tk.Button(self)
        LoginButtonRegister.place(relx=0.84, rely=0.63, height=42, width=66)
        LoginButtonRegister.configure(activebackground="#d9d9d9")
        LoginButtonRegister.configure(activeforeground="#000000")
        LoginButtonRegister.configure(background="#d9d9d9")
        LoginButtonRegister.configure(disabledforeground="#a3a3a3")
        LoginButtonRegister.configure(foreground="#000000")
        LoginButtonRegister.configure(highlightbackground="#d9d9d9")
        LoginButtonRegister.configure(highlightcolor="black")
        LoginButtonRegister.configure(pady="0")
        LoginButtonRegister.configure(text='''Login''')
        LoginButtonRegister.bind('<Button-1>', lambda e: controller.show_frame(HomePage))

        global ConsoleTextRegister
        ConsoleTextRegister = tk.Entry(self)
        ConsoleTextRegister.place(relx=0.3, rely=0.84,height=26, relwidth=0.62)
        ConsoleTextRegister.configure(background="white")
        ConsoleTextRegister.configure(disabledforeground="#000000")
        ConsoleTextRegister.configure(font=font9)
        ConsoleTextRegister.configure(foreground="#000000")
        ConsoleTextRegister.configure(highlightbackground="#d9d9d9")
        ConsoleTextRegister.configure(highlightcolor="black")
        ConsoleTextRegister.configure(insertbackground="black")
        ConsoleTextRegister.configure(selectbackground="#c4c4c4")
        ConsoleTextRegister.configure(selectforeground="black")
        ConsoleTextRegister.insert(0, "Insert a username and a password in order to register yourself.")
        ConsoleTextRegister.configure(state='disabled')

        ConsoleLabelRegister = tk.Label(self)
        ConsoleLabelRegister.place(relx=0.08, rely=0.82, height=41, width=82)
        ConsoleLabelRegister.configure(activebackground="#f9f9f9")
        ConsoleLabelRegister.configure(activeforeground="black")
        ConsoleLabelRegister.configure(background="#d9d9d9")
        ConsoleLabelRegister.configure(disabledforeground="#a3a3a3")
        ConsoleLabelRegister.configure(foreground="#000000")
        ConsoleLabelRegister.configure(highlightbackground="#d9d9d9")
        ConsoleLabelRegister.configure(highlightcolor="black")
        ConsoleLabelRegister.configure(text='''Console''')

    def reset(self):
        ConsoleTextRegister.configure(state='normal')
        ConsoleTextRegister.delete(0 ,END)
        ConsoleTextRegister.insert(0, "Insert a username and a password in order to register yourself.")
        ConsoleTextRegister.configure(state='disabled')
        NameTextRegister.delete(0 ,END)
        NameTextRegister.insert(0, "")
        PasswordTextRegister1.delete(0 ,END)
        PasswordTextRegister1.insert(0, "")
        PasswordTextRegister2.delete(0 ,END)
        PasswordTextRegister2.insert(0, "")

    def goHome(self, c):
        #c.show_frame(HomePage)
        c.show_frame(GetPasswordPage)
            
    def do_button(self):
        page = self.controller.get_page(RegisterPage)
        page.goHome(self.controller)
        page.reset()

        upd = self.controller.get_page(UpdatePasswordPage)
        upd.reset()
        dlt = self.controller.get_page(DeletePasswordPage)
        dlt.reset()
        add = self.controller.get_page(AddPasswordPage)
        add.reset()
        get = self.controller.get_page(GetPasswordPage)
        get.reset()
        home = self.controller.get_page(HomePage)
        home.resetFields()

        clientGui_utility.reset_toggle_password(checkbuttonRegister, PasswordTextRegister1, PasswordTextRegister2)

class DeletePasswordPage(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        tk.Frame.configure(self, bg=backgroundColor)

        self.controller = controller
        
        font16 = "-family {Courier New} -size 16 -weight normal -slant"  \
            " roman -underline 0 -overstrike 0"
        font9 = "-family {Segoe UI} -size 9 -weight normal -slant "  \
            "roman -underline 0 -overstrike 0"

        WebsiteLabelDelete = tk.LabelFrame(self)
        WebsiteLabelDelete.place(relx=0.08, rely=0.15, relheight=0.17
                , relwidth=0.68)
        WebsiteLabelDelete.configure(relief=GROOVE)
        WebsiteLabelDelete.configure(foreground="black")
        WebsiteLabelDelete.configure(text='''Website''')
        WebsiteLabelDelete.configure(background="#d9d9d9")
        WebsiteLabelDelete.configure(highlightbackground="#d9d9d9")
        WebsiteLabelDelete.configure(highlightcolor="black")
        WebsiteLabelDelete.configure(width=410)

        global WebsiteTextDelete
        WebsiteTextDelete = tk.Entry(WebsiteLabelDelete)
        WebsiteTextDelete.place(relx=0.37, rely=0.25,height=26, relwidth=0.6)
        WebsiteTextDelete.configure(background="white")
        WebsiteTextDelete.configure(disabledforeground="#a3a3a3")
        WebsiteTextDelete.configure(font=font16)
        WebsiteTextDelete.configure(foreground="#000000")
        WebsiteTextDelete.configure(highlightbackground="#d9d9d9")
        WebsiteTextDelete.configure(highlightcolor="black")
        WebsiteTextDelete.configure(insertbackground="black")
        WebsiteTextDelete.configure(selectbackground="#c4c4c4")
        WebsiteTextDelete.configure(selectforeground="black")

        PasswordLabelDelete = tk.LabelFrame(self)
        PasswordLabelDelete.place(relx=0.08, rely=0.37, relheight=0.17, relwidth=0.68)
        PasswordLabelDelete.configure(relief=GROOVE)
        PasswordLabelDelete.configure(foreground="black")
        PasswordLabelDelete.configure(text='''Password''')
        PasswordLabelDelete.configure(background="#d9d9d9")
        PasswordLabelDelete.configure(highlightbackground="#d9d9d9")
        PasswordLabelDelete.configure(highlightcolor="black")
        PasswordLabelDelete.configure(width=410)

        global PasswordTextDelete
        PasswordTextDelete = tk.Entry(PasswordLabelDelete)
        PasswordTextDelete.place(relx=0.37, rely=0.25,height=26, relwidth=0.6)
        PasswordTextDelete.configure(background="white")
        PasswordTextDelete.configure(disabledforeground="#a3a3a3")
        PasswordTextDelete.configure(font=font16)
        PasswordTextDelete.configure(foreground="#000000")
        PasswordTextDelete.configure(highlightbackground="#d9d9d9")
        PasswordTextDelete.configure(highlightcolor="black")
        PasswordTextDelete.configure(insertbackground="black")
        PasswordTextDelete.configure(selectbackground="#c4c4c4")
        PasswordTextDelete.configure(selectforeground="black")
        PasswordTextDelete.configure(show="*")
        PasswordTextDelete.configure(justify="left")

        global checkbuttonDelete
        checkbuttonDelete = tk.Checkbutton(self)
        checkbuttonDelete.place(relx=0.39, rely=0.55,height=26, relwidth=0.6)
        checkbuttonDelete.configure(text="Hide password")
        checkbuttonDelete.configure(background="#d9d9d9")
        checkbuttonDelete.configure(activebackground="#d9d9d9")
        checkbuttonDelete.configure(onvalue=True)
        checkbuttonDelete.configure(offvalue=False)
        checkbuttonDelete.configure(command=lambda widget="checkbuttonDelete": clientGui_utility.toggle_password(checkbuttonDelete, PasswordTextDelete))
        checkbuttonDelete.var = tk.BooleanVar(value=True)
        checkbuttonDelete['variable'] = checkbuttonDelete.var

        PasswordButtonDelete = tk.Button(self)
        PasswordButtonDelete.place(relx=0.80, rely=0.19, height=42, width=123)
        PasswordButtonDelete.configure(activebackground="#d9d9d9")
        PasswordButtonDelete.configure(activeforeground="#000000")
        PasswordButtonDelete.configure(background="#d9d9d9")
        PasswordButtonDelete.configure(disabledforeground="#a3a3a3")
        PasswordButtonDelete.configure(foreground="#000000")
        PasswordButtonDelete.configure(highlightbackground="#d9d9d9")
        PasswordButtonDelete.configure(highlightcolor="black")
        PasswordButtonDelete.configure(pady="0")
        PasswordButtonDelete.configure(text='''Delete Password''')
        PasswordButtonDelete.bind('<Button-1>', lambda e: clientGui_support.deletepassword(e, 
                WebsiteTextDelete, PasswordTextDelete, ConsoleTextDelete))

        LogoutButtonDelete = tk.Button(self)
        LogoutButtonDelete.place(relx=0.05, rely=0.68, height=42, width=123)
        LogoutButtonDelete.configure(activebackground="#d9d9d9")
        LogoutButtonDelete.configure(activeforeground="#000000")
        LogoutButtonDelete.configure(background="#d9d9d9")
        LogoutButtonDelete.configure(disabledforeground="#a3a3a3")
        LogoutButtonDelete.configure(foreground="#000000")
        LogoutButtonDelete.configure(highlightbackground="#d9d9d9")
        LogoutButtonDelete.configure(highlightcolor="black")
        LogoutButtonDelete.configure(pady="0")
        LogoutButtonDelete.configure(text='''Logout''')
        LogoutButtonDelete.configure(command=lambda: clientGui_support.clearFields(self, WebsiteTextDelete, PasswordTextDelete))
    
        GetPasswordButtonDelete = tk.Button(self)
        GetPasswordButtonDelete.place(relx=0.30, rely=0.68, height=42, width=123)
        GetPasswordButtonDelete.configure(activebackground="#d9d9d9")
        GetPasswordButtonDelete.configure(activeforeground="#000000")
        GetPasswordButtonDelete.configure(background="#d9d9d9")
        GetPasswordButtonDelete.configure(disabledforeground="#a3a3a3")
        GetPasswordButtonDelete.configure(foreground="#000000")
        GetPasswordButtonDelete.configure(highlightbackground="#d9d9d9")
        GetPasswordButtonDelete.configure(highlightcolor="black")
        GetPasswordButtonDelete.configure(pady="0")
        GetPasswordButtonDelete.configure(text='''Get Password''')
        GetPasswordButtonDelete.bind('<Button-1>', lambda e: controller.show_frame(GetPasswordPage))

        AddPasswordButtonDelete = tk.Button(self)
        AddPasswordButtonDelete.place(relx=0.55, rely=0.68, height=42, width=123)
        AddPasswordButtonDelete.configure(activebackground="#d9d9d9")
        AddPasswordButtonDelete.configure(activeforeground="#000000")
        AddPasswordButtonDelete.configure(background="#d9d9d9")
        AddPasswordButtonDelete.configure(disabledforeground="#a3a3a3")
        AddPasswordButtonDelete.configure(foreground="#000000")
        AddPasswordButtonDelete.configure(highlightbackground="#d9d9d9")
        AddPasswordButtonDelete.configure(highlightcolor="black")
        AddPasswordButtonDelete.configure(pady="0")
        AddPasswordButtonDelete.configure(text='''Add Password''')
        AddPasswordButtonDelete.bind('<Button-1>', lambda e: controller.show_frame(AddPasswordPage))

        UpdatePasswordButtonDelete = tk.Button(self)
        UpdatePasswordButtonDelete.place(relx=0.80, rely=0.68, height=42, width=123)
        UpdatePasswordButtonDelete.configure(activebackground="#d9d9d9")
        UpdatePasswordButtonDelete.configure(activeforeground="#000000")
        UpdatePasswordButtonDelete.configure(background="#d9d9d9")
        UpdatePasswordButtonDelete.configure(disabledforeground="#a3a3a3")
        UpdatePasswordButtonDelete.configure(foreground="#000000")
        UpdatePasswordButtonDelete.configure(highlightbackground="#d9d9d9")
        UpdatePasswordButtonDelete.configure(highlightcolor="black")
        UpdatePasswordButtonDelete.configure(pady="0")
        UpdatePasswordButtonDelete.configure(text='''Update Password''')
        UpdatePasswordButtonDelete.bind('<Button-1>', lambda e: controller.show_frame(UpdatePasswordPage))

        global ConsoleTextDelete
        ConsoleTextDelete = tk.Entry(self)
        ConsoleTextDelete.place(relx=0.3, rely=0.84,height=26, relwidth=0.62)
        ConsoleTextDelete.configure(background="white")
        ConsoleTextDelete.configure(disabledforeground="#000000")
        ConsoleTextDelete.configure(font=font9)
        ConsoleTextDelete.configure(foreground="#000000")
        ConsoleTextDelete.configure(highlightbackground="#d9d9d9")
        ConsoleTextDelete.configure(highlightcolor="black")
        ConsoleTextDelete.configure(insertbackground="black")
        ConsoleTextDelete.configure(selectbackground="#c4c4c4")
        ConsoleTextDelete.configure(selectforeground="black")
        ConsoleTextDelete.insert(0, "Insert the name of the website and its password to delete it.")
        ConsoleTextDelete.configure(state='disabled')

        ConsoleLabelDelete = tk.Label(self)
        ConsoleLabelDelete.place(relx=0.08, rely=0.82, height=41, width=82)
        ConsoleLabelDelete.configure(activebackground="#f9f9f9")
        ConsoleLabelDelete.configure(activeforeground="black")
        ConsoleLabelDelete.configure(background="#d9d9d9")
        ConsoleLabelDelete.configure(disabledforeground="#a3a3a3")
        ConsoleLabelDelete.configure(foreground="#000000")
        ConsoleLabelDelete.configure(highlightbackground="#d9d9d9")
        ConsoleLabelDelete.configure(highlightcolor="black")
        ConsoleLabelDelete.configure(text='''Console''')

    def reset(self):
        ConsoleTextDelete.configure(state='normal')
        ConsoleTextDelete.delete(0 ,END)
        ConsoleTextDelete.insert(0, "Insert the name of the website and its password to delete it.")
        ConsoleTextDelete.configure(state='disabled')
        WebsiteTextDelete.delete(0 ,END)
        WebsiteTextDelete.insert(0, "")
        PasswordTextDelete.delete(0 ,END)
        PasswordTextDelete.insert(0, "")
    
    def goHome(self, c):
        c.show_frame(HomePage)
            
    def do_button(self):
        page = self.controller.get_page(DeletePasswordPage)
        page.goHome(self.controller)
        page.reset()

        upd = self.controller.get_page(UpdatePasswordPage)
        upd.reset()
        get = self.controller.get_page(GetPasswordPage)
        get.reset()
        add = self.controller.get_page(AddPasswordPage)
        add.reset()
        reg = self.controller.get_page(RegisterPage)
        reg.reset()
        home = self.controller.get_page(HomePage)
        home.reset()

        clientGui_utility.reset_toggle_password(checkbuttonDelete, PasswordTextDelete)
        #clientGui_utility.reset_toggle_password(checkbuttonDelete, PasswordTextDelete)
        #clientGui_utility.toggle_password(checkbuttonDelete, PasswordTextDelete)
        #checkbuttonDelete.var.set(False)

class UpdatePasswordPage(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        tk.Frame.configure(self, bg=backgroundColor)
        self.controller = controller

        font16 = "-family {Courier New} -size 16 -weight normal -slant"  \
            " roman -underline 0 -overstrike 0"
        font9 = "-family {Segoe UI} -size 9 -weight normal -slant "  \
            "roman -underline 0 -overstrike 0"

        WebsiteLabelUpdate = tk.LabelFrame(self)
        WebsiteLabelUpdate.place(relx=0.08, rely=0.15, relheight=0.17, relwidth=0.68)
        WebsiteLabelUpdate.configure(relief=GROOVE)
        WebsiteLabelUpdate.configure(foreground="black")
        WebsiteLabelUpdate.configure(text='''Website''')
        WebsiteLabelUpdate.configure(background="#d9d9d9")
        WebsiteLabelUpdate.configure(highlightbackground="#d9d9d9")
        WebsiteLabelUpdate.configure(highlightcolor="black")
        WebsiteLabelUpdate.configure(width=410)

        global WebsiteTextUpdate
        WebsiteTextUpdate = tk.Entry(WebsiteLabelUpdate)
        WebsiteTextUpdate.place(relx=0.37, rely=0.25,height=26, relwidth=0.6)
        WebsiteTextUpdate.configure(background="white")
        WebsiteTextUpdate.configure(disabledforeground="#a3a3a3")
        WebsiteTextUpdate.configure(font=font16)
        WebsiteTextUpdate.configure(foreground="#000000")
        WebsiteTextUpdate.configure(highlightbackground="#d9d9d9")
        WebsiteTextUpdate.configure(highlightcolor="black")
        WebsiteTextUpdate.configure(insertbackground="black")
        WebsiteTextUpdate.configure(selectbackground="#c4c4c4")
        WebsiteTextUpdate.configure(selectforeground="black")

        OldPasswordLabelUpdate = tk.LabelFrame(self)
        OldPasswordLabelUpdate.place(relx=0.08, rely=0.37, relheight=0.17, relwidth=0.28)
        OldPasswordLabelUpdate.configure(relief=GROOVE)
        OldPasswordLabelUpdate.configure(foreground="black")
        OldPasswordLabelUpdate.configure(text='''Old Password''')
        OldPasswordLabelUpdate.configure(background="#d9d9d9")
        OldPasswordLabelUpdate.configure(highlightbackground="#d9d9d9")
        OldPasswordLabelUpdate.configure(highlightcolor="black")
        OldPasswordLabelUpdate.configure(width=410)

        global OldPasswordTextUpdate
        OldPasswordTextUpdate = tk.Entry(OldPasswordLabelUpdate)
        OldPasswordTextUpdate.place(relx=0.10, rely=0.25,height=26, relwidth=0.8)
        OldPasswordTextUpdate.configure(background="white")
        OldPasswordTextUpdate.configure(disabledforeground="#a3a3a3")
        OldPasswordTextUpdate.configure(font=font16)
        OldPasswordTextUpdate.configure(foreground="#000000")
        OldPasswordTextUpdate.configure(highlightbackground="#d9d9d9")
        OldPasswordTextUpdate.configure(highlightcolor="black")
        OldPasswordTextUpdate.configure(insertbackground="black")
        OldPasswordTextUpdate.configure(selectbackground="#c4c4c4")
        OldPasswordTextUpdate.configure(selectforeground="black")
        OldPasswordTextUpdate.configure(show="*")
        OldPasswordTextUpdate.configure(justify="left")
        
        NewPasswordLabelUpdate = tk.LabelFrame(self)
        NewPasswordLabelUpdate.place(relx=0.48, rely=0.37, relheight=0.17, relwidth=0.28)
        NewPasswordLabelUpdate.configure(relief=GROOVE)
        NewPasswordLabelUpdate.configure(foreground="black")
        NewPasswordLabelUpdate.configure(text='''New Password''')
        NewPasswordLabelUpdate.configure(background="#d9d9d9")
        NewPasswordLabelUpdate.configure(highlightbackground="#d9d9d9")
        NewPasswordLabelUpdate.configure(highlightcolor="black")
        NewPasswordLabelUpdate.configure(width=410)

        global NewPasswordTextUpdate
        NewPasswordTextUpdate = tk.Entry(NewPasswordLabelUpdate)
        NewPasswordTextUpdate.place(relx=0.10, rely=0.25,height=26, relwidth=0.8)
        NewPasswordTextUpdate.configure(background="white")
        NewPasswordTextUpdate.configure(disabledforeground="#a3a3a3")
        NewPasswordTextUpdate.configure(font=font16)
        NewPasswordTextUpdate.configure(foreground="#000000")
        NewPasswordTextUpdate.configure(highlightbackground="#d9d9d9")
        NewPasswordTextUpdate.configure(highlightcolor="black")
        NewPasswordTextUpdate.configure(insertbackground="black")
        NewPasswordTextUpdate.configure(selectbackground="#c4c4c4")
        NewPasswordTextUpdate.configure(selectforeground="black")
        NewPasswordTextUpdate.configure(show="*")
        NewPasswordTextUpdate.configure(justify="left")

        global checkbuttonUpdate
        checkbuttonUpdate = tk.Checkbutton(self)
        checkbuttonUpdate.place(relx=0.39, rely=0.55,height=26, relwidth=0.6)
        checkbuttonUpdate.configure(text="Hide password")
        checkbuttonUpdate.configure(activebackground="#d9d9d9")
        checkbuttonUpdate.configure(background="#d9d9d9")
        checkbuttonUpdate.configure(onvalue=True)
        checkbuttonUpdate.configure(offvalue=False)
        checkbuttonUpdate.configure(command=lambda widget="checkbuttonUpdate": clientGui_utility.toggle_password(checkbuttonUpdate, OldPasswordTextUpdate, NewPasswordTextUpdate))
        checkbuttonUpdate.var = tk.BooleanVar(value=True)
        checkbuttonUpdate['variable'] = checkbuttonUpdate.var

        UpdatePasswordButtonUpdate = tk.Button(self)
        UpdatePasswordButtonUpdate.place(relx=0.80, rely=0.19, height=42, width=123)
        UpdatePasswordButtonUpdate.configure(activebackground="#d9d9d9")
        UpdatePasswordButtonUpdate.configure(activeforeground="#000000")
        UpdatePasswordButtonUpdate.configure(background="#d9d9d9")
        UpdatePasswordButtonUpdate.configure(disabledforeground="#a3a3a3")
        UpdatePasswordButtonUpdate.configure(foreground="#000000")
        UpdatePasswordButtonUpdate.configure(highlightbackground="#d9d9d9")
        UpdatePasswordButtonUpdate.configure(highlightcolor="black")
        UpdatePasswordButtonUpdate.configure(pady="0")
        UpdatePasswordButtonUpdate.configure(text='''Update Password''')
        UpdatePasswordButtonUpdate.bind('<Button-1>', lambda e: clientGui_support.updatepassword(e, 
                WebsiteTextUpdate, OldPasswordTextUpdate, NewPasswordTextUpdate, ConsoleTextUpdate))

        LogoutButtonUpdate = tk.Button(self)
        LogoutButtonUpdate.place(relx=0.05, rely=0.68, height=42, width=123)
        LogoutButtonUpdate.configure(activebackground="#d9d9d9")
        LogoutButtonUpdate.configure(activeforeground="#000000")
        LogoutButtonUpdate.configure(background="#d9d9d9")
        LogoutButtonUpdate.configure(disabledforeground="#a3a3a3")
        LogoutButtonUpdate.configure(foreground="#000000")
        LogoutButtonUpdate.configure(highlightbackground="#d9d9d9")
        LogoutButtonUpdate.configure(highlightcolor="black")
        LogoutButtonUpdate.configure(pady="0")
        LogoutButtonUpdate.configure(text='''Logout''')
        LogoutButtonUpdate.configure(command=lambda: clientGui_support.clearFields(self, WebsiteTextUpdate, OldPasswordTextUpdate, NewPasswordTextUpdate))

        GetPasswordButtonUpdate = tk.Button(self)
        GetPasswordButtonUpdate.place(relx=0.30, rely=0.68, height=42, width=123)
        GetPasswordButtonUpdate.configure(activebackground="#d9d9d9")
        GetPasswordButtonUpdate.configure(activeforeground="#000000")
        GetPasswordButtonUpdate.configure(background="#d9d9d9")
        GetPasswordButtonUpdate.configure(disabledforeground="#a3a3a3")
        GetPasswordButtonUpdate.configure(foreground="#000000")
        GetPasswordButtonUpdate.configure(highlightbackground="#d9d9d9")
        GetPasswordButtonUpdate.configure(highlightcolor="black")
        GetPasswordButtonUpdate.configure(pady="0")
        GetPasswordButtonUpdate.configure(text='''Get Password''')
        GetPasswordButtonUpdate.bind('<Button-1>', lambda e: controller.show_frame(GetPasswordPage))
        
        AddPasswordButtonUpdate = tk.Button(self)
        AddPasswordButtonUpdate.place(relx=0.55, rely=0.68, height=42, width=123)
        AddPasswordButtonUpdate.configure(activebackground="#d9d9d9")
        AddPasswordButtonUpdate.configure(activeforeground="#000000")
        AddPasswordButtonUpdate.configure(background="#d9d9d9")
        AddPasswordButtonUpdate.configure(disabledforeground="#a3a3a3")
        AddPasswordButtonUpdate.configure(foreground="#000000")
        AddPasswordButtonUpdate.configure(highlightbackground="#d9d9d9")
        AddPasswordButtonUpdate.configure(highlightcolor="black")
        AddPasswordButtonUpdate.configure(pady="0")
        AddPasswordButtonUpdate.configure(text='''Add Password''')
        AddPasswordButtonUpdate.bind('<Button-1>', lambda e: controller.show_frame(AddPasswordPage))

        DeletePasswordButtonUpdate = tk.Button(self)
        DeletePasswordButtonUpdate.place(relx=0.8, rely=0.68, height=42, width=123)
        DeletePasswordButtonUpdate.configure(activebackground="#d9d9d9")
        DeletePasswordButtonUpdate.configure(activeforeground="#000000")
        DeletePasswordButtonUpdate.configure(background="#d9d9d9")
        DeletePasswordButtonUpdate.configure(disabledforeground="#a3a3a3")
        DeletePasswordButtonUpdate.configure(foreground="#000000")
        DeletePasswordButtonUpdate.configure(highlightbackground="#d9d9d9")
        DeletePasswordButtonUpdate.configure(highlightcolor="black")
        DeletePasswordButtonUpdate.configure(pady="0")
        DeletePasswordButtonUpdate.configure(text='''Delete Password''')
        DeletePasswordButtonUpdate.bind('<Button-1>', lambda e: controller.show_frame(DeletePasswordPage))

        global ConsoleTextUpdate
        ConsoleTextUpdate = tk.Entry(self)
        ConsoleTextUpdate.place(relx=0.3, rely=0.84,height=26, relwidth=0.62)
        ConsoleTextUpdate.configure(background="white")
        ConsoleTextUpdate.configure(disabledforeground="#000000")
        ConsoleTextUpdate.configure(font=font9)
        ConsoleTextUpdate.configure(foreground="#000000")
        ConsoleTextUpdate.configure(highlightbackground="#d9d9d9")
        ConsoleTextUpdate.configure(highlightcolor="black")
        ConsoleTextUpdate.configure(insertbackground="black")
        ConsoleTextUpdate.configure(selectbackground="#c4c4c4")
        ConsoleTextUpdate.configure(selectforeground="black")
        ConsoleTextUpdate.insert(0, "Insert the name of the website, the old password and the new password to update it.")
        ConsoleTextUpdate.configure(state='disabled')

        ConsoleLabelUpdate = tk.Label(self)
        ConsoleLabelUpdate.place(relx=0.08, rely=0.82, height=41, width=82)
        ConsoleLabelUpdate.configure(activebackground="#f9f9f9")
        ConsoleLabelUpdate.configure(activeforeground="black")
        ConsoleLabelUpdate.configure(background="#d9d9d9")
        ConsoleLabelUpdate.configure(disabledforeground="#a3a3a3")
        ConsoleLabelUpdate.configure(foreground="#000000")
        ConsoleLabelUpdate.configure(highlightbackground="#d9d9d9")
        ConsoleLabelUpdate.configure(highlightcolor="black")
        ConsoleLabelUpdate.configure(text='''Console''')

    def reset(self):
        ConsoleTextUpdate.configure(state='normal')
        ConsoleTextUpdate.delete(0 ,END)
        ConsoleTextUpdate.insert(0, "Insert the name of the website, the old password and the new password to update it.")
        ConsoleTextUpdate.configure(state='disabled')
        WebsiteTextUpdate.delete(0 ,END)
        WebsiteTextUpdate.insert(0, "")
        OldPasswordTextUpdate.delete(0 ,END)
        OldPasswordTextUpdate.insert(0, "")
        NewPasswordTextUpdate.delete(0 ,END)
        NewPasswordTextUpdate.insert(0, "")

    def goHome(self, c):
        c.show_frame(HomePage)
            
    def do_button(self):
        page = self.controller.get_page(UpdatePasswordPage)
        page.goHome(self.controller)
        page.reset()

        get = self.controller.get_page(GetPasswordPage)
        get.reset()
        dlt = self.controller.get_page(DeletePasswordPage)
        dlt.reset()
        add = self.controller.get_page(AddPasswordPage)
        add.reset()
        reg = self.controller.get_page(RegisterPage)
        reg.reset()
        home = self.controller.get_page(HomePage)
        home.reset()

        clientGui_utility.reset_toggle_password(checkbuttonUpdate, OldPasswordTextUpdate, NewPasswordTextUpdate)
        #checkbuttonUpdate.var.set(True)

class AddPasswordPage(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        tk.Frame.configure(self, bg=backgroundColor)

        self.controller = controller

        font16 = "-family {Courier New} -size 16 -weight normal -slant"  \
            " roman -underline 0 -overstrike 0"
        font9 = "-family {Segoe UI} -size 9 -weight normal -slant "  \
            "roman -underline 0 -overstrike 0"

        WebsiteLabelAdd = tk.LabelFrame(self)
        WebsiteLabelAdd.place(relx=0.08, rely=0.15, relheight=0.17, relwidth=0.68)
        WebsiteLabelAdd.configure(relief=GROOVE)
        WebsiteLabelAdd.configure(foreground="black")
        WebsiteLabelAdd.configure(text='''Website''')
        WebsiteLabelAdd.configure(background="#d9d9d9")
        WebsiteLabelAdd.configure(highlightbackground="#d9d9d9")
        WebsiteLabelAdd.configure(highlightcolor="black")
        WebsiteLabelAdd.configure(width=410)

        global WebsiteTextAdd
        WebsiteTextAdd = tk.Entry(WebsiteLabelAdd)
        WebsiteTextAdd.place(relx=0.37, rely=0.25,height=26, relwidth=0.6)
        WebsiteTextAdd.configure(background="white")
        WebsiteTextAdd.configure(disabledforeground="#a3a3a3")
        WebsiteTextAdd.configure(font=font16)
        WebsiteTextAdd.configure(foreground="#000000")
        WebsiteTextAdd.configure(highlightbackground="#d9d9d9")
        WebsiteTextAdd.configure(highlightcolor="black")
        WebsiteTextAdd.configure(insertbackground="black")
        WebsiteTextAdd.configure(selectbackground="#c4c4c4")
        WebsiteTextAdd.configure(selectforeground="black")

        PasswordLabelAdd = tk.LabelFrame(self)
        PasswordLabelAdd.place(relx=0.08, rely=0.37, relheight=0.17, relwidth=0.68)
        PasswordLabelAdd.configure(relief=GROOVE)
        PasswordLabelAdd.configure(foreground="black")
        PasswordLabelAdd.configure(text='''Password''')
        PasswordLabelAdd.configure(background="#d9d9d9")
        PasswordLabelAdd.configure(highlightbackground="#d9d9d9")
        PasswordLabelAdd.configure(highlightcolor="black")
        PasswordLabelAdd.configure(width=410)

        global PasswordTextAdd
        PasswordTextAdd = tk.Entry(PasswordLabelAdd)
        PasswordTextAdd.place(relx=0.37, rely=0.25,height=26, relwidth=0.6)
        PasswordTextAdd.configure(background="white")
        PasswordTextAdd.configure(disabledforeground="#a3a3a3")
        PasswordTextAdd.configure(font=font16)
        PasswordTextAdd.configure(foreground="#000000")
        PasswordTextAdd.configure(highlightbackground="#d9d9d9")
        PasswordTextAdd.configure(highlightcolor="black")
        PasswordTextAdd.configure(insertbackground="black")
        PasswordTextAdd.configure(selectbackground="#c4c4c4")
        PasswordTextAdd.configure(selectforeground="black")
        PasswordTextAdd.configure(show="*")
        PasswordTextAdd.configure(justify="left")

        global checkbuttonAdd
        checkbuttonAdd = tk.Checkbutton(self)
        checkbuttonAdd.place(relx=0.39, rely=0.55,height=26, relwidth=0.6)
        checkbuttonAdd.configure(text="Hide password")
        checkbuttonAdd.configure(background="#d9d9d9")
        checkbuttonAdd.configure(activebackground="#d9d9d9")
        checkbuttonAdd.configure(onvalue=True)
        checkbuttonAdd.configure(offvalue=False)
        checkbuttonAdd.configure(command=lambda widget="checkbuttonAdd": clientGui_utility.toggle_password(checkbuttonAdd, PasswordTextAdd))
        checkbuttonAdd.var = tk.BooleanVar(value=True)
        checkbuttonAdd['variable'] = checkbuttonAdd.var

        global PasswordButtonAdd
        PasswordButtonAdd = tk.Button(self)
        PasswordButtonAdd.place(relx=0.80, rely=0.19, height=42, width=123)
        PasswordButtonAdd.configure(activebackground="#d9d9d9")
        PasswordButtonAdd.configure(activeforeground="#000000")
        PasswordButtonAdd.configure(background="#d9d9d9")
        PasswordButtonAdd.configure(disabledforeground="#a3a3a3")
        PasswordButtonAdd.configure(foreground="#000000")
        PasswordButtonAdd.configure(highlightbackground="#d9d9d9")
        PasswordButtonAdd.configure(highlightcolor="black")
        PasswordButtonAdd.configure(pady="0")
        PasswordButtonAdd.configure(text='''Add Password''')
        PasswordButtonAdd.bind('<Button-1>', lambda e: clientGui_support.addpassword(e,
                WebsiteTextAdd, PasswordTextAdd, ConsoleTextAdd))

        LogoutButtonAdd = tk.Button(self)
        LogoutButtonAdd.place(relx=0.05, rely=0.68, height=42, width=123)
        LogoutButtonAdd.configure(activebackground="#d9d9d9")
        LogoutButtonAdd.configure(activeforeground="#000000")
        LogoutButtonAdd.configure(background="#d9d9d9")
        LogoutButtonAdd.configure(disabledforeground="#a3a3a3")
        LogoutButtonAdd.configure(foreground="#000000")
        LogoutButtonAdd.configure(highlightbackground="#d9d9d9")
        LogoutButtonAdd.configure(highlightcolor="black")
        LogoutButtonAdd.configure(pady="0")
        LogoutButtonAdd.configure(text='''Logout''')
        LogoutButtonAdd.configure(command=lambda: clientGui_support.clearFields(self, WebsiteTextAdd, PasswordTextAdd))

        GetPasswordButtonAdd = tk.Button(self)
        GetPasswordButtonAdd.place(relx=0.30, rely=0.68, height=42, width=123)
        GetPasswordButtonAdd.configure(activebackground="#d9d9d9")
        GetPasswordButtonAdd.configure(activeforeground="#000000")
        GetPasswordButtonAdd.configure(background="#d9d9d9")
        GetPasswordButtonAdd.configure(disabledforeground="#a3a3a3")
        GetPasswordButtonAdd.configure(foreground="#000000")
        GetPasswordButtonAdd.configure(highlightbackground="#d9d9d9")
        GetPasswordButtonAdd.configure(highlightcolor="black")
        GetPasswordButtonAdd.configure(pady="0")
        GetPasswordButtonAdd.configure(text='''Get Password''')
        GetPasswordButtonAdd.bind('<Button-1>', lambda e: controller.show_frame(GetPasswordPage))

        DeletePasswordButtonAdd = tk.Button(self)
        DeletePasswordButtonAdd.place(relx=0.55, rely=0.68, height=42, width=123)
        DeletePasswordButtonAdd.configure(activebackground="#d9d9d9")
        DeletePasswordButtonAdd.configure(activeforeground="#000000")
        DeletePasswordButtonAdd.configure(background="#d9d9d9")
        DeletePasswordButtonAdd.configure(disabledforeground="#a3a3a3")
        DeletePasswordButtonAdd.configure(foreground="#000000")
        DeletePasswordButtonAdd.configure(highlightbackground="#d9d9d9")
        DeletePasswordButtonAdd.configure(highlightcolor="black")
        DeletePasswordButtonAdd.configure(pady="0")
        DeletePasswordButtonAdd.configure(text='''Delete Password''')
        DeletePasswordButtonAdd.bind('<Button-1>', lambda e: controller.show_frame(DeletePasswordPage))

        UpdatePasswordButtonAdd = tk.Button(self)
        UpdatePasswordButtonAdd.place(relx=0.8, rely=0.68, height=42, width=123)
        UpdatePasswordButtonAdd.configure(activebackground="#d9d9d9")
        UpdatePasswordButtonAdd.configure(activeforeground="#000000")
        UpdatePasswordButtonAdd.configure(background="#d9d9d9")
        UpdatePasswordButtonAdd.configure(disabledforeground="#a3a3a3")
        UpdatePasswordButtonAdd.configure(foreground="#000000")
        UpdatePasswordButtonAdd.configure(highlightbackground="#d9d9d9")
        UpdatePasswordButtonAdd.configure(highlightcolor="black")
        UpdatePasswordButtonAdd.configure(pady="0")
        UpdatePasswordButtonAdd.configure(text='''Update Password''')
        UpdatePasswordButtonAdd.bind('<Button-1>', lambda e: controller.show_frame(UpdatePasswordPage))

        global ConsoleTextAdd
        ConsoleTextAdd = tk.Entry(self)
        ConsoleTextAdd.place(relx=0.3, rely=0.84,height=26, relwidth=0.62)
        ConsoleTextAdd.configure(background="white")
        ConsoleTextAdd.configure(disabledforeground="#000000")
        ConsoleTextAdd.configure(font=font9)
        ConsoleTextAdd.configure(foreground="#000000")
        ConsoleTextAdd.configure(highlightbackground="#d9d9d9")
        ConsoleTextAdd.configure(highlightcolor="black")
        ConsoleTextAdd.configure(insertbackground="black")
        ConsoleTextAdd.configure(selectbackground="#c4c4c4")
        ConsoleTextAdd.configure(selectforeground="black")
        ConsoleTextAdd.insert(0, "Insert the name of the website and its password to add it.")
        ConsoleTextAdd.configure(state='disabled')

        ConsoleLabelAdd = tk.Label(self)
        ConsoleLabelAdd.place(relx=0.08, rely=0.82, height=41, width=82)
        ConsoleLabelAdd.configure(activebackground="#f9f9f9")
        ConsoleLabelAdd.configure(activeforeground="black")
        ConsoleLabelAdd.configure(background="#d9d9d9")
        ConsoleLabelAdd.configure(disabledforeground="#a3a3a3")
        ConsoleLabelAdd.configure(foreground="#000000")
        ConsoleLabelAdd.configure(highlightbackground="#d9d9d9")
        ConsoleLabelAdd.configure(highlightcolor="black")
        ConsoleLabelAdd.configure(text='''Console''')
    
    def reset(self):
        ConsoleTextAdd.configure(state='normal')
        ConsoleTextAdd.delete(0 ,END)
        ConsoleTextAdd.insert(0, "Insert the name of the website and its password to add it.")
        ConsoleTextAdd.configure(state='disabled')
        WebsiteTextAdd.delete(0 ,END)
        WebsiteTextAdd.insert(0, "")
        PasswordTextAdd.delete(0 ,END)
        PasswordTextAdd.insert(0, "")

    def goHome(self, c):
        c.show_frame(HomePage)
            
    def do_button(self):
        page = self.controller.get_page(AddPasswordPage)
        page.goHome(self.controller)
        page.reset()

        upd = self.controller.get_page(UpdatePasswordPage)
        upd.reset()
        dlt = self.controller.get_page(DeletePasswordPage)
        dlt.reset()
        get = self.controller.get_page(GetPasswordPage)
        get.reset()
        reg = self.controller.get_page(RegisterPage)
        reg.reset()
        home = self.controller.get_page(HomePage)
        home.reset()
        
        clientGui_utility.reset_toggle_password(checkbuttonAdd, PasswordTextAdd)
        #checkbuttonAdd.var.set(True)


if __name__ == '__main__':
    
    app = Client()
    app.geometry("750x450+300+120")
    app.title("Remote Password Manager")
    # app.configure(background="#a9b6f8")
    # app.configure(highlightbackground="#d9d9d9")
    # app.configure(highlightcolor="black")
    # app.resizable(width='FALSE', height='FALSE')
    app.mainloop()
