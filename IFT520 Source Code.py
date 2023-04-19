from datetime import date
from operator import ne
import tkinter as tk
from getpass import getpass
from tkinter.tix import IMAGETEXT
from mysql.connector import connect, Error
from tkinter import *
from tkinter import ttk
import psycopg2
import os
import rsa
from datetime import date
from datetime import datetime
import pickle
from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64decode
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from binascii import hexlify
from Crypto.Util.Padding import pad, unpad
import hashlib
from Crypto.Hash import SHA256
from binascii import unhexlify
import base64
from base64 import urlsafe_b64encode
import hashlib
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from base64 import urlsafe_b64encode, urlsafe_b64decode
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from email.message import EmailMessage
from tkinter import messagebox
from cryptography.hazmat.primitives import padding
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from binascii import hexlify, unhexlify
import random
import tkinter as tk
from tkinter import ttk, Label, Scrollbar, VERTICAL, W, E, NO
from tkinter import messagebox

today = date.today()

DATABASE_URL = "postgresql://default:LDsRLnPMUBGGypgc3nZncA@ift520-9628.7tt.cockroachlabs.cloud:26257/asymmetric?sslmode=verify-full"

conn = psycopg2.connect(DATABASE_URL)

class main:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Secure Email")
        self.root.geometry('300x300')
        self.root.resizable(width=False, height=False)
        self.root['background']='#8C1D40'
        self.root.attributes('-alpha',0.97)
        self.main()

    def main(self):
        usr_login = tk.Label(self.root, text="Username", bg='#8C1D40', font=("Arial", 10))
        usr_login.grid(row=0, column=0)
        self.usernameText = tk.Entry(self.root, bg='#FFC627')
        self.usernameText.grid(row=0, column=1, pady=20, padx=10, sticky=E) 

        pwd_login = tk.Label(self.root, text="Password", bg='#8C1D40', font=("Arial", 10))
        pwd_login.grid(row=1, column=0)
        self.passwordText = tk.Entry(self.root, show='*', bg='#FFC627')  
        self.passwordText.grid(row=1, column=1) 

        #remember me check box saves the login credentials for next time
        usr_pwd_button = tk.Label(self.root, text="Remember me.", bg='#8C1D40', activebackground='#8C1D40', font=("Arial", 10))
        usr_pwd_button.grid(row=2, column=1)
        rembr = tk.Checkbutton(self.root, bg='#8C1D40', font=("Arial", 10), activebackground='#8C1D40')
        rembr.grid(row=2, column=2)
        usr_logn_button = tk.Button(self.root, text="Login", command=self.login, bg='#FFC627', activebackground='#8C1D40', highlightbackground = "black", highlightthickness = 5, font=("Arial", 10), bd=3, relief="solid")
        usr_logn_button.grid(row=3, column=1)

        #signup button
        lable = tk.Label(self.root, text="Not registered ?", bg='#8C1D40', font=("Arial", 10))
        lable.grid(row=4, column=1)
        rememberMe = tk.StringVar()
        signupButton = tk.Button(self.root,  text="Sign up.", command=self.signup, bg='#FFC627', activebackground='#8C1D40', highlightbackground = "black", highlightthickness = 5, font=("Arial", 10), bd=3, relief="solid")
        signupButton.grid(row=4, column=2)

        self.root.mainloop()
    def to_hex(string):
        return ''.join([hex(ord(c))[2:].zfill(2) for c in string])
    def check_password(self, username, password):
        query = "SELECT privatekeys, publickeys FROM keys WHERE username = %s"
        passwordquery = "SELECT password FROM login WHERE username = %s"
        with conn.cursor() as cur:
            cur.execute(query, (username,))
            row = cur.fetchone()
            cur.close()
        with conn.cursor() as cur:
            cur.execute(passwordquery, (username,))
            row2 = cur.fetchone()
            cur.close()
        if row is None:
            return False
        if row2 is None:
            return False
        private_key_bytes = row[0]
        password_bytes = bytes(row2[0], 'utf-8')

        if private_key_bytes:
            private_key = RSA.import_key(private_key_bytes)
            cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
            encrypted_password_bytes = unhexlify(password_bytes)
            decrypted_password_bytes = cipher.decrypt(encrypted_password_bytes)

            unpadder = padding.PKCS7(128).unpadder()
            decrypted_padded_password = unpadder.update(decrypted_password_bytes) + unpadder.finalize()

            decrypted_password = decrypted_padded_password.decode('utf-8')
            return decrypted_password == password
        else:
            return False

    def login(self):
        a = self.usernameText.get()
        b = self.passwordText.get()
        decrypted_password = main.check_password(self, a, b)
        print(decrypted_password)

        usrCheck = 0
        passCheck = 0
        with conn.cursor() as cur:
            #cur.execute("CREATE TABLE IF NOT EXISTS login (username STRING PRIMARY KEY, password STRING)")
            #cur.execute("INSERT INTO login (username, password) VALUES (1234234, 123456789)")
            cur.execute("SELECT username FROM login")
            username = cur.fetchall()
            cur.close()
        conn.commit()
        for x in username:
            if x[0] == a:
                usrCheck = 1
        if decrypted_password == True:
            passCheck = 1
        if usrCheck == 1 & passCheck == 1:
            global usernamexd
            usernamexd = a
            self.root.destroy()
            application()
        else:
            pass
    def signup(self):
        self.root.destroy()
        signup()

class signup:
    def __init__(self):
        self.app = tk.Tk()
        self.app.title("Sign Up")
        self.app.geometry('400x400')
        self.app.resizable(width=False, height=False)
        self.app['background']='#8C1D40'
        self.app.attributes('-alpha',0.97)
        self.main()
    def main(self):
        
        usernamex = Label(self.app, text ='username: ', bg='#8C1D40', font=("Arial", 10))
        usernamex.grid(row=0,column=0, pady=20, sticky=E)
        self.username = Entry(self.app, width=23, bg='#FFC627')
        self.username.grid(row=0, column=1,pady=20, sticky=E)

        password = Label(self.app, text ='password: ', bg='#8C1D40', font=("Arial", 10))
        password.grid(row=1,column=0, pady=20, sticky=E)
        self.password = Entry(self.app, width=23, bg='#FFC627')
        self.password.grid(row=1, column=1,pady=20, sticky=E)

        reenterp = Label(self.app, text ='re-enter password: ', bg='#8C1D40', font=("Arial", 10))
        reenterp.grid(row=2,column=0, padx=10, pady=20, sticky=E)
        self.password = Entry(self.app, width=23, bg='#FFC627')
        self.password.grid(row=2, column=1,pady=20, sticky=E)

        email = Label(self.app, text ='Email: ', bg='#8C1D40', font=("Arial", 10))
        email.grid(row=3,column=0, pady=20, sticky=E)
        self.email = Entry(self.app, width=23, bg='#FFC627')
        self.email.grid(row=3, column=1,pady=20, sticky=E)

        SignUp = tk.Button(self.app, text="Sign-Up", height=1, width=20, fg="black", highlightbackground = "black", highlightthickness = 5, font=("Arial", 10), 
        bg='#FFC627', bd=3, relief="solid", activebackground='#8C1D40', command=self.makekey)
        SignUp.grid(row=4, column=1, padx=0, pady=20, sticky=tk.NS) 
        
        Cancel = tk.Button(self.app, text="Cancel", height=1, width=20, fg="black", highlightbackground = "black", highlightthickness = 5, font=("Arial", 10), 
        bg='#FFC627', bd=3, relief="solid", activebackground='#8C1D40', command=self.Cancel)
        Cancel.grid(row=5, column=1, padx=0, pady=0, sticky=tk.NS) 
    
    def Cancel(self):
        self.app.destroy()
        main()
        
    def makekey(self):
        # CREATE PUBLIC AND PRIVATE KEY
        username = self.username.get()
        password = self.password.get()
        email = self.email.get()

        # Generate RSA key pair
        key = RSA.generate(4096)

        # Get public and private keys
        public_key = key.publickey()
        private_key = key

        store_private_key = private_key.export_key()
        store_public_key = public_key.export_key()

        # Encrypt message using OAEP
        cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
        
        # Use PKCS7 padding with a fixed block size of 128 bits (16 bytes)
        padder = padding.PKCS7(128).padder()
        padded_password = padder.update(password.encode()) + padder.finalize()

        encrypted_password_bytes = cipher.encrypt(padded_password)
        
        encrypted_password = hexlify(encrypted_password_bytes).decode('utf-8')

        # Store keys and encrypted password in the database
        time = today.strftime("%m/%d/%y")
        with conn.cursor() as cur:
            cur.execute("CREATE TABLE IF NOT EXISTS login (username STRING PRIMARY KEY NOT NULL, password TEXT NOT NULL, email STRING NOT NULL, accountCreationDate DATE NOT NULL)")
            cur.execute("CREATE TABLE IF NOT EXISTS keys (username STRING PRIMARY KEY NOT NULL, email STRING NOT NULL, privatekeys BYTEA NOT NULL, publickeys BYTEA NOT NULL)")
            cur.execute("CREATE TABLE IF NOT EXISTS usersession (username STRING PRIMARY KEY NOT NULL, status STRING NOT NULL)")

            cur.execute('INSERT INTO login VALUES(%s, %s, %s, %s)', (username, encrypted_password, email, time))
            cur.execute('INSERT INTO keys VALUES(%s, %s, %s, %s)', (username, email, store_private_key, store_public_key))
            cur.execute('INSERT INTO userSession VALUES(%s, %s)', (username, time))
            cur.close()
            conn.commit()

        self.app.destroy()
        main()
        
class application:
    def __init__(self):
        self.app = tk.Tk()
        self.app.title("Secure Email")
        self.app.geometry('960x900')
        self.app.resizable(width=False, height=False)
        self.app['background']='#8C1D40'
        self.app.attributes('-alpha',0.97)
        bg_frame = tk.Frame(self.app, bg="#8C1D40")
        bg_frame.place(relx=0.14, rely=0.35, width=720, height=540)
        style = ttk.Style()
        style.configure("Custom.Treeview", rowheight=25)
        style.configure("Custom.Treeview.Heading", background="#8C1D40", foreground="#FFC627", relief="flat")  # Style the headings
        style.map("Custom.Treeview.Heading", background=[('active', '#FFC627')])  # Style the active heading

        # Set field background and row colors
        style.configure("Custom.Treeview", fieldbackground="#8C1D40", background=["#8C1D40", "#FFC627"])

        self.main()
    def main(self):
    
        refresh = tk.Button(self.app, text="Refresh", height=4, width=12, font=("Arial", 12), relief="solid", activebackground='#8C1D40', command=self.Refresh, 
                            bg='#FFC627', highlightbackground = "black", highlightthickness = 5, bd=3)
        refresh.grid(row=1, column=0, padx=10, pady=5, sticky=tk.NW)
        
        ReGenerateKeyPair = tk.Button(self.app, text="Regenerate Key Pair", height=4, width=12, font=("Arial", 12), relief="solid", activebackground='#8C1D40', command=self.ReGenKeys, 
                            bg='#FFC627', highlightbackground = "black", highlightthickness = 5, bd=3, wraplength=100)
        ReGenerateKeyPair.grid(row=1, column=0, padx=10, pady=5, sticky=tk.SW)
        
        welcomeLabel = Label(self.app, text ='Welcome to the IFT 520 Secure Email Application', relief="solid", font=("Arial", 20), 
                            bg='#FFC627', highlightbackground = "black", highlightthickness = 1, bd=3)
        welcomeLabel.grid(row=1,column=1, pady=60, sticky=E)
        compose = tk.Button(self.app, text="Compose", height=4, width=12, font=("Arial", 12), relief="solid", activebackground='#8C1D40', command=self.compose, 
                            bg='#FFC627', highlightbackground = "black", highlightthickness = 5, bd=3)
        compose.grid(row=1, column=1, padx=60, pady=5, sticky=tk.S)

        trash = tk.Button(self.app, text="Trash", height=15, width=12, font=("Arial", 12), relief="solid", activebackground='#8C1D40', command=self.trash, 
                            bg='#FFC627', highlightbackground = "black", highlightthickness = 5, bd=3)
        trash.grid(row=1, column=2, padx=60, pady=5, sticky=tk.SW)
        logout = tk.Button(self.app, text="Logout", height=4, width=12, font=("Arial", 12), relief="solid", activebackground='#8C1D40', command=self.logout, 
                            bg='#FFC627', highlightbackground = "black", highlightthickness = 5, bd=3)
        logout.grid(row=1, column=1, padx=10, pady=5, sticky=tk.N)
        
        
        
        style = ttk.Style()
        style.configure("Custom.Treeview", rowheight=25)
        style.configure("Custom.Treeview.Heading", background="#FFC627", foreground="#FFC627", relief="flat")  # Style the headings
        style.map("Custom.Treeview.Heading", background=[('active', '#FFC627')])  # Style the active heading

        # Set field background and row colors
        style.configure("Custom.Treeview", fieldbackground="#8C1D40", background="#8C1D40")
        style.configure("Custom.Treeview.Item", fieldbackground="#8C1D40", background=["#8C1D40", "#FFC627"])


        self.tree = ttk.Treeview(self.app, style="Custom.Treeview")
        self.tree.place(relx=0.14, rely=0.35, width=720, height=540)
        self.scrollbary = Scrollbar(orient=VERTICAL)
        self.scrollbary.place(relx=0.89, rely=0.3509, width=22, height=538)

        # Rest of the treeview configuration code...

        self.tree.configure(yscrollcommand=self.scrollbary.set)
        self.scrollbary.config(command=self.tree.yview)
        
        self.tree.configure(columns=("Sender", "Message Content"))

        self.tree.heading("Sender", text="Sender", anchor=W)
        self.tree.heading("Message Content", text="Message Content", anchor=W)


        self.tree.column("#0", stretch=NO, minwidth=0, width=0)
        self.tree.column("#1", stretch=NO, minwidth=0, width=190)
        
        self.tree.bind("<Double-1>", self.show_email_content)

        with conn.cursor() as cur:
            #cur.execute("DROP TABLE email")
            cur.execute('CREATE TABLE IF NOT EXISTS email (messageid STRING PRIMARY KEY NOT NULL, username STRING NOT NULL, sender STRING NOT NULL, recipient STRING NOT NULL, cc STRING NOT NULL, bcc STRING NOT NULL, subject TEXT NOT NULL, message TEXT NOT NULL, date STRING NOT NULL)')
            cur.execute("SELECT email FROM login WHERE username = %s", (usernamexd,))
            row = cur.fetchall()
            cur.execute("SELECT * FROM email WHERE recipient = %s", (row[0],))
            x = cur.fetchall()
            for dt in x:
                self.tree.insert("", 'end', iid=dt[0], text=dt[0], values =(dt[1],dt[6]))
            conn.commit()
            cur.close()
        conn.commit()

        self.app.mainloop()
        
    def ReGenKeys(self):
        
        with conn.cursor() as cur:
            cur.execute("SELECT email FROM login WHERE username = %s", (usernamexd,))
            row = cur.fetchall()
            cur.execute("SELECT messageid FROM email WHERE recipient = %s", (row[0],))
            row = cur.fetchall()
            cur.close()
            conn.commit()
        if row is None or str(row) == "" or str(row) == "[]":
            
            query = "SELECT privatekeys, publickeys FROM keys WHERE username = %s"
            passwordquery = "SELECT password FROM login WHERE username = %s"
            with conn.cursor() as cur:
                cur.execute(query, (usernamexd,))
                row = cur.fetchone()
                cur.close()
            with conn.cursor() as cur:
                cur.execute(passwordquery, (usernamexd,))
                row2 = cur.fetchone()
                cur.close()
            if row is None:
                return False
            if row2 is None:
                return False
            private_key_bytes = row[0]
            password_bytes = bytes(row2[0], 'utf-8')
            private_key = RSA.import_key(private_key_bytes)
            cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
            encrypted_password_bytes = unhexlify(password_bytes)
            decrypted_password_bytes = cipher.decrypt(encrypted_password_bytes)

            unpadder = padding.PKCS7(128).unpadder()
            decrypted_padded_password = unpadder.update(decrypted_password_bytes) + unpadder.finalize()
            decrypted_password = decrypted_padded_password.decode('utf-8')
            
            # Generate RSA key pair
            key = RSA.generate(4096)

            # Get public and private keys
            public_key = key.publickey()
            private_key = key

            store_private_key = private_key.export_key()
            store_public_key = public_key.export_key()

            # Encrypt message using OAEP
            cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
            
            # Use PKCS7 padding with a fixed block size of 128 bits (16 bytes)
            padder = padding.PKCS7(128).padder()
            padded_password = padder.update(decrypted_password.encode()) + padder.finalize()

            encrypted_password_bytes = cipher.encrypt(padded_password)
            
            encrypted_password = hexlify(encrypted_password_bytes).decode('utf-8')
            

            # Store keys and encrypted password in the database
            time = today.strftime("%m/%d/%y")
            with conn.cursor() as cur:
                cur.execute("SELECT email FROM login WHERE username = %s", (usernamexd,))
                row = cur.fetchall()
                #cur.execute("CREATE TABLE IF NOT EXISTS login (username STRING PRIMARY KEY NOT NULL, password TEXT NOT NULL, email STRING NOT NULL, accountCreationDate DATE NOT NULL)")
                #cur.execute("CREATE TABLE IF NOT EXISTS keys (username STRING PRIMARY KEY NOT NULL, email STRING NOT NULL, privatekeys BYTEA NOT NULL, publickeys BYTEA NOT NULL)")
                cur.execute('DELETE FROM login WHERE username=%s', (usernamexd,))
                cur.execute('INSERT INTO login VALUES(%s, %s, %s, %s)', (usernamexd, encrypted_password, row[0], time))
                cur.execute('DELETE FROM keys WHERE username=%s', (usernamexd,))
                cur.execute('INSERT INTO keys VALUES(%s, %s, %s, %s)', (usernamexd, row[0], store_private_key, store_public_key))
                cur.close()
                conn.commit()
            messagebox.showinfo("Success", "Generated RSA New Key Pair")
        else:
            messagebox.showwarning("Warning", "Please Delete Entire Mailbox Before Generating A New Key Pair")

    def show_email_content(self, event):
        selected_item = self.tree.selection()
        if selected_item:
            # Retrieve email data from the database using selected_item as the messageid
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM email WHERE messageid = %s", (selected_item,))
                email_data = cur.fetchone()
                conn.commit()
                cur.close()

            # Create the email content window
            email_content_window = EmailContentWindow(self.app, email_data)

    def trash(self):
        selected_item = self.tree.selection()
        if selected_item:
            # Delete the email from the treeview
            self.tree.delete(selected_item)

            # Delete the email from the database
            with conn.cursor() as cur:
                cur.execute("DELETE FROM email WHERE messageid = %s", (selected_item,))
                conn.commit()
                cur.close()

            # Show a message to the user
            messagebox.showinfo("Success", "Email deleted successfully")
        else:
            messagebox.showwarning("Warning", "Please select an email to delete")

    def logout(self):
        self.app.destroy()
        main()
    def Refresh(self):
        # Clear existing items in the treeview
        for item in self.tree.get_children():
            self.tree.delete(item)

        with conn.cursor() as cur:
            #cur.execute("DROP TABLE email")
            #cur.execute('CREATE TABLE IF NOT EXISTS email (messageid STRING PRIMARY KEY NOT NULL, username STRING NOT NULL, sender STRING NOT NULL, recipient STRING NOT NULL, cc STRING NOT NULL, bcc STRING NOT NULL, subject TEXT NOT NULL, message TEXT NOT NULL, date STRING NOT NULL)')
            cur.execute("SELECT email FROM login WHERE username = %s", (usernamexd,))
            row = cur.fetchall()
            cur.execute("SELECT * FROM email WHERE recipient = %s", (row[0],))
            x = cur.fetchall()
            for dt in x:
                self.tree.insert("", 'end', iid=dt[0], text=dt[0], values =(dt[1],dt[6]))
            conn.commit()
            cur.close()
        conn.commit()


    def compose(self):
        ComposeEmailGUI()

        # When doubleclicking a line in the tree from applicaiton(), this will open a new gui that displays 
        # all of the contents of the email in a nicely formatted gui. Base the newly created object for tkinter with the code below
class EmailContentWindow:
    def __init__(self, app, email_data):
        self.app = app
        self.email_data = email_data
        self.create_email_content_window()

    def create_email_content_window(self):
        self.email_window = Toplevel(self.app)
        self.email_window.title("Email Content")
        self.email_window.geometry("800x600")
        self.email_window['background'] = '#8C1D40'
        
        fromemail = self.email_data[3]
        subjecttt = self.email_data[6]
        body = self.email_data[7]

        message = decrypt_email_body(subjecttt, fromemail)
        subject = decrypt_email_body(body, fromemail)
        
        sender_label = tk.Label(self.email_window, text=f"Sender: {self.email_data[2]}", bg='#8C1D40', font=("Arial", 12))
        sender_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")

        recipient_label = tk.Label(self.email_window, text=f"Recipient: {self.email_data[3]}", bg='#8C1D40', font=("Arial", 12))
        recipient_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")

        subject_label = tk.Label(self.email_window, text=f"Subject: {subject}", bg='#8C1D40', font=("Arial", 12))
        subject_label.grid(row=2, column=0, padx=10, pady=10, sticky="w")

        message_label = tk.Label(self.email_window, text=f"Message: {message}", bg='#8C1D40', font=("Arial", 12), wraplength=750, justify='left')
        message_label.grid(row=3, column=0, padx=10, pady=10, sticky="w")


class ComposeEmailGUI:
    def __init__(self):
        self.app = tk.Tk()
        self.app.title("Compose Email")
        self.app.geometry('600x700')
        self.app.resizable(width=False, height=False)
        self.app['background']='#8C1D40'
        self.app.attributes('-alpha',0.97)
        self.main()

    def main(self):
        # From label and entry
        
        query = "SELECT email FROM login WHERE username = %s"
        with conn.cursor() as cur:
            cur.execute(query, (usernamexd,))
            row0 = cur.fetchone()
            cur.close()
        
        from_label = tk.Label(self.app, text='From:', font=("Arial", 12), bg='#8C1D40', fg='#FFC627')
        from_label.grid(row=0, column=0, pady=10, padx=20, sticky=tk.W)
        self.from_entry = tk.Entry(self.app, width=50, font=("Arial", 12), bg='#FFC627')
        self.from_entry.grid(row=0, column=1, pady=10, padx=10)
        self.from_entry.insert(0, row0[0])

        # To label and entry
        to_label = tk.Label(self.app, text='To:', font=("Arial", 12), bg='#8C1D40', fg='#FFC627')
        to_label.grid(row=1, column=0, pady=10, padx=20, sticky=tk.W)
        self.to_entry = tk.Entry(self.app, width=50, font=("Arial", 12), bg='#FFC627')
        self.to_entry.grid(row=1, column=1, pady=10, padx=10)

        # CC label and entry
        cc_label = tk.Label(self.app, text='CC:', font=("Arial", 12), bg='#8C1D40', fg='#FFC627')
        cc_label.grid(row=2, column=0, pady=10, padx=20, sticky=tk.W)
        self.cc_entry = tk.Entry(self.app, width=50, font=("Arial", 12), bg='#FFC627')
        self.cc_entry.grid(row=2, column=1, pady=10, padx=10)

        # BCC label and entry
        bcc_label = tk.Label(self.app, text='BCC:', font=("Arial", 12), bg='#8C1D40', fg='#FFC627')
        bcc_label.grid(row=3, column=0, pady=10, padx=20, sticky=tk.W)
        self.bcc_entry = tk.Entry(self.app, width=50, font=("Arial", 12), bg='#FFC627')
        self.bcc_entry.grid(row=3, column=1, pady=10, padx=10)

        # Subject label and entry
        subject_label = tk.Label(self.app, text='Subject:', font=("Arial", 12), bg='#8C1D40', fg='#FFC627')
        subject_label.grid(row=4, column=0, pady=10, padx=20, sticky=tk.W)
        self.subject_entry = tk.Entry(self.app, width=50, font=("Arial", 12), bg='#FFC627')
        self.subject_entry.grid(row=4, column=1, pady=10, padx=10)

        # Body label and text area
        body_label = tk.Label(self.app, text='Body:', font=("Arial", 12), bg='#8C1D40', fg='#FFC627')
        body_label.grid(row=5, column=0, pady=10, padx=20, sticky=tk.W)
        self.body_text = tk.Text(self.app, height=10, width=50, font=("Arial", 12), bg='#FFC627')
        self.body_text.grid(row=5, column=1, pady=10, padx=10)

        # Send button
        send_button = tk.Button(self.app, text="Send", height=2, width=10, bg='#FFC627', font=("Arial", 12), command=self.send_email)
        send_button.grid(row=6, column=1, pady=20, padx=10, sticky=tk.E)

        # Quit button
        quit_button = tk.Button(self.app, text="Quit", height=2, width=10, bg='#FFC627', font=("Arial", 12), command=self.quit)
        quit_button.grid(row=7, column=1, pady=20, padx=10, sticky=tk.E)
    def send_email(self):
        now = datetime.now()
        """Function to send the composed email"""
        fromx = self.from_entry.get()
        toemail = self.to_entry.get()
        cc = self.cc_entry.get()
        bcc = self.bcc_entry.get()
        subject = self.subject_entry.get()
        body = self.body_text.get("1.0", tk.END).strip()  # Get the content of the text widget and remove extra whitespace
        currentime = now.strftime("%d/%m/%Y %H:%M:%S")
        
        query = "SELECT email FROM login WHERE email = %s"
        with conn.cursor() as cur:
            cur.execute(query, (toemail,))
            row0 = cur.fetchone()
            cur.close()
        query = "SELECT email FROM login WHERE username = %s"
        with conn.cursor() as cur:
            cur.execute(query, (usernamexd,))
            awa = cur.fetchone()
            cur.close()    
        if row0 is None or str(row0[0]) == "":
            messagebox.showwarning("Warning", f"{toemail} Does Not Exist")
        if self.from_entry.get() != awa[0]:
            messagebox.showwarning("Warning", "Email does not match Your Email")
        else:
            encrypted_email = encrypt_email_body(body, toemail)
            encrypted_subject = encrypt_email_body(subject, toemail)
            
            messageid = random.randint(1,20000000000000)
            
            with conn.cursor() as cur:
                cur.execute('INSERT INTO email (messageid, username, sender, recipient, cc, bcc, subject, message, date) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)', (messageid, usernamexd, fromx, toemail, cc, bcc, encrypted_email, encrypted_subject, currentime))
                conn.commit()
                cur.close()
            messagebox.showinfo("Success", "Email sent successfully")

    def quit(self):
        self.app.destroy()
        pass

def get_keys(toemail):
    query = "SELECT privatekeys, publickeys FROM keys WHERE email = %s"
    with conn.cursor() as cur:
        cur.execute(query, (toemail,))
        row = cur.fetchone()
        cur.close()
    if not row:
        return None, None
    
    private_key_bytes = row[0]
    public_key_bytes = row[1]

    private_key = RSA.import_key(private_key_bytes) if private_key_bytes else None
    public_key = RSA.import_key(public_key_bytes) if public_key_bytes else None

    return private_key, public_key

def encrypt_email_body(body, toemail):
    _, public_key = get_keys(toemail)  # Extract the public key from the tuple
    if not public_key:
        print(f"No public key found for {toemail}")
        return None

    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    padder = padding.PKCS7(128).padder()
    padded_body = padder.update(body.encode()) + padder.finalize()
    encrypted_body = cipher.encrypt(padded_body)
    return hexlify(encrypted_body).decode('utf-8')

def decrypt_email_body(encrypted_body, from_email):
    privatekey, _ = get_keys(from_email)
    cipher = PKCS1_OAEP.new(privatekey, hashAlgo=SHA256)
    encrypted_body_bytes = unhexlify(encrypted_body.encode())
    decrypted_body_bytes = cipher.decrypt(encrypted_body_bytes)

    unpadder = padding.PKCS7(128).unpadder()
    decrypted_body = unpadder.update(decrypted_body_bytes) + unpadder.finalize()
    return decrypted_body.decode('utf-8')

main()
conn.close() 
