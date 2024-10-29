import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
from message import Message
from crypto_utils import CryptoUtils
import base64

class ChatClient:
    def __init__(self, host='localhost', port=1234):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((host, port))
        
        # Generate key pair for digital signatures
        self.private_key, self.public_key = CryptoUtils.generate_key_pair()
        
        # Setup login window
        self.setup_login_window()

    def setup_login_window(self):
        self.login_window = tk.Tk()
        self.login_window.title("Secure Chat - Login")
        self.login_window.geometry("300x400")
        self.login_window.resizable(False, False)
        
        # Create main frame
        main_frame = tk.Frame(self.login_window, padx=20, pady=20)
        main_frame.pack(expand=True, fill='both')
        
        # Title
        title_label = tk.Label(main_frame, text="Secure Chat", font=("Helvetica", 24, "bold"))
        title_label.pack(pady=20)
        
        # Username frame
        username_frame = tk.Frame(main_frame)
        username_frame.pack(fill='x', pady=10)
        
        username_label = tk.Label(username_frame, text="Username:", font=("Helvetica", 10))
        username_label.pack(anchor='w')
        
        self.username_entry = tk.Entry(username_frame, font=("Helvetica", 12))
        self.username_entry.pack(fill='x', pady=(5,0))
        
        # Password frame
        password_frame = tk.Frame(main_frame)
        password_frame.pack(fill='x', pady=10)
        
        password_label = tk.Label(password_frame, text="Password:", font=("Helvetica", 10))
        password_label.pack(anchor='w')
        
        self.password_entry = tk.Entry(password_frame, show="•", font=("Helvetica", 12))
        self.password_entry.pack(fill='x', pady=(5,0))
        
        # Error label
        self.error_label = tk.Label(main_frame, text="", fg="red", wraplength=250)
        self.error_label.pack(pady=10)
        
        # Buttons frame
        buttons_frame = tk.Frame(main_frame)
        buttons_frame.pack(pady=20)
        
        login_btn = tk.Button(
            buttons_frame, 
            text="Login",
            command=self.handle_login,
            width=12,
            font=("Helvetica", 10, "bold")
        )
        login_btn.pack(side='left', padx=5)
        
        register_btn = tk.Button(
            buttons_frame, 
            text="Register",
            command=self.show_register_window,
            width=12,
            font=("Helvetica", 10)
        )
        register_btn.pack(side='left', padx=5)
        
        # Bind Enter key to login
        self.login_window.bind('<Return>', lambda event: self.handle_login())
        
        self.login_window.mainloop()

    def show_register_window(self):
        self.register_window = tk.Toplevel(self.login_window)
        self.register_window.title("Secure Chat - Register")
        self.register_window.geometry("300x450")
        self.register_window.resizable(False, False)
        
        # Create main frame
        main_frame = tk.Frame(self.register_window, padx=20, pady=20)
        main_frame.pack(expand=True, fill='both')
        
        # Title
        title_label = tk.Label(main_frame, text="Create Account", font=("Helvetica", 24, "bold"))
        title_label.pack(pady=20)
        
        # Username
        username_label = tk.Label(main_frame, text="Username:", font=("Helvetica", 10))
        username_label.pack(anchor='w')
        self.reg_username_entry = tk.Entry(main_frame, font=("Helvetica", 12))
        self.reg_username_entry.pack(fill='x', pady=(5,10))
        
        # Password
        password_label = tk.Label(main_frame, text="Password:", font=("Helvetica", 10))
        password_label.pack(anchor='w')
        self.reg_password_entry = tk.Entry(main_frame, show="•", font=("Helvetica", 12))
        self.reg_password_entry.pack(fill='x', pady=(5,10))
        
        # Confirm Password
        confirm_label = tk.Label(main_frame, text="Confirm Password:", font=("Helvetica", 10))
        confirm_label.pack(anchor='w')
        self.reg_confirm_entry = tk.Entry(main_frame, show="•", font=("Helvetica", 12))
        self.reg_confirm_entry.pack(fill='x', pady=(5,10))
        
        # Error label
        self.reg_error_label = tk.Label(main_frame, text="", fg="red", wraplength=250)
        self.reg_error_label.pack(pady=10)
        
        # Register button
        register_btn = tk.Button(
            main_frame,
            text="Create Account",
            command=self.handle_register,
            font=("Helvetica", 10, "bold")
        )
        register_btn.pack(pady=10)
        
        # Bind Enter key to register
        self.register_window.bind('<Return>', lambda event: self.handle_register())

    def handle_login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not username or not password:
            self.error_label.config(text="Please fill in all fields")
            return
        
        try:
            success = self.authenticate_user(username, password, 'login')
            if success:
                self.username = username
                self.login_window.destroy()
                self.setup_chat_window()
        except Exception as e:
            self.error_label.config(text=str(e))

    def handle_register(self):
        username = self.reg_username_entry.get().strip()
        password = self.reg_password_entry.get()
        confirm = self.reg_confirm_entry.get()
        
        # Validation
        if not username or not password or not confirm:
            self.reg_error_label.config(text="Please fill in all fields")
            return
        
        if len(username) < 3:
            self.reg_error_label.config(text="Username must be at least 3 characters")
            return
        
        if len(password) < 6:
            self.reg_error_label.config(text="Password must be at least 6 characters")
            return
        
        if password != confirm:
            self.reg_error_label.config(text="Passwords do not match")
            return
        
        try:
            success = self.authenticate_user(username, password, 'register')
            if success:
                self.register_window.destroy()
                messagebox.showinfo("Success", "Account created successfully! You can now login.")
        except Exception as e:
            self.reg_error_label.config(text=str(e))

    def setup_chat_window(self):
        self.window = tk.Tk()
        self.window.title(f"Chat Client - {self.username}")
        
        self.chat_area = scrolledtext.ScrolledText(self.window, state='disabled', wrap='word')
        self.chat_area.pack(padx=10, pady=10)
        
        self.message_entry = tk.Entry(self.window)
        self.message_entry.pack(padx=10, pady=10, fill=tk.X)
        
        self.send_button = tk.Button(self.window, text="Send", command=self.send_message)
        self.send_button.pack(padx=10, pady=10)
        
        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        threading.Thread(target=self.receive_messages, daemon=True).start()
        
        self.window.mainloop()

    def send_message(self):
        content = self.message_entry.get()
        if content:
            message = Message(self.username, content)
            # Encrypt the message
            message.encrypt(self.symmetric_key)
            # Sign the encrypted message
            message.sign(self.private_key)
            
            try:
                self.client_socket.send(message.to_json().encode('utf-8'))
                self.message_entry.delete(0, tk.END)
            except Exception as e:
                print(f"Error sending message: {e}")

    def receive_messages(self):
        while True:
            try:
                message_data = self.client_socket.recv(1024).decode('utf-8')
                if message_data:
                    message = Message.from_json(message_data)
                    
                    # If it's not a server message, decrypt and verify
                    if message.sender != "Server":
                        # Verify signature
                        if not message.verify(self.public_keys.get(message.sender)):
                            message.content = "[INVALID SIGNATURE] " + message.content
                        # Decrypt message
                        message.decrypt(self.symmetric_key)
                    
                    self.chat_area.config(state='normal')
                    self.chat_area.insert(tk.END, str(message) + '\n')
                    self.chat_area.config(state='disabled')
                    self.chat_area.yview(tk.END)
            except Exception as e:
                print(f"Error receiving message: {e}")
                break

    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.client_socket.close()
            self.window.destroy()

if __name__ == "__main__":
    client = ChatClient()
