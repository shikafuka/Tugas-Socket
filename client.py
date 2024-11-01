import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from tkinter import messagebox

# Caesar Cipher for encryption and decryption
def caesar_encrypt(plaintext, shift):
    result = []
    for char in plaintext:
        if char.isalpha():
            shift_val = 65 if char.isupper() else 97
            result.append(chr((ord(char) - shift_val + shift) % 26 + shift_val))
        else:
            result.append(char)
    return ''.join(result)

def caesar_decrypt(ciphertext, shift):
    return caesar_encrypt(ciphertext, -shift)

class ClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Login")
        
        # Setup login window
        self.login_frame = tk.Frame(self.root)
        self.login_frame.pack(padx=10, pady=10)

        # IP Address input
        self.ip_label = tk.Label(self.login_frame, text="Server IP:")
        self.ip_label.grid(row=0, column=0, padx=5, pady=5)
        self.ip_entry = tk.Entry(self.login_frame)
        self.ip_entry.grid(row=0, column=1, padx=5, pady=5)

        # Port input
        self.port_label = tk.Label(self.login_frame, text="Port:")
        self.port_label.grid(row=1, column=0, padx=5, pady=5)
        self.port_entry = tk.Entry(self.login_frame)
        self.port_entry.grid(row=1, column=1, padx=5, pady=5)

        # Username input
        self.username_label = tk.Label(self.login_frame, text="Username:")
        self.username_label.grid(row=2, column=0, padx=5, pady=5)
        self.username_entry = tk.Entry(self.login_frame)
        self.username_entry.grid(row=2, column=1, padx=5, pady=5)

        # Password input
        self.password_label = tk.Label(self.login_frame, text="Password:")
        self.password_label.grid(row=3, column=0, padx=5, pady=5)
        self.password_entry = tk.Entry(self.login_frame, show="*")
        self.password_entry.grid(row=3, column=1, padx=5, pady=5)

        # Login button
        self.login_button = tk.Button(self.login_frame, text="Login", command=self.login)
        self.login_button.grid(row=4, columnspan=2, padx=5, pady=5)

        # Exit Button
        self.exit_button = tk.Button(self.root, text="Exit", command=self.exit_chat)
        self.exit_button.pack(padx=10, pady=10)
        
        # Variables for socket and user info
        self.client_socket = None

    def login(self):
        ip = self.ip_entry.get()
        port = self.port_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()

        if ip == "" or port == "" or username == "" or password == "":
            messagebox.showwarning("Input Error", "Please enter all fields.")
            return

        # Attempt to connect to server and authenticate
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            server_port = int(port)
            self.client_socket.connect((ip, server_port))
            self.client_socket.send(f"{username}:{password}".encode('utf-8'))

            # Receive server response for authentication
            response = self.client_socket.recv(1024).decode('utf-8')
            if response == "OK":
                # Successful login, open chat window
                self.open_chat_window(username)
            else:
                messagebox.showerror("Login Failed", response)
        except Exception as e:
            messagebox.showerror("Connection Error", f"Unable to connect to server: {e}")
            return

    def open_chat_window(self, username):
        # Destroy login frame and show chat window
        self.login_frame.destroy()

        self.root.title(f"Chat - {username}")

        # Setup chat window
        self.chat_display = scrolledtext.ScrolledText(self.root)
        self.chat_display.pack(padx=10, pady=10)

        self.message_entry = tk.Entry(self.root)
        self.message_entry.pack(padx=10, pady=5)

        # Bind the Enter key to the send_message function
        self.message_entry.bind("<Return>", self.send_message)

        self.send_button = tk.Button(self.root, text="Send", command=self.send_message)
        self.send_button.pack(padx=10, pady=5)

        self.username = username

        # Start a thread to receive messages
        self.receive_thread = threading.Thread(target=self.receive_messages)
        self.receive_thread.start()

    def send_message(self, event=None):
        message = self.message_entry.get()
        if message:
            encrypted_message = caesar_encrypt(message, 3)  # Encrypt the message
            self.client_socket.send(encrypted_message.encode('utf-8'))
            self.chat_display.insert(tk.END, f"Me: {message}\n")
            self.message_entry.delete(0, tk.END)

    def receive_messages(self):
        while True:
            try:
                message = self.client_socket.recv(1024).decode('utf-8')
                decrypted_message = caesar_decrypt(message, 3)  # Decrypt the message
                self.chat_display.insert(tk.END, f"{decrypted_message}\n")
            except:
                print("Error receiving message")
                break
            
    def exit_chat(self):
        result = messagebox.askquestion("Exit", "Are you sure you want to exit?", icon='warning')
        if result == 'yes':
            if self.client_socket is not None:
                try:
                    self.client_socket.sendto("exit".encode('utf-8'), ("localhost", 12000))  # Send "exit" to the server
                except Exception as e:
                    print(f"Failed to notify server of exit: {e}")
                self.client_socket.close()  # Close socket if it exists
            self.root.quit()  # Close the GUI application

root = tk.Tk()
app = ClientApp(root)
root.mainloop()
