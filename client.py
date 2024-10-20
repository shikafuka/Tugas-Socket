import socket
import threading
import tkinter as tk
from tkinter import scrolledtext

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

class Client:
    def __init__(self, root):
        self.root = root
        self.root.title("Chat Application")

        # Setup GUI
        self.chat_display = scrolledtext.ScrolledText(self.root)
        self.chat_display.pack()

        self.message_entry = tk.Entry(self.root)
        self.message_entry.pack()

        self.send_button = tk.Button(self.root, text="Send", command=self.send_message)
        self.send_button.pack()

        # Setup socket connection
        self.server_ip = input("Enter server IP: ")
        self.server_port = int(input("Enter server port: "))
        self.username = input("Enter your username: ")
        self.password = input("Enter your password: ")

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client_socket.connect((self.server_ip, self.server_port))

        self.authenticate()

        # Start thread to receive messages
        self.receive_thread = threading.Thread(target=self.receive_messages)
        self.receive_thread.start()

    def authenticate(self):
        # Send username and password for authentication
        self.client_socket.send(f"{self.username}:{self.password}".encode('utf-8'))
        response = self.client_socket.recv(1024).decode('utf-8')
        if response != "OK":
            print("Authentication failed. Exiting...")
            self.root.quit()

    def send_message(self):
        message = self.message_entry.get()
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

root = tk.Tk()
client = Client(root)
root.mainloop()
