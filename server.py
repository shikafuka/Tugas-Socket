import socket
import threading

clients = []
client_usernames = {}

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

# Function to handle clients
def handle_client(server_socket):
    while True:
        try:
            # Receive message and client address using recvfrom for UDP
            message, client_address = server_socket.recvfrom(1024)
            decoded_message = message.decode('utf-8')

            # Check if the client is sending credentials for authentication
            if client_address not in clients:
                username, password = decoded_message.split(':')

                # Check password
                if password != "chat123":
                    server_socket.sendto("Invalid password!".encode('utf-8'), client_address)
                    continue

                # Check for unique username
                if username in client_usernames.values():
                    server_socket.sendto("Username already taken. Please try again.".encode('utf-8'), client_address)
                else:
                    clients.append(client_address)
                    client_usernames[client_address] = username
                    server_socket.sendto("OK".encode('utf-8'), client_address)
                    print(f"[{username}] joined from {client_address}")
                    broadcast_message(f"{username} has joined the chat.", server_socket, client_address)
                    continue

            # Process normal messages (encrypted)
            if client_address in clients:
                username = client_usernames[client_address]
                decrypted_message = caesar_decrypt(decoded_message, 3)
                print(f"[{username}] {decrypted_message}")
                broadcast_message(f"{username}: {decrypted_message}", server_socket, client_address)

        except Exception as e:
            print(f"Error handling client {client_address}: {e}")

# Broadcast message to other clients
def broadcast_message(message, server_socket, sender_address):
    encrypted_message = caesar_encrypt(message, 3)
    for client in clients:
        if client != sender_address:
            try:
                server_socket.sendto(encrypted_message.encode('utf-8'), client)
            except:
                print(f"Failed to send message to {client}")
                clients.remove(client)

# Start the server
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(("localhost", 12000))
    print("Server started on localhost:12000")

    handle_client(server_socket)

if __name__ == "__main__":
    start_server()
