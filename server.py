import socket

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

def handle_client(server_socket, password):
    while True:
        try:
            # Receive message from clients
            message, client_address = server_socket.recvfrom(1024)
            decoded_message = message.decode('utf-8')

            # If the client is not authenticated, check password
            if client_address not in clients:
                # First message should be in the format "username:password"
                if ':' not in decoded_message:
                    server_socket.sendto("Invalid format. Please send username:password".encode('utf-8'), client_address)
                    continue

                username, received_password = decoded_message.split(':')
                if received_password != password:
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

            # Handle exit message
            if decoded_message.lower() == "exit":
                username = client_usernames[client_address]
                print(f"[{username}] has left the chat.")  # Log on server when a user quits
                broadcast_message(f"{username} has left the chat.", server_socket, client_address)
                clients.remove(client_address)
                del client_usernames[client_address]
                continue

            # Process normal messages (keep encrypted for log)
            if client_address in clients:
                username = client_usernames[client_address]
                print(f"[{username}] {decoded_message} (Encrypted)")  # Print the encrypted message received from the client
                decrypted_message = caesar_decrypt(decoded_message, 3)
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

def is_valid_ip(ip):
    try:
        # Use socket library to check IP address validity
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def is_valid_port(port):
    return 1 <= port <= 65535

# Start the server
def start_server(ip, port, password):
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind((ip, port))
        print(f"Server started on {ip}:{port} with password '{password}'")
    except OSError as e:
        print(f"Failed to bind to {ip}:{port}. Error: {e}")
        return

    handle_client(server_socket, password)

if __name__ == "__main__":
    # Loop until a valid IP address is provided
    while True:
        ip = input("Enter server IP (default 'localhost'): ") or "localhost"
        if ip == "localhost" or is_valid_ip(ip):
            break
        print("Invalid IP address. Please enter a valid IP address.")

    # Loop until a valid port number is provided
    while True:
        try:
            port = int(input("Enter server port (default 12000): ") or 12000)
            if is_valid_port(port):
                break
            print("Invalid port. Port must be between 1 and 65535.")
        except ValueError:
            print("Invalid input. Please enter a numeric value for the port.")

    password = input("Enter chatroom password (default 'chat123'): ") or "chat123"

    start_server(ip, port, password)
