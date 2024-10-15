import socket
import threading

# Global list to track client addresses
clients = []
client_usernames = {}

# Server function to handle clients
def handle_client(server_socket):
    while True:
        try:
            # Receive message and client address
            message, client_address = server_socket.recvfrom(1024)
            decoded_message = message.decode('utf-8')

            # If it's a new client, register them
            if client_address not in clients:
                clients.append(client_address)
                username = decoded_message  # Assume the first message is the username
                client_usernames[client_address] = username
                print(f"[{username}] joined from {client_address}")
                continue

            # Print received message on the server
            print(f"[{client_usernames[client_address]}] {decoded_message}")

            # Broadcast the message to all other clients
            for client in clients:
                if client != client_address:
                    server_socket.sendto(message, client)
        except:
            print("An error occurred while handling a client")
            break

def start_server():
    # Create UDP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ("localhost", 12000)
    server_socket.bind(server_address)

    print(f"Server started on {server_address}")

    # Start handling clients
    handle_client(server_socket)

if __name__ == "__main__":
    start_server()
