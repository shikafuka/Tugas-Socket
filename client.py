import socket
import threading

def receive_messages(client_socket):
    while True:
        try:
            # Receive messages from the server
            message, _ = client_socket.recvfrom(1024)
            print(message.decode('utf-8'))
        except:
            print("Error receiving message")
            break

def start_client():
    # Create UDP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ("localhost", 12000)

    # Input username and send to server
    username = input("Enter your username: ")
    client_socket.sendto(username.encode('utf-8'), server_address)

    # Start thread to receive messages
    receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
    receive_thread.start()

    # Main loop for sending messages
    while True:
        message = input("")
        client_socket.sendto(f"{username}: {message}".encode('utf-8'), server_address)

if __name__ == "__main__":
    start_client()
