import socket

HOST = 'localhost'
PORT = 8888


def start_proxy():
    # create the proxy socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # bind the socket to a local address and port
    server_socket.bind((HOST, PORT))

    # start listening for incoming connections
    server_socket.listen(1)

    print(f"Proxy server listening on port {PORT}")

    while True:
        # accept a connection from a client
        client_socket, client_address = server_socket.accept()

        # read the client's request
        request = client_socket.recv(4096).decode()

        print('Proxy Server: Captured request as follows:')
        print(request)
        print('-=-=-=-=-')

        # forward the request to the destination server
        forward_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        forward_socket.connect(('www.google.com', 80))
        print('Proxy Server: Connected to Google')
        print('-=-=-=-=-')
        forward_socket.sendall(request.encode())

        # receive the response from the server and send it back to the client
        response = forward_socket.recv(4096)
        client_socket.sendall(response)

        # close the sockets
        forward_socket.close()
        client_socket.close()


start_proxy()
