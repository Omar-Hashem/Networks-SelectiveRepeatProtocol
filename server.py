import TCP
import threading
import read_files
import sys
import os
import math

_BUFFER_SIZE = 400

class serverThread(threading.Thread):
    def __init__(self, serverSocket):
        threading.Thread.__init__(self)
        self.serverSocket = serverSocket

    def run(self):
        file_name = self.serverSocket.receive()

        try:
            file = open(file_name, "rb", 0)
            file_size = os.path.getsize(file_name)
            num_of_parts = math.ceil(file_size / _BUFFER_SIZE)

            self.serverSocket.send(str(num_of_parts))

            for i in range(num_of_parts):
                data = file.read(_BUFFER_SIZE)
                self.serverSocket.send(data)

            # print(self.serverSocket.estimated_RTT + self.serverSocket.estimated_RTT * 4)

            self.serverSocket.close()
        except Exception as e:
            self.serverSocket.send("error")


def get_server_data():
    server_arguments = read_files.parse_server_file(sys.argv[1])
    return server_arguments['server_port_number'], server_arguments['sending_sliding_window_size'], \
           server_arguments['random_generate_seed_value'], server_arguments['loss_probability']


def server():
    if len(sys.argv) != 2:
        print("Error: insertion of arguments file missed!")
        exit()

    server_port_number,                 \
    sending_sliding_window_size,        \
    random_generate_seed_value,         \
    loss_probability = get_server_data()

    tcp_socket = TCP.make_socket(int(server_port_number), TCP.AF_INET, float(loss_probability))
    print(tcp_socket.loss_probability)
    if not tcp_socket.bind():
        print("Error : Cannot bind a busy port !")
        exit()

    while True:
        success_flag, s = tcp_socket.accept()

        if success_flag:
            print("Client Accepted !")
            serverThread(s).start()

try:
    server()
except Exception:
    print("Error: client side terminated or OS closed connection forcibly !")
    exit(1)
