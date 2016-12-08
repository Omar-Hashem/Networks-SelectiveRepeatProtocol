import read_files
import sys
import socket
import TCP
import time
from printing import bcolors

_BUFFER_SIZE = 400

def client():

    if len(sys.argv) != 2:
        print(bcolors.FAIL + "Error: insertion of arguments file missed!" + bcolors.ENDC)
        exit()

    server_ip, server_port_number, client_port_number, file_name, receiveing_sliding_window_size = get_client_data()
    s = TCP.make_socket(int(client_port_number), TCP.AF_INET, 0)  # check for IPv6

    if not s.bind():
        print(bcolors.FAIL + "error : please change port number [ port busy ] " + bcolors.ENDC)
        exit(1)
        
    if server_ip == "localhost":
        s.connect(socket.gethostname(), int(server_port_number))
    else:
        s.connect(server_ip, int(server_port_number))

    s.send(file_name)
    data = s.receive()

    if data == "error":
        print(bcolors.FAIL + "Error: File not Found !" + bcolors.ENDC)
    else:
        file = open(file_name.split("\\")[-1], "ab")

        num_of_packets = int(data)
        print('Number of packets :', num_of_packets)

        before = time.time()

        for i in range(0, num_of_packets, 1):
            data = s.receive()

            percentage = int(i * 100 / num_of_packets)
            my_print(percentage, i, num_of_packets, True)

            file.write(data)

        reception_time = time.time() - before 

        my_print(100, num_of_packets, num_of_packets, False)
        
        print("Success: File Reception Completed !")

        s.close()

        print("\nStatistics :-")
        print("Reception Time =", "{0:.2f}".format(reception_time), "Sec")
        print("Average Speed =", "{0:.2f}".format(num_of_packets / reception_time), "Packets/Sec")


def get_client_data():
    client_arguments = read_files.parse_client_file(sys.argv[1])
    return client_arguments['server_ip'], client_arguments['server_port_number'], \
           client_arguments['client_port_number'], client_arguments['file_name'], \
           client_arguments['receiveing_sliding_window_size']

def my_print(percentage, i, num_of_packets, erase):
    to_print = bcolors.OKGREEN
    to_print = to_print + "{0:3d}".format(percentage)
    to_print = to_print + " % Transferred "
    to_print = to_print + ('#' * percentage)
    to_print = to_print + ' ' * (100 - percentage)
    to_print = to_print + '| '
    to_print = to_print + "Packet Num : "
    to_print = to_print + "{0:d}".format(i)
    to_print = to_print + '/'
    to_print = to_print + "{0:d}".format(num_of_packets)
    to_print = to_print + bcolors.ENDC
    print(to_print, end="")

    if erase:
        sys.stdout.write('\r')
    else:
        print('')

try:
    client()
except Exception:
    print("Error: OS Forcibly closed connection !")
    exit(1)

