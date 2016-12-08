import TCP
import socket

def server():
    s = TCP.make_socket(10000, TCP.AF_INET, 0.9)
    print('bind', s.bind())
    flag, another_server = s.accept()

    print(flag)
    print(another_server)
    print(another_server.dest_addr)

    print('timeout interval', s.estimated_RTT + s.dev_RTT * 4)

def client():
    s = TCP.make_socket(9800, TCP.AF_INET, 0.9)
    print('bind', s.bind())
    print(s.connect(socket.gethostname(), 10000))
    print(s.dest_addr)

    print('timeout interval', s.estimated_RTT + s.dev_RTT * 4)
