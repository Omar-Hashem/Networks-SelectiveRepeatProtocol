import socket

from validator import isValidPacket
from collections import deque
import packet
import pickle
import random
import threading
import time

# type of destination
AF_INET = 4
AF_INET6 = 6

# how man bytes can send/receive accept
_BUFFER_SIZE = 1024

# if not provided, limits the send/receive queue
_DEFAULT_MAX_QUEUE_SIZE = 5000

# how many timeouts should I allow without failing
_MAX_TIMEOUT_ACK_THRESHOLD = 100

# initial timeout
_INITAL_TIME_OUT_INTERVAL = 0.5

# initial congestion control window
_INITIAL_CWND = 1

# initial send/receive state
_INITIAL_STATE = 0

# congestion control different states types
_SLOW_START = 0
_CONGESTION_AVOIDANCE = 1
_FAST_RECOVERY = 3

class socketTCP:
    def __init__(self, port, socket_family, loss_probability, max_queue_size, congestion_control):
        self.port = port
        self.socket_family = socket_family
        self.loss_probability = loss_probability
        self.cum_prob = 0.0
        self.udt_send_cnt = 0
        self.udt_rcv_cnt = 0
        self.send_state = 0
        self.receive_state = 0
        self.dest_addr = 0  # to be setted by address/connect (IP,Port)
        self.number_of_receivers = 100
        self.connection_closed = False

        self.condition_lock = threading.Condition()
        self.send_queue = deque()
        self.buffer_send_base = 0  
        self.receive_buffer = {}
        self.buffer_receive_base = 0
        self.receive_lock = threading.Condition()  # lock for buffer and counter
        self.counter = 0

        # congestion control parameters
        self.congestion_control = congestion_control
        self.duplicate_count = 0
        self.cwnd = _INITIAL_CWND
        self.congestion_state = _SLOW_START
        self.slow_threshold = int(max_queue_size / 10) + 1

        # windowing parameters
        self.max_queue_size = max_queue_size

        if self.congestion_control:
            self.window_size = min(int(self.cwnd), self.max_queue_size)
        else:
            self.window_size = self.max_queue_size

        # dynamic timeout parameters
        self.alpha = 0.125
        self.beta = 0.25
        self.estimated_RTT = _INITAL_TIME_OUT_INTERVAL
        self.dev_RTT = _INITAL_TIME_OUT_INTERVAL / 2.0
        self.timeout = _INITAL_TIME_OUT_INTERVAL

        if socket_family == AF_INET:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            self.socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

        self.socket.settimeout(self.timeout)

    def bind(self):  # if port = 0, then OS picks free port for the socket
        # We need to clear this port, later
        try:
            self.socket.bind(('0.0.0.0', self.port))

            self.port = self.socket.getsockname()[1]

            return True
        except socket.error:
            return False

    def _drop(self):
        if self.cum_prob >= 1.0:
            self.cum_prob = self.cum_prob - 1.0
            return True
        else:
            return False

    def _udt_send(self, data, dest_ip, dest_port):
        self.udt_send_cnt = self.udt_send_cnt + 1
        self.cum_prob = self.cum_prob + self.loss_probability

        if not self._drop():
            self.socket.sendto(data, (dest_ip, dest_port))

    def _udt_receive(self):
        self.udt_rcv_cnt = self.udt_rcv_cnt + 1

        data, address = self.socket.recvfrom(_BUFFER_SIZE)  # returns (data, address = (ip, port))

        my_packet = pickle.loads(data)

        return (my_packet, address)

    def timeout_enhance(self, sample_RTT):
        # print("Sample RTT:", sample_RTT)
        # print("Counter:", self.counter)
        # print("Send base:", self.buffer_send_base)
        # print("Receive base:", self.buffer_receive_base)
        
        self.estimated_RTT = (1 - self.alpha) * self.estimated_RTT + self.alpha * sample_RTT
        self.dev_RTT = (1 - self.beta) * self.dev_RTT + self.beta * abs(self.estimated_RTT - sample_RTT)
        self.timeout = self.estimated_RTT + 4 * self.dev_RTT
        self.socket.settimeout(self.timeout)

    def _rdt_send(self, data, dest_ip, dest_port):

        # RTT is the time between send & valid ACK

        data = packet.get_data_packet(5555, self.send_state, data)

        send_time = time.time()

        self._udt_send(pickle.dumps(data), dest_ip, dest_port)

        # State is sender waits for ACK

        cnt = 0
        while True:
            cnt = cnt + 1
            try:
                ack_data, address = self._udt_receive()
                if not isinstance(ack_data, packet.ack_packet):
                    continue
                if not isValidPacket(ack_data):
                    continue
                if ack_data.ack_no != self.send_state:
                    continue

                sample_RTT = time.time() - send_time
                self.timeout_enhance(sample_RTT)
                self.send_state = 1 - self.send_state  # Change state 0 -> 1 and vice versa
                break
            except socket.timeout:
                if cnt == _MAX_TIMEOUT_ACK_THRESHOLD:
                    self.send_state = 1 - self.send_state
                    break

                send_time = time.time()
                self._udt_send(pickle.dumps(data), dest_ip, dest_port)
                continue

    def send_ack(self, checkSum, ackNum, address):
        ack = packet.get_ack_packet(checkSum, ackNum)
        self._udt_send(pickle.dumps(ack), address[0], address[1])

    def _rdt_receive(self):
        while True:
            try:
                data, address = self._udt_receive()

                if not isValidPacket(data):
                    self.send_ack(5555, 1 - self.receive_state, address)
                    continue

                if data.seq_no != self.receive_state:
                    self.send_ack(5555, 1 - self.receive_state, address)
                    continue

                # data, valid, has correct sequence number, no loss
                self.send_ack(5555, self.receive_state, address)  # Last Ack might not reach sender

                self.receive_state = 1 - self.receive_state  # Change state 0 -> 1 and vice versa

                return (data.data, address)
            except socket.timeout:
                continue

    def send(self, data):
        self._rdt_send_repeative(data, self.dest_addr[0], self.dest_addr[1])

    def receive(self):
        return self._rdt_receive_repeative()

    def accept(self):
        self.receive_state = 0
        self.send_state = 0

        data, address = self._rdt_receive()
        # data is number x

        s = make_socket(0, self.socket_family, self.loss_probability, self.max_queue_size, self.congestion_control) 

        # note here
        s.send_state = _INITIAL_STATE
        s.receive_state = _INITIAL_STATE
        s.counter = _INITIAL_STATE
        s.buffer_receive_base = _INITIAL_STATE
        s.buffer_send_base = _INITIAL_STATE

        if not isinstance(data, int):
            return (False, s)

        if threading.activeCount() - 1 >= self.number_of_receivers:
            self._rdt_send((data + 5, s.port), address[0], address[1])
            return (False, s)

        s.dest_addr = address

        if not s.bind():
            self._rdt_send((data + 5, s.port), address[0], address[1])
            return (False, s)

        self._rdt_send((data + 1, s.port), address[0], address[1])

        data, address = self._rdt_receive()

        self.receive_state = 0
        self.send_state = 0

        if data == s.port + 1:
            receive_thread(s).start()
            return (True, s)
        else:
            return (False, s)

    def connect(self, dest_ip, dest_port):
        # client SYN(X) where x is random
        # server SYNACK(ACK=X+1,Y) let Y = new port
        # client SYNACK(Y+1)

        self.receive_state = 0
        self.send_state = 0

        x = random.randint(1, 100000)
        self._rdt_send(x, dest_ip, dest_port)

        data, address = self._rdt_receive()

        if data[0] == x + 1:
            self.dest_addr = (dest_ip, data[1])
            self._rdt_send(data[1] + 1, dest_ip, dest_port)
        else:
            self.receive_state = 0
            self.send_state = 0
            return False

        self.receive_state = _INITIAL_STATE
        self.send_state = _INITIAL_STATE
        self.counter = _INITIAL_STATE
        self.buffer_receive_base = _INITIAL_STATE
        self.buffer_send_base = _INITIAL_STATE

        receive_thread(self).start()
        return True

    def listen(self, limit_of_receivers):
        self.number_of_receivers = limit_of_receivers

    def close(self):
        self.connection_closed = True
        # self.socket.close()

    def _rdt_receive_repeative(self):

        with self.receive_lock:
            while self.counter not in self.receive_buffer:
                self.receive_lock.wait()

            data = self.receive_buffer[self.counter]
            del self.receive_buffer[self.counter]

            self.counter = self.counter + 1
            self.buffer_receive_base = self.buffer_receive_base + 1 

            return data

    def _rdt_send_repeative(self, data, dest_ip, dest_port):
        with self.condition_lock:
            while len(self.send_queue) == self.window_size:
                self.condition_lock.wait()

            data_packet = packet.get_data_packet(5555, self.send_state, data)
            elem = [data_packet, time.time(), dest_ip, dest_port, self.send_state, 0]
            self.send_queue.append(elem)
            self._udt_send(pickle.dumps(data_packet), dest_ip, dest_port)
            self.send_state = self.send_state + 1

            timer_thread(self, elem, threading.Event()).start()

    def _control_congestion(self, timeout=False, new_ack=False):
        if timeout:
            try:
                self.duplicate_count = 0
                self.slow_threshold = self.cwnd / 2
                self.cwnd = 1
                self.congestion_state = _SLOW_START

                if min(self.max_queue_size, int(self.cwnd)) != self.window_size:
                    print(min(self.max_queue_size, int(self.cwnd)))

                self.window_size = min(self.max_queue_size, int(self.cwnd))

                return
            except Exception:
                return

        if self.congestion_state == _SLOW_START:
            if new_ack:
                self.duplicate_count = 0
                self.cwnd += 1
                if self.cwnd >= self.slow_threshold:
                    self.congestion_state = _CONGESTION_AVOIDANCE
            elif self.duplicate_count >= 3:
                self.slow_threshold = self.cwnd / 2
                self.cwnd = self.slow_threshold + 3
                self.congestion_state = _FAST_RECOVERY

        elif self.congestion_control == _FAST_RECOVERY:
            if new_ack:
                self.cwnd = max(self.slow_threshold, 1)
                self.duplicate_count = 0
                self.congestion_state = _CONGESTION_AVOIDANCE
            else:
                self.cwnd += 1

        else:  # Congestion avoidance
            if new_ack:
                self.cwnd += 1.0 / self.cwnd
                self.duplicate_count = 0
            elif self.duplicate_count >= 3:
                self.slow_threshold = self.cwnd / 2
                self.cwnd = self.slow_threshold + 3

        if min(self.max_queue_size, int(self.cwnd)) != self.window_size:
            print(min(self.max_queue_size, int(self.cwnd)))

        self.window_size = min(self.max_queue_size, int(self.cwnd))

def make_socket(port, socket_family, loss_probability, max_queue_size=_DEFAULT_MAX_QUEUE_SIZE, congestion_control=True):
    return socketTCP(port, socket_family, loss_probability, max_queue_size, congestion_control)

class timer_thread(threading.Thread):
    def __init__(self, s, elem, event):
        threading.Thread.__init__(self)
        self.s = s
        self.elem = elem
        self.stopped = event
        self.cnt = 0

    def run(self):
        while not self.stopped.wait(self.s.timeout):
            if self.elem[5] or self.cnt == _MAX_TIMEOUT_ACK_THRESHOLD:
                self.stopped.set()
                exit(0)
            self.s._udt_send(pickle.dumps(self.elem[0]), self.elem[2], self.elem[3])
            self.cnt += 1

            if self.s.congestion_control:
                self.s._control_congestion(timeout=True)


class receive_thread(threading.Thread):
    def __init__(self, s):
        threading.Thread.__init__(self)
        self.s = s

    def receive_data(self, my_packet, address):
        with self.s.receive_lock:
            if my_packet.seq_no >= self.s.buffer_receive_base and my_packet.seq_no <= self.s.buffer_receive_base + self.s.max_queue_size - 1:
                self.s.receive_buffer[my_packet.seq_no] = my_packet.data

                self.s.receive_lock.notifyAll()

                self.s.send_ack(5555, my_packet.seq_no, address)
            elif my_packet.seq_no < self.s.buffer_receive_base:
                self.s.send_ack(5555, my_packet.seq_no, address)
            else:
                pass  # the packet can't be buffered due to limited size of the buffer

    def receive_ack(self, my_packet, address):
        with self.s.condition_lock:
            if my_packet.ack_no < self.s.buffer_send_base:
                if self.s.congestion_control:
                    self.s.duplicate_count += 1
                    self.s._control_congestion()
                return

            index = my_packet.ack_no - self.s.buffer_send_base

            if index > len(self.s.send_queue):  # case of erroneous packet
                return

            if not self.s.send_queue[index][5]:
                self.s.send_queue[index][5] = 1
                sample_RTT = time.time() - self.s.send_queue[index][1]
                self.s.timeout_enhance(sample_RTT)

                if self.s.congestion_control:
                    self.s._control_congestion(new_ack=True)

            else:
                if self.s.congestion_control:
                    self.s.duplicate_count += 1
                    self.s._control_congestion()

            if my_packet.ack_no == self.s.buffer_send_base:
                while self.s.send_queue and self.s.send_queue[0][5]:
                    self.s.send_queue.popleft()
                    self.s.buffer_send_base = self.s.buffer_send_base + 1
            
            self.s.condition_lock.notifyAll()

    def run(self):
        while True:
            if self.s.connection_closed:
                with self.s.condition_lock:
                    if not self.s.send_queue:
                        self.s.socket.close()
                        break

            try:
                my_packet, address = self.s._udt_receive()
                if isinstance(my_packet, packet.ack_packet):
                    self.receive_ack(my_packet, address)
                elif isinstance(my_packet, packet.data_packet):
                    self.receive_data(my_packet, address)
            except socket.timeout as E:
                pass



