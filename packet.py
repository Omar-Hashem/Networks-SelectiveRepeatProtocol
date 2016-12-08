class data_packet ():
    def __init__(self, check_sum, seq_no, data):
        self.check_sum = check_sum
        self.seq_no = seq_no
        self.data = data

def get_data_packet(check_sum, seq_no, data):
    return data_packet(check_sum, seq_no, data)


class ack_packet ():
    def __init__(self, check_sum, ack_no):
        self.check_sum = check_sum
        self.ack_no = ack_no

def get_ack_packet(check_sum, ack_no):
    return ack_packet(check_sum, ack_no)

