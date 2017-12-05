import sys
import socket


class PingPacket(object):

    def calculate_checksum(self, buffer):

        """
        I'm not too confident that this is right but testing seems
        to suggest that it gives the same answers as in_cksum in ping.c
        :param buffer:
        :return:
        """
        sum = 0
        count_to = (len(buffer) / 2) * 2
        count = 0

        while count < count_to:
            this_val = buffer[count + 1] * 256 + buffer[count]
            sum += this_val
            sum &= 0xffffffff  # Necessary?
            count += 2

        if count_to < len(buffer):
            sum += buffer[len(buffer) - 1]
            sum &= 0xffffffff  # Necessary?

        sum = (sum >> 16) + (sum & 0xffff)
        sum += sum >> 16
        answer = ~sum
        answer &= 0xffff

        # Swap bytes. Bugger me if I know why.
        answer = answer >> 8 | (answer << 8 & 0xff00)

        return answer


class PingSocket(object):
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)


class PingApp(object):
    def __init__(self):
        self.socket = PingSocket()


class PingClient(PingApp):
    def __init__(self):
        super(PingClient, self).__init__()
        self.data = "test"

    def send(self, dest_ip):
        data = self.data


def show_usage():
    print(""" USAGE:
    pyping.py client
    pyping.py server""")
    exit()

if __name__ == '__main__':
    try:
        mode = sys.argv[1]
    except IndexError:
        show_usage()
    if mode == 'client':
        print("client")

    elif mode == 'server':
        print("server")
    else:
        show_usage()

