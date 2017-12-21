#    CryptoPing: CryptoPing is python tool to send and receive encrypted messages/files over ICMP protocol.
#    Copyright (C) 2017 Tanel Peep
#
#
#    Based on ping.py package by George Notaras
#    http://www.g-loaded.eu/2009/10/30/python-ping/
#
#    Based on icmp.py package by Daniel Vidal de la Rubia
#    https://github.com/Vidimensional/Icmp-File-Transfer
#
#    Based on aioping package by Anton Belousov
#    https://github.com/stellarbit/aioping
#
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program. If not, see <http://www.gnu.org/licenses/>.


import sys
import asyncio
import struct
import time
import functools
import socket
from aioconsole import ainput
import async_timeout

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0

proto_icmp = socket.getprotobyname("icmp")


if sys.platform == "win32":
    # On Windows, the best timer is time.clock()
    default_timer = time.clock
else:
    # On most other platforms the best timer is time.time()
    default_timer = time.time


class PingPacket(object):
    def __init__(self, packet_seq, packet_type=None, message=None, packet=None):
        """
        Create and read ICMP packet
        """
        if packet:
            self.packet = packet
            self.data = ""
            self.read_packet()
            self.packet_type = packet_type
        else:
            self.buffer = 0
            self.packet = 0
            self.packet_type = packet_type
            self.message = message
            self.checksum = 0
            self.packet_seq = packet_seq
            self.create_packet()

    @staticmethod
    def create_checksum(buffer):
        """
        Creating packet checksum

        I'm not too confident that this is right but testing seems to
        suggest that it gives the same answers as in_cksum in ping.c.
        """
        sum = 0
        count_to = (len(buffer) / 2) * 2
        count = 0
        while count < count_to:
            this_val = ord(buffer[count + 1]) * 256 + ord(buffer[count])
            sum = sum + this_val
            sum = sum & 0xffffffff  # Necessary?
            count = count + 2
        if count_to < len(buffer):
            sum = sum + ord(buffer[len(buffer) - 1])
            sum = sum & 0xffffffff  # Necessary?
        sum = (sum >> 16) + (sum & 0xffff)
        sum = sum + (sum >> 16)
        answer = ~sum
        answer = answer & 0xffff
        # Swap bytes. Bugger me if I know why.
        answer = answer >> 8 | (answer << 8 & 0xff00)
        return answer

    def create_packet(self):
        """
        Create and return ICMP packet
        """
        # Make a dummy header with a 0 checksum.
        # Header is type (8), code (8), checksum (16), id (16), sequence (16)
        header = struct.pack('bbHHh', self.packet_type, 0, 0, 1, self.packet_seq)

        data = self.message
        if len(data) % 2 != 0:
            data += " "

        headdata = header.decode("utf-8")+data

        # Calculate the checksum on the data and the dummy header.
        my_checksum = PingPacket.create_checksum(headdata)

        # Now that we have the right checksum, we put that in. It's just easier
        # to make up a new header than to stuff it into the dummy.
        header = struct.pack('bbHHh', self.packet_type, 0, socket.htons(my_checksum), 1, self.packet_seq)
        self.packet = header + bytes(data, 'utf-8')

    def read_packet(self):
        """
        Read and return ICMP packet data
        """
        # Packet header size
        offset = 20

        # Recorded packet
        rec_packet = self.packet

        # Reading ICMP header
        icmp_header = rec_packet[offset:offset + 8]

        # Unpack ICMP header
        icmp_header = struct.unpack('bbHHh', icmp_header)

        # Data offset
        data_offset = len(rec_packet) - len(icmp_header)

        # Reading data
        data = rec_packet[offset + 8:offset + 8 + data_offset]

        # Unpack data
        payload_fmt = '%ds' % (len(data))
        data = struct.unpack(payload_fmt, data)

        # Decode data to string
        self.data = data[0].decode("utf-8")


class PingSocket(object):
    def __init__(self):
        """
        Create ICMP socket to send and recv packets
        """
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.socket.setblocking(False)
        self.id = 256

    def socket_sendto(self, dest_ip, packet, future):
        """
        Sending ICMP packet out of socket
        :param dest_ip:
        :param packet:
        :param future:
        :return:
        """
        self.socket.sendto(packet, dest_ip)
        asyncio.get_event_loop().remove_writer(self.socket)
        future.set_result(None)

    async def sendto_socket(self, dest_addr, id_, timeout, family, message, packet_type):
        """
        Sending ICMP packet to socket
        :param dest_addr:
        :param id_:
        :param timeout:
        :param family:
        :param message:
        :param packet_type:
        :return:
        """
        future = asyncio.get_event_loop().create_future()
        packet = PingPacket(packet_seq=id_,
                            message=message,
                            packet_type=packet_type)
        callback = functools.partial(self.socket_sendto,
                                     packet=packet.packet,
                                     dest_ip=dest_addr,
                                     future=future)
        asyncio.get_event_loop().add_writer(self.socket, callback)
        await future


class PingMessage(object):
    def __init__(self):
        """
        Specifying server and client data
        """
        self.mode = ""

    def received_from(self):
        """
        Specify packet sender
        :return:
        """
        if self.mode == "server":
            return "client"
        elif self.mode == "client":
            return "server"

    def is_recv_message(self, message):
        """
        Checking that received ICMP packet contains message
        :param message:
        :return:
        """
        if message[0:6] == self.received_from() and len(message) <= 8:
            return True
        else:
            return False

    def is_recv_data(self, message):
        """
        Checking that received ICMP packet contains right data value (client or server)
        :param message:
        :return:
        """
        if message[0:6] == self.received_from() and len(message) > 8:
            return True
        else:
            return False

    def print_message(self, message):
        """
        Printing out received and sent messages
        :param message:
        :return:
        """
        if len(message) > 7:
            direction = ""
            if self.mode == message[0:6]:
                direction = "sent"
            elif self.mode != message[0:6]:
                direction = "recv"
            print(direction + '(' + message[0:6] + '):' + message[7:len(message)])


class PingApp(object):
    def __init__(self):
        """
        SuperClass for Client and Server.
        Main App for sending and receiving packets
        """
        self.socket = PingSocket()
        self.timeout = 10
        self.ping_message = PingMessage()
        self.message_head = ""
        self.message_text = ""
        self.message = "test1234"
        self.packet_seq = 1

    def __enter__(self):
        return self

    async def cli_input(self):
        """
        Command line input
        :return:
        """
        while True:
            self.message_text = await ainput("")
            self.message = self.message_head + self.message_text
            if len(self.message) % 2 != 0:
                self.message += " "


class PingClient(PingApp):
    def __init__(self):
        """
        Client SubClass for PingAPP.
        Client App for sending and receiving packets
        """
        super(PingClient, self).__init__()
        self.packet_type = ICMP_ECHO_REQUEST
        self.message_head = "client:"
        self.ping_message.mode = "client"

    async def comm(self, dest_addr):
        """
        Method for communication (send and receive)
        :param dest_addr:
        :return:
        """
        loop = asyncio.get_event_loop()
        info = await loop.getaddrinfo(dest_addr, 0)
        family = info[0][0]
        addr = info[0][4]

        my_id = 1

        while True:
            sent_message = await self.send(addr, my_id, family, self.message)
            await self.recv(sent_message)

            await asyncio.sleep(2)

    async def send(self, dest_addr, my_id, family, message):
        """
        Sending ICMP packet to socket
        :param dest_addr:
        :param my_id:
        :param family:
        :param message:
        :return:
        """
        self.message = "client:"
        await self.socket.sendto_socket(dest_addr, my_id,
                                        self.timeout, family,
                                        message=message,
                                        packet_type=self.packet_type)
        if not self.ping_message.is_recv_data(message):
            self.ping_message.print_message(message)
        return message

    async def recv(self, sent_message):
        """
        Receive ICMP packet from socket
        :param sent_message:
        :return:
        """
        loop = asyncio.get_event_loop()
        timeout = 10

        try:
            with async_timeout.timeout(timeout):
                while True:

                    rec_packet = await loop.sock_recv(self.socket.socket, 1024)
                    data = PingPacket(1, packet=rec_packet)
                    if self.ping_message.is_recv_data(data.data):
                        self.ping_message.print_message(data.data)
                        return
                    elif self.ping_message.is_recv_message(data.data):
                        return
        except asyncio.TimeoutError:
            print("Ping timeout")


class PingServer(PingApp):
    def __init__(self):
        """
        Server SubClass for PingApp.
        Server App for sending and receiving packets
        """
        super(PingServer, self).__init__()
        self.packet_type = ICMP_ECHO_REPLY
        self.message_head = "server:"
        self.ping_message.mode = "server"

    async def comm(self, dest_addr):
        """
        Method for communication (send and receive)
        :param dest_addr:
        :return:
        """
        loop = asyncio.get_event_loop()
        info = await loop.getaddrinfo(dest_addr, 0)
        family = info[0][0]
        addr = info[0][4]

        my_id = 1

        while True:
            sent_message = await self.send(addr, my_id, family, self.message)
            await self.recv(sent_message)

    async def send(self, dest_addr, my_id, family, message):
        """
        Sending packet to socket
        :param dest_addr:
        :param my_id:
        :param family:
        :param message:
        :return:
        """
        self.message = "server:"
        await self.socket.sendto_socket(dest_addr, my_id, self.timeout, family, message=message, packet_type=self.packet_type)
        if not self.ping_message.is_recv_data(message):
            self.ping_message.print_message(message)

    async def recv(self, sent_message):
        """
        Receive packet from socket
        :param sent_message:
        :return:
        """
        loop = asyncio.get_event_loop()
        timeout = 10

        try:
            with async_timeout.timeout(timeout):
                while True:
                    rec_packet = await loop.sock_recv(self.socket.socket, 1024)
                    time_received = default_timer()
                    try:
                        data = PingPacket(1, packet=rec_packet)
                        if self.ping_message.is_recv_data(data.data):
                            self.ping_message.print_message(data.data)
                            return
                        elif self.ping_message.is_recv_message(data.data):
                            return
                    except Exception:
                        pass
        except asyncio.TimeoutError:
            print("Ping timeout")


class PingMode(object):
    def __init__(self):
        """
        Initialize App in Client or Server mode
        """
        self.dest = ""
        self.loop = asyncio.get_event_loop()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        print("")


class PingModeClient(PingMode):
    def __init__(self):
        """
        Client Mode subclass
        """
        super(PingModeClient, self).__init__()
        self.client = PingClient()

    def init(self, dest_addr):
        """
        Initialize Client App tasks
        :param dest_addr:
        :return:
        """
        self.loop.create_task(self.client.cli_input())
        self.loop.create_task(self.client.comm(dest_addr=dest_addr))
        self.loop.run_forever()


class PingModeServer(PingMode):
    def __init__(self):
        """
        Server Mode subclass
        """
        super(PingModeServer, self).__init__()
        self.server = PingServer()

    def init(self, dest_addr):
        """
        Initialize Server App tasks
        :param dest_addr:
        :return:
        """
        self.loop.create_task(self.server.cli_input())
        self.loop.create_task(self.server.comm(dest_addr=dest_addr))
        self.loop.run_forever()


def show_usage():
    """
    Application usage
    :return:
    """
    print("USAGE:\n"
          "    pyping.py client <destination IP>\n"
          "    pyping.py server <local listening IP>\n"
          "    ")
    exit()


if __name__ == '__main__':
    """
    Main function for starting App.
    
    Checking command line arguments.
    """
    arg = ""
    try:
        arg = sys.argv[1]
    except IndexError:
        show_usage()

    dst_addr = ""
    lcl_addr = ""

    if arg == 'client':
        try:
            dst_addr = sys.argv[2]
        except ValueError:
            show_usage()

        with PingModeClient() as client:
            client.init(dest_addr=dst_addr)

    elif arg == 'server':
        try:
            lcl_addr = sys.argv[2]
        except ValueError:
            show_usage()
        with PingModeServer() as server:
            server.init(dest_addr=lcl_addr)

    else:
        show_usage()
