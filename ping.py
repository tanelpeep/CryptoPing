import sys
import asyncio
import struct
import time
import functools
import socket
from aioconsole import ainput
import numpy as np
import select
import async_timeout
import random
import os


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
    def __init__(self, packet_seq):

        self.buffer = 0
        self.packet = 0
        self.checksum = 0
        self.packet_seq = packet_seq
        self.create_packet()

    @staticmethod
    def create_checksum(buffer):

        # I'm not too confident that this is right but testing seems to
        # suggest that it gives the same answers as in_cksum in ping.c.
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
        icmp_type = ICMP_ECHO_REQUEST

        # Header is type (8), code (8), checksum (16), id (16), sequence (16)
        my_checksum = 0

        # Make a dummy header with a 0 checksum.
        # Header is type (8), code (8), checksum (16), id (16), sequence (16)
        packet_id = int(1)
        header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, 0, packet_id, 2)
        #bytes_in_double = struct.calcsize("d")

        #data = 192 * 'Q'
        data = 'ICMP data text'
        #data = struct.pack("d", default_timer()) + data.encode("ascii")
        #buffer = header + data

        # Calculate the checksum on the data and the dummy header.
        #self.buffer = header + data
        #self.create_checksum()
        print(type(data))
        headdata = header.decode("utf-8")+data
        my_checksum = PingPacket.create_checksum(headdata)

        # Now that we have the right checksum, we put that in. It's just easier
        # to make up a new header than to stuff it into the dummy.
        header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0,
                             socket.htons(my_checksum), 1, 2)
        self.packet = header + bytes(data, 'utf-8')




class PingSocket(object):
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.socket.setblocking(False)
        self.id = 256

    def socket_sendto(self, dest_ip, packet, future):
        self.socket.sendto(packet, dest_ip)
        asyncio.get_event_loop().remove_writer(self.socket)
        future.set_result(None)

    async def sendto_socket(self, dest_addr, id_, timeout, family):
        future = asyncio.get_event_loop().create_future()
        packet = PingPacket(packet_seq=1)
        callback = functools.partial(self.socket_sendto, packet=packet.packet, dest_ip=dest_addr, future=future)
        asyncio.get_event_loop().add_writer(self.socket, callback)
        await future

    def socket_receieve(self, future):
        while True:

            r = select.select([self.socket], [], [])
            for i in r:
                print("dd")
                print(i), i.recvfrom(0)

        asyncio.get_event_loop().remove_writer(self.socket)
        future.set_result(None)

    async def receive_socket(self):
        future = asyncio.get_event_loop().create_future()
        callback = functools.partial(self.socket_receieve,future=future)
        asyncio.get_event_loop().add_writer(self.socket, callback)
        await future


class PingApp(object):
    def __init__(self):
        self.socket = PingSocket()
        self.timeout = 10
    def __enter__(self):
        return self

class PingClient(PingApp):
    def __init__(self):
        super(PingClient, self).__init__()

    async def send(self, dest_addr):
        loop = asyncio.get_event_loop()
        info = await loop.getaddrinfo(dest_addr, 0)
        family = info[0][0]
        addr = info[0][4]

        my_id = 256
        print(my_id)

        while True:
            await self.socket.sendto_socket(addr, my_id, self.timeout, family)
            await asyncio.sleep(2)
            await self.recv()


        #self.socket.socket.close()

    async def recv(self):

        loop = asyncio.get_event_loop()
        timeout = 10

        try:
            with async_timeout.timeout(timeout):
                while True:

                    rec_packet = await loop.sock_recv(self.socket.socket, 1024)
                    time_received = default_timer()

                    if self.socket.socket.family == socket.AddressFamily.AF_INET:
                        offset = 20
                    else:
                        offset = 0
                    #print(rec_packet[20:])
                    icmp_header = rec_packet[offset:offset + 8]
                    print(len(icmp_header))
                    icmp_header = struct.unpack('bbHHh', icmp_header)
                    #print(icmp_header[4])
                    data_offset = len(rec_packet) - len(icmp_header)
                    print(len(rec_packet[20:]))

                    header_fmt = 'bbHHh'
                    payload_fmt = '%ds' % (14)
                    print(payload_fmt)
                    #return rec_packet
                    #type, code, checksum, packet_id, sequence = struct.unpack(
                    #    "bbHHh", icmp_header
                    #)

                    data = rec_packet[offset + 8:offset + 8 + data_offset]
                    print(len(data))

                    data = struct.unpack(payload_fmt,data)
                    print(data[0])
                    #print(data.encode("utf-8"))
                    bytes_in_double = struct.calcsize("dddHHH")
                    #print(bytes_in_double)
                    #time_sent = struct.unpack("d", data)[0]
                    #print(time_sent)

                    #print(rec_packet)
                    #if packet_id == 256:

                     #   return time_received
        except asyncio.TimeoutError:
            return
            raise TimeoutError("Ping timeout")
        print(data2.encode("utf-8"))

class PingServer(PingApp):
    def __init__(self):
        super(PingServer, self).__init__()

    async def send(self):
        print("")

    async def recv(self):
        print("")

class PingMode(object):
    def __init__(self):
        self.dest = ""
        self.loop = asyncio.get_event_loop()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        print("")

class PingModeClient(PingMode):
    def __init__(self):
        super(PingModeClient, self).__init__()

    def init(self):
        # loop.run_until_complete(client.send("192.168.0.1"))
        # loop.create_task(some_coroutine())
        self.loop.create_task(PingClient().send('192.168.0.19'))
        #self.loop.create_task(PingClient().send('192.168.0.1'))
        # loop.create_task(print("test"))
        #self.loop.create_task(PingClient().send('192.168.0.1'))
        #self.loop.create_task(PingClient().recv())
        # loop.create_task(ping("192.168.0.1", 10))
        # loop.create_task(ping("192.168.0.19", 10))
        # loop.create_task(some_coroutine2())
        # loop.create_task(ping("192.168.0.1", 10))
        self.loop.run_forever()

class PingModeServer(PingMode):
    def __init__(self):
        super(PingModeServer, self).__init__()

    def init(self):
        self.loop.run_forever()

def show_usage():
    print(""" USAGE:
    pyping.py client
    pyping.py server""")
    exit()



async def some_coroutine():
    line = await ainput(">>> ")

async def some_coroutine2():
    await asyncio.sleep(10)
    print("testin")





if __name__ == '__main__':
    try:
        arg = sys.argv[1]
    except IndexError:
        show_usage()

    if arg == 'client':
        with PingModeClient() as client:
            client.init()

    elif arg == 'server':
        with PingModeServer() as server:
            server.init()


