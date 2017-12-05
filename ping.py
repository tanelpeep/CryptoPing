import sys
import asyncio
import struct
import time
import functools
import socket
from aioconsole import ainput
import numpy as np
import random


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

        self.buffer = 0  # type: np.ndarray
        self.packet = 0
        self.checksum = 0
        self.packet_seq = packet_seq
        self.create_packet()

    def create_packet(self):
        icmp_type = ICMP_ECHO_REQUEST

        # Header is type (8), code (8), checksum (16), id (16), sequence (16)
        my_checksum = 0

        # Make a dummy header with a 0 checksum.
        header = struct.pack("BbHHh", icmp_type, 0, my_checksum, self.packet_seq, 1)
        bytes_in_double = struct.calcsize("d")
        data = "Testin"
        data = struct.pack("d", default_timer()) + data.encode("ascii")

        # Calculate the checksum on the data and the dummy header.
        self.buffer = header + data
        self.create_checksum()
        my_checksum = self.checksum

        # Now that we have the right checksum, we put that in. It's just easier
        # to make up a new header than to stuff it into the dummy.
        header = struct.pack(
            "BbHHh", icmp_type, 0, socket.htons(my_checksum), self.packet_seq, 1
        )
        self.packet = header + data

    def create_checksum(self):


        sum = 0
        count_to = (len(self.buffer) / 2) * 2
        count = 0

        while count < count_to:
            this_val = self.buffer[count + 1] * 256 + self.buffer[count]
            sum += this_val
            sum &= 0xffffffff  # Necessary?
            count += 2

        if count_to < len(self.buffer):
            sum += self.buffer[len(self.buffer) - 1]
            sum &= 0xffffffff  # Necessary?

        sum = (sum >> 16) + (sum & 0xffff)
        sum += sum >> 16
        answer = ~sum
        answer &= 0xffff

        # Swap bytes. Bugger me if I know why.
        answer = answer >> 8 | (answer << 8 & 0xff00)
        self.checksum = answer


def sendto_ready(packet, socket, future, dest):
    """
    :param packet:
    :param socket:
    :param future:
    :param dest:
    """
    socket.sendto(packet, dest)
    asyncio.get_event_loop().remove_writer(socket)
    future.set_result(None)


async def send_one_ping(my_socket, dest_addr, id, timeout, family):
    """
    Send one ping to the given >dest_addr<.
    :param my_socket:
    :param dest_addr:
    :param id:
    :param timeout:
    :return:
    """

    future = asyncio.get_event_loop().create_future()
    packet = PingPacket(packet_seq=id)
    callback = functools.partial(sendto_ready, packet=packet.packet, socket=my_socket, dest=dest_addr, future=future)
    asyncio.get_event_loop().add_writer(my_socket, callback)
    await future


async def ping(dest_addr, timeout=10):
        """
        Returns either the delay (in seconds) or raises an exception.
        :param dest_addr:
        :param timeout:
        """

        loop = asyncio.get_event_loop()
        info = await loop.getaddrinfo(dest_addr, 0)
        family = info[0][0]
        addr = info[0][4]

        if family == socket.AddressFamily.AF_INET:
            icmp = proto_icmp

        try:
            my_socket = socket.socket(family, socket.SOCK_RAW, icmp)
            my_socket.setblocking(False)

        except OSError as e:
            msg = e.strerror

            if e.errno == 1:
                # Operation not permitted
                msg += (
                    " - Note that ICMP messages can only be sent from processes"
                    " running as root."
                )

                raise OSError(msg)

            raise

        #my_id = int((id(timeout) * random.random()) % 65535)
        my_id = 256
        print(my_id)

        await send_one_ping(my_socket, addr, my_id, timeout, family)
        # delay = await receive_one_ping(my_socket, my_id, timeout)
        my_socket.close()

        # return delay


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
        mode = sys.argv[1]
    except IndexError:
        show_usage()

    if mode == 'client':
        loop = asyncio.get_event_loop()
        # loop.run_until_complete(ping("192.168.0.1", 10))
        # loop.create_task(some_coroutine())
        loop.create_task(ping("192.168.0.1", 10))
        loop.create_task(ping("192.168.0.19", 10))
        # loop.create_task(some_coroutine2())
        print("fdd")
        loop.create_task(ping("192.168.0.1", 10))
        loop.run_forever()
    elif mode == 'server':
        print("server")


