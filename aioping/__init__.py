#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import division, print_function

"""
    A pure python ping implementation using raw sockets.

    Compatibility:
        OS: Linux, Windows, MacOSX
        Python: 2.6 - 3.5

    Note that due to the usage of RAW sockets root/Administrator
    privileges are requied.

    Derived from ping.c distributed in Linux's netkit. That code is
    copyright (c) 1989 by The Regents of the University of California.
    That code is in turn derived from code written by Mike Muuss of the
    US Army Ballistic Research Laboratory in December, 1983 and
    placed in the public domain. They have my thanks.

    Copyright (c) Matthew Dixon Cowles, <http://www.visi.com/~mdc/>.
    Distributable under the terms of the GNU General Public License
    version 2. Provided with no warranties of any sort.

    asyncio enhancements (c) Matthias Urlichs <matthias@urlichs.de>
    Public interface adapted from code by Anton Belousov / Stellarbit LLC

    Website / bug tracker: https://github.com/M-o-a-T/aioping

"""

# This would enable extension into larger framework that aren't multi threaded.
import os
import sys
import time
import array
import fcntl
import socket
import struct
import signal
import asyncio

__all__ = "Ping Verbose VerbosePing ping verbose_ping simple_ping".split()

if __name__ == '__main__':
    import argparse


class NoAddressFound(OSError):
    pass


class ICMPError(OSError):
    pass


try:
    from _thread import get_ident
except ImportError:
    def get_ident():
        return 0

if sys.platform == "win32":
    # On Windows, the best timer is time.clock()
    default_timer = time.clock
else:
    # On most other platforms the best timer is time.time()
    default_timer = time.time

# ICMP parameters

ICMP_ECHOREPLY = 0  # Echo reply (per RFC792)
ICMP_ECHO = 8  # Echo request (per RFC792)
ICMP_ECHO_IPV6 = 128  # Echo request (per RFC4443)
ICMP_ECHO_IPV6_REPLY = 129  # Echo request (per RFC4443)
ICMP_MAX_RECV = 2048  # Max size of incoming buffer

MAX_SLEEP = 1000


class MStats2(object):

    def __init__(self):
        self._this_ip = '0.0.0.0'
        self._median_time = None
        self._total_time = 0
        self._pstdev_time = None
        self._frac_loss = None
        self._timing_list = []
        self._packets_sent = 0
        self._packets_rcvd = 0

        self.reset()

    def reset(self):
        self._timing_list = []
        self._packets_sent = 0
        self._packets_rcvd = 0

        self._reset_statistics()

    @property
    def this_ip(self):
        return self._this_ip

    @this_ip.setter
    def this_ip(self, value):
        self._this_ip = value

    @property
    def pkts_sent(self):
        return self._packets_sent

    @property
    def pkts_rcvd(self):
        return self._packets_rcvd

    @property
    def pkts_lost(self):
        return self._packets_sent - self._packets_rcvd

    @property
    def min_time(self):
        return min(self._timing_list) if self._timing_list else None

    @property
    def max_time(self):
        return max(self._timing_list) if self._timing_list else None

    @property
    def tot_time(self):
        # if self._total_time is None:
        #     self._total_time = sum(self._timing_list)
        # return self._total_time
        return sum(self._timing_list)

    def _get_mean_time(self):
        # if self._mean_time is None:
        #     if len(self._timing_list) > 0:
        #         self._mean_time = self.tot_time / len(self._timing_list)
        # return self._mean_time
        return self.tot_time / len(self._timing_list)

    mean_time = property(_get_mean_time)
    avrgTime = property(_get_mean_time)

    @property
    def median_time(self):
        if self._median_time is None:
            self._median_time = self._calc_median_time()
        return self._median_time

    @property
    def pstdev_time(self):
        """Returns the 'Population Standard Deviation' of the set."""
        # if self._pstdev_time is None:
        #     self._pstdev_time = self._calc_pstdev_time()
        # return self._pstdev_time
        return self._calc_pstdev_time()

    @property
    def frac_loss(self):
        # if self._frac_loss is None:
        #     if self.pkts_sent > 0:
        #         self._frac_loss = self.pkts_lost / self.pkts_sent
        # return self._frac_loss
        return self.pkts_lost / self.pkts_sent

    def packet_sent(self, n=1):
        self._packets_sent += n

    def packet_received(self, n=1):
        self._packets_rcvd += n

    def record_time(self, value):
        self._timing_list.append(value)
        self._reset_statistics()

    def _reset_statistics(self):
        self._total_time = None
        self._mean_time = None
        self._median_time = None
        self._pstdev_time = None
        self._frac_loss = None

    def _calc_median_time(self):
        n = len(self._timing_list)
        if n == 0:
            return None
        if n & 1 == 1:  # Odd number of samples? Return the middle.
            return sorted(self._timing_list)[n // 2]
        # Even number of samples? Return the mean of the two middle samples.
        else:
            half_n = n // 2
            return sum(sorted(self._timing_list)[half_n - 1:half_n + 1]) / 2

    def _calc_sum_square_time(self):
        mean = self.mean_time
        return sum(((t - mean) ** 2 for t in self._timing_list))

    def _calc_pstdev_time(self):
        pvar = self._calc_sum_square_time() / len(self._timing_list)
        return pvar ** 0.5


def _checksum(source_string):
    """
    A port of the functionality of in_cksum() from ping.c
    Ideally this would act on the string as a series of 16-bit ints (host
    packed), but this works.
    Network data is big-endian, hosts are typically little-endian
    """
    if len(source_string) % 2:
        source_string += "\x00"

    converted = array.array("H", source_string)
    if sys.byteorder == "big":
        converted.bytewap()
    val = sum(converted)

    val &= 0xffffffff  # Truncate val to 32 bits (a variance from ping.c, which
    # uses signed ints, but overflow is unlikely in ping)

    val = (val >> 16) + (val & 0xffff)  # Add high 16 bits to low 16 bits
    val += (val >> 16)  # Add carry from above (if any)
    answer = ~val & 0xffff  # Invert and truncate to 16 bits
    answer = socket.htons(answer)

    return answer


_next_id = 1


class Ping(object):
    def __init__(self, dest_ip=None,
                 hostname=None,
                 interval=1,
                 num_data_bytes=64,
                 stats=None,
                 ipv6=False,
                 verbose=True,
                 source_ip=None,
                 source_intf=None,
                 loop=None,
                 count=3,
                 timeout=5):
        self.dest_ip = dest_ip
        self.hostname = hostname
        self.interval = interval
        self.count = count
        self.timeout = timeout
        self.numDataBytes = num_data_bytes
        self.stats = stats
        self.ipv6 = ipv6
        self.verbose = verbose
        self.sourceIP = source_ip
        self.sourceIntf = source_intf
        self.loop = loop or asyncio.get_event_loop()

        self.ID = _next_id
        self.seqNumber = 0
        self.startTime = None
        self.queue = None

        self.socket = None

    def close(self):
        if self.socket is not None:
            self.loop.remove_reader(self.socket.fileno())
            self.socket.close()
            self.socket = None

    async def init(self, hostname=None):
        hostname = hostname or self.hostname
        self.dest_ip = None if hostname else self.dest_ip

        self.close()

        self.seqNumber = 0
        self.startTime = default_timer()
        self.queue = asyncio.Queue(loop=self.loop)

        global _next_id
        self.ID = _next_id

        # This is required to prevent the overflow of the 16-bit 'identification' bit.
        if _next_id == 65535:
            _next_id = 0
        else:
            _next_id += 1

        if self.dest_ip is None:
            if hostname is None:
                raise RuntimeError("You need to set either hostname or destIP")

            for info in (await self.loop.getaddrinfo(hostname, None)):
                if info[0] == socket.AF_INET6:
                    if self.ipv6 is False:
                        continue
                    self.ipv6 = True
                elif info[0] == socket.AF_INET:
                    if self.ipv6 is True:
                        continue
                    self.ipv6 = False
                else:
                    continue
                self.dest_ip = info[4][0]
                break
            else:
                raise NoAddressFound(hostname)

        if self.ipv6:
            self.socket = socket.socket(socket.AF_INET6, socket.SOCK_RAW,
                                        socket.getprotobyname("ipv6-icmp"))
            self.socket.setsockopt(socket.IPPROTO_IPV6,
                                   socket.IPV6_RECVHOPLIMIT, 1)
        else:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                        socket.getprotobyname("icmp"))

        if self.sourceIP is not None:
            self.socket.bind((self.sourceIP, 0))

        if self.sourceIntf is not None:
            try:
                so_bindtodevice = socket.SO_BINDTODEVICE
            except AttributeError:
                so_bindtodevice = 25

            self.socket.setsockopt(socket.SOL_SOCKET, so_bindtodevice,
                                   (self.sourceIntf + '\0').encode('utf-8'))

        if self.stats:
            self.stats.this_ip = self.dest_ip

        # Don't block on the socket
        flag = fcntl.fcntl(self.socket.fileno(), fcntl.F_GETFL)
        fcntl.fcntl(self.socket.fileno(), fcntl.F_SETFL, (flag | os.O_NONBLOCK))

        self.loop.add_reader(self.socket.fileno(), self._receive)

    async def single(self, timeout=None):
        """
        Fire off a single ping.
        Returns the answer's delay (in ms).
        """
        self._send()

        recv = self.queue.get()
        if timeout is None or timeout > self.timeout:
            timeout = self.timeout

        if timeout is not None:
            recv = asyncio.wait_for(recv, timeout, loop=self.loop)

        recv = await recv
        if isinstance(recv, Exception):
            raise recv

        recv_time, data_size, iph_src_ip, icmp_seq_number, iph_ttl = recv

        delay = recv_time - self.startTime - icmp_seq_number * self.interval
        await self.pinged(recvTime=recv_time, delay=delay,
                          host=self.resolve_host(iph_src_ip), seqNum=icmp_seq_number,
                          ttl=iph_ttl, size=data_size)

        return delay

    async def pinged(self, recvTime, delay, host, seqNum, ttl, size):
        """Hook to catch a successful ping"""
        pass

    async def run(self):
        """
        Send .count ping to .destIP with the given delay and timeout.

        To continuously attempt ping requests, set .count to zero.
        """

        assert self.interval > 0

        while not self.count or self.stats.pkts_rcvd < self.count:
            now = default_timer()
            delay1 = self.seqNumber * self.interval - (now - self.startTime)
            while (not self.count or self.seqNumber < self.count) and delay1 <= 0:
                self._send()
                delay1 += self.interval
            if self.count and self.seqNumber >= self.count:
                delay1 = None
            if self.timeout is not None:
                delay2 = self.startTime + self.timeout - now
                if delay2 < 0:
                    break
                if delay1 is None or delay1 > delay2:
                    delay1 = delay2
            try:
                recv = self.queue.get()
                if delay1 is not None:
                    recv = asyncio.wait_for(recv, delay1,
                                            loop=self.loop)
                recv = await recv
                if isinstance(recv, Exception):  # error
                    raise recv
                recv_time, data_size, iph_src_ip, icmp_seq_number, iph_ttl = recv
                delay = recv_time - self.startTime - icmp_seq_number * self.interval
                await self.pinged(recvTime=recv_time, delay=delay,
                                  host=self.resolve_host(iph_src_ip), seqNum=icmp_seq_number,
                                  ttl=iph_ttl, size=data_size)

            except asyncio.TimeoutError:
                pass

        return self.stats.pkts_rcvd

    def resolve_host(self, iphSrcIP):
        """TODO: actually resolve this address"""
        return iphSrcIP

    def _send(self):
        """
        Send one ping to the given >destIP<.
        """

        # Header is type (8), code (8), checksum (16), id (16), sequence (16)
        # (numDataBytes - 8) - Remove header size from packet size
        my_checksum = 0

        # Make a dummy heder with a 0 checksum.
        if self.ipv6:
            header = struct.pack(
                "!BbHHh", ICMP_ECHO_IPV6, 0, my_checksum, self.ID, self.seqNumber
            )
        else:
            header = struct.pack(
                "!BBHHH", ICMP_ECHO, 0, my_checksum, self.ID, self.seqNumber
            )

        pad_bytes = []
        start_val = 0x42
        for i in range(start_val, start_val + (self.numDataBytes - 8)):
            pad_bytes += [(i & 0xff)]  # Keep chars in the 0-255 range

        data = bytearray(pad_bytes)

        # Calculate the checksum on the data and the dummy header.
        my_checksum = _checksum(header + data)  # Checksum is in network order

        # Now that we have the right checksum, we put that in. It's just easier
        # to make up a new header than to stuff it into the dummy.
        if self.ipv6:
            header = struct.pack(
                "!BbHHh", ICMP_ECHO_IPV6, 0, my_checksum, self.ID, self.seqNumber
            )
        else:
            header = struct.pack(
                "!BBHHH", ICMP_ECHO, 0, my_checksum, self.ID, self.seqNumber
            )

        packet = header + data

        self.socket.sendto(packet, (self.dest_ip, 0))  # Port number is irrelevant
        if self.stats is not None:
            self.stats.packet_sent()

        self.seqNumber += 1

    def _receive(self):
        """
        Receive the ping from the socket. Timeout = in ms
        """

        try:
            time_received = default_timer()

            # iphDestIP is the original address from 
            rec_packet, anc_data, flags, addr = self.socket.recvmsg(ICMP_MAX_RECV)
            if self.ipv6:
                icmp_header = rec_packet[0:8]
            else:
                icmp_header = rec_packet[20:28]

            icmp_type, icmp_code, icmp_checksum, icmp_packet_id, icmp_seq_number \
                = struct.unpack("!BBHHH", icmp_header)

            iph_dest_ip = ''
            if self.ipv6:
                iph_src_ip = addr[0]
                if icmp_type not in (ICMP_ECHO_IPV6, ICMP_ECHO_IPV6_REPLY):
                    iph_dest_ip = socket.inet_ntop(socket.AF_INET6,
                                                   rec_packet[32:48])
                iph_ttl = 0
                if len(anc_data) == 1:
                    cmsg_level, cmsg_type, cmsg_data = anc_data[0]
                    a = array.array("i")
                    a.frombytes(cmsg_data)
                    iph_ttl = a[0]
            else:
                ip_header = rec_packet[:20]
                iph_version, iph_type_of_svc, iph_length, iph_id, iph_flags, iph_ttl, \
                    iph_protocol, iph_checksum, iph_src_ip, iph_dest_ip = struct.unpack(
                        "!BBHHHBBHII", ip_header)

                iph_src_ip = socket.inet_ntop(socket.AF_INET,
                                              struct.pack("!I", iph_src_ip))

                if icmp_type not in (ICMP_ECHO, ICMP_ECHOREPLY):
                    iph_dest_ip = socket.inet_ntop(socket.AF_INET,
                                                   rec_packet[44:48])

            if icmp_type in (ICMP_ECHOREPLY, ICMP_ECHO_IPV6_REPLY):
                # Reply to our packet?
                if icmp_packet_id == self.ID:
                    data_size = len(rec_packet) - 28

                    if self.stats is not None:
                        self.stats.packet_received()
                        delay = time_received - self.startTime - icmp_seq_number * self.interval
                        self.stats.record_time(delay)

                    self.queue.put_nowait((time_received, (data_size + 8), iph_src_ip,
                                           icmp_seq_number, iph_ttl))

            elif icmp_type not in (ICMP_ECHO, ICMP_ECHO_IPV6) \
                    and iph_dest_ip == self.dest_ip:
                # TODO improve error reporting. XXX: need to re-use the
                # socket, otherwise we won't get host-unreachable errors.
                self.queue.put_nowait(ICMPError(icmp_type, icmp_code))

        except BaseException:
            self.loop.stop()
            raise

    def print_stats(self):
        """
        Show stats when pings are done
        """
        my_stats = self.stats
        if my_stats is None:
            return

        print("\n----%s PYTHON PING Statistics----" % my_stats.this_ip)

        print("%d packets transmitted, %d packets received, %0.1f%% packet loss"
              % (my_stats.pkts_sent, my_stats.pkts_rcvd, 100.0 * my_stats.frac_loss))

        if my_stats.pkts_rcvd > 0:
            print("round-trip (ms)  min/avg/max = %0.1f/%0.1f/%0.1f" % (
                my_stats.min_time * 1000, my_stats.avrgTime * 1000, my_stats.max_time * 1000
            ))
            print('                 median/pstddev = %0.2f/%0.2f' % (
                my_stats.median_time * 1000, my_stats.pstdev_time * 1000
            ))

        print('')
        return

    # noinspection PyUnusedLocal
    def _signal_handler(self, signum, frame):
        """ Handle exit via signals """
        self.print_stats()
        print("(Terminated with signal %d)" % signum)
        sys.exit(0)

    def add_signal_handler(self):
        signal.signal(signal.SIGINT, self._signal_handler)
        if hasattr(signal, "SIGBREAK"):  # Handle Ctrl-Break /Windows/
            signal.signal(signal.SIGBREAK, self._signal_handler)


class Verbose(object):
    """A mix-in class to print a message when each ping os received"""

    async def pinged(self, **kw):
        # noinspection PyUnresolvedReferences
        await super().pinged(**kw)
        print("%d bytes from %s: icmp_seq=%d ttl=%d time=%.2f ms" % (
            kw['size'], kw['host'], kw['seqNum'], kw['ttl'], kw['delay'] * 1000))


class VerbosePing(Verbose, Ping):
    pass


async def ping(dest_addr, timeout=10, **kw):
    """
    Returns either the delay (in seconds) or raises an exception.
    @dest_addr: host name or IP address to ping.
    @timeout: maximum delay.
    """
    _ping = Ping(dest_addr, **kw)
    await _ping.init()
    res = _ping.single()
    if timeout:
        res = asyncio.wait_for(res, timeout, loop=_ping.loop)
    res = await res
    _ping.close()
    return res


async def ping_stats(ip_addr: str = None, timeout=None, hostname: str = None, stats: MStats2 = None, **kwargs) -> MStats2:
    """Ping and return stats.

    :param ip_addr:
    :param timeout:
    :param hostname:
    :param stats: Stats object to update or None to create new.
    :param kwargs:
    :return:
    """
    stats = stats or MStats2()

    _ping = Ping(dest_ip=ip_addr, hostname=hostname, timeout=timeout, stats=stats, **kwargs)

    await _ping.init()
    # res = _ping.single(timeout=timeout)
    res = await _ping.run()

    if timeout:
        res = asyncio.wait_for(res, timeout, loop=_ping.loop)

    _ping.close()

    return stats


single_ping = ping


async def verbose_ping(dest_addr, verbose=True, want_stats=False, handle_signals=None, timeout=5, count=3, **kw):
    """
    Send @count ping to @destIP with the given @timeout, and display
    the result.

    To continuously attempt ping requests, set @count to zero.

    Installs a signal handler if @count is zero.
    Override this by setting @handle_signals to false.

    Returns the ping statistics object if @stats is true. Otherwise,
    the result is True if there was at least one valid echo.
    """
    if 'stats' not in kw:
        kw['stats'] = MStats2()

    _ping = VerbosePing(verbose=verbose, timeout=timeout, count=count, **kw)

    if handle_signals is None:
        handle_signals = (not count)

    if handle_signals:
        _ping.add_signal_handler()

    await _ping.init(dest_addr)
    res = await _ping.run()

    if verbose:
        _ping.print_stats()

    _ping.close()

    if want_stats:
        return kw['stats']

    return res


if __name__ == "__main__":
    from pprint import pprint

    _loop = asyncio.get_event_loop()

    for p in (ping, verbose_ping):
        tasks = []
        for host in "heise.de google.com not-available.invalid 192.168.1.111".split(" "):
            tasks.append(asyncio.ensure_future(p(host)))
        pprint(_loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True)))
