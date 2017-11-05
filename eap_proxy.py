#!/usr/bin/python3

import socket
from threading import Thread
import signal
import ctypes
import fcntl
import sys
import datetime

class Sniffer():
    # Structure for ifreq interface flags
    class ifreq(ctypes.Structure):
        _fields_ = [("ifr_ifrn", ctypes.c_char * 16),
                    ("ifr_flags", ctypes.c_short)]

    # On init, tries to create and bind to a raw socket on
    # each of the given interfaces, then sets promiscuous mode
    def __init__(self, iface_ont, iface_int):
        try:
            # Try to create and bind a socket on the ONT port
            self.s_ont=socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x888e))
            self.s_ont.bind((iface_ont,0))
        except socket.error as err:
            # Print error and exit with error code on failure
            print("Could not create socket on " + iface_ont + ": " + err.args[1])
            sys.exit(err.args[0])

        try:
            # Try to create and bind a socket on the INT port
            self.s_int=socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x888e))
            self.s_int.bind((iface_int,0))
        except socket.error as err :
            # Print error and exit with error code on failure
            print("Could not create socket on " + iface_ont + ": " + err.args[1])
            sys.exit(err.args[0])

        self.sniff = True
        # Put both interfaces into promsicuous mode
        self.promisc(self.s_ont, True)
        self.promisc(self.s_int, True)

    # Loop that listens for EAP type (0x888E) ether frames
    # arriving at the source socket (s_sock) and forwards
    # that data to the destination socket (d_sock).
    #
    # This function will be called by two seperate threads,
    # each listing on and sending to opposite sockets to
    # effectively create a bidirectional ethernet proxy.
    def proxy(self, s_sock, d_sock):
        src = s_sock.getsockname()[0]
        dst = d_sock.getsockname()[0]

        print( "Started sniffing for EAP packets on " + src)
        fails = 0
        while( self.sniff ):
            pkt = s_sock.recv(2048)
            d_sock.send(pkt)
            print( "Relayed " + str(len(pkt)) + " byte EAP packet from " + src + " => " + dst)

    # Put an interface into promiscuous mode
    def promisc(self, iface, tog):
        # Define consts
        IFF_PROMISC = 0x100
        SIOCGIFFLAGS = 0x8913
        SIOCSIFFLAGS = 0x8914

        # Create an instance of the defined ifreq structure
        ifr = self.ifreq()
        ifr.ifr_ifrn = iface.getsockname()[0].encode() # s_o/int
        fcntl.ioctl(iface.fileno(), SIOCGIFFLAGS, ifr)

        if tog: # Set promiscuous mode flag
            ifr.ifr_flags |= IFF_PROMISC
        else: # Unset promiscuous mode flag
            ifr.ifr_flags &= ~IFF_PROMISC
        # Apply flags to interface
        fcntl.ioctl(iface.fileno(), SIOCSIFFLAGS, ifr)


def signal_handler(signal, frame):
    print('Caught signal, exiting...')
    snf.sniff = False
    snf.promisc(snf.s_ont,False)
    snf.promisc(snf.s_int,False)

    for thread in threads:
        if thread.isAlive():
            try:
                thread._Thread__stop()
            except:
                print((str(thread.getName()) + ' could not be terminated'))
                sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    threads = []
    snf = Sniffer(sys.argv[1], sys.argv[2])

    threads.append(Thread(target=snf.proxy, args=[ snf.s_ont, snf.s_int ]))
    threads.append(Thread(target=snf.proxy, args=[ snf.s_int, snf.s_ont ]))

    for t in threads: t.start()
    signal.signal(signal.SIGINT, signal_handler)
    #signal.pause() # Not sure why this was here, prevented
                    # the program from exiting and would hang
                    # if running as a daemon, preventing restart.
                    # Maybe it was @todo for proper locking
                    # on the threads so it could survive the
                    # interfaces going up and down?
                    #
                    # In any case, I've changed the behavior
                    # to unset promisc and exit on any socket
                    # errors so systemd can reatart it and
                    # keep it running as a service.
