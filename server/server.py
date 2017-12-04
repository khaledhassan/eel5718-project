#!/usr/bin/env python

import pickle
from optparse import OptionParser
import socket # I wish we could use https://docs.python.org/2.7/library/socketserver.html -- can we?
import sys
import threading

# see http://docopt.org/ for some info on command line argument formats
parser = OptionParser(usage="usage: %prog [options]")
parser.add_option("-s", "--server", action="store", type="string", dest="server_host",
                  default="localhost", help="server hostname/IP (defaults to localhost)")
parser.add_option("-p", "--port", action="store", type="int", dest="server_port",
                  default=8888, help="server port (defaults to 8888)")


class HandlerThread(threading.Thread):
    def __init__(self, clientsocket):
        threading.Thread.__init__(self)
        self.clientsocket = clientsocket

    def run(self):
        print "running handler thread"
        chunks = []
        while True:
            chunk = self.clientsocket.recv(2048)
            chunks.append(chunk)
            if len(chunk) == 0:
                break

        pickled = ''.join(chunks)
        data = pickle.loads(pickled)
        print data

def main():
    (options, args) = parser.parse_args()
    print options

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print "listening for connections on {}:{}".format(options.server_host, options.server_port)
        s.bind((options.server_host, options.server_port))  # double parenthesis to make it a tuple?
        s.listen(5) # 5 = backlog, number of connections allowed to be waiting to connect; 0-5, which is best?

        while True:
            (clientsocket, address) = s.accept()
            print "got connection from {}".format(address)
            t = HandlerThread(clientsocket)
            t.start()


    except socket.error as e:
        print "socket error: {}".format(e)


if __name__ == "__main__":
    main()