#!/usr/bin/env python

import pickle
from optparse import OptionParser
import socket
import sys

# see http://docopt.org/ for some info on command line argument formats
parser = OptionParser(usage="usage: %prog [options] (-m | -f FILE)")
parser.add_option("-s", "--server", action="store", type="string", dest="server_host",
                  default="localhost", help="server hostname/IP (defaults to localhost)")
parser.add_option("-p", "--port", action="store", type="int", dest="server_port",
                  default=8888, help="server port (defaults to 8888)")
# -m flag sets "file_mode" to False, otherwise it's True, and we expect to see a filename in file_to_encrypt
# if no such file is found, print usage instructions
parser.add_option("-m", "--message", action="store_false", dest="file_mode",
                  default=True, help="will read a message from stdin (until EOF)")
parser.add_option("-f", "--file", action="store", type="string", dest="file_to_encrypt",
                  metavar="FILE", help="name of file to encrypt")


def main():
    (options, args) = parser.parse_args()
    print options

    if options.file_to_encrypt is None and options.file_mode is True:
        parser.error("did not specify filename or -m/--message flag")

    if options.file_mode is True:
        with open(options.file_to_encrypt) as f:
            message = f.read()
    else:
        sys.exit("TODO: message mode to be implemented")

    try:
        print "opening connection to {} port {}".format(options.server_host, options.server_port)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((options.server_host, options.server_port))  # double parenthesis to make it a tuple?

        data_type = "file" if options.file_mode else "message"
        data = {"type": data_type, "content": message}
        data_pickled = pickle.dumps(data)
        print "sending data"
        s.send(data_pickled)
        s.shutdown() # according to <https://docs.python.org/2.7/howto/sockets.html> you should shutdown before closing
        s.close() # we close the connection in order to signal to the other side that we're finished
        print "connection closed"
    except socket.error as e:
        print "socket error: {}".format(e)

if __name__ == "__main__":
    main()