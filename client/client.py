#!/usr/bin/env python

import base64
import pickle
from optparse import OptionParser
import os
import socket
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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

aes_key = b'01234567890123456789012345678901'
hmac_key = b'12345678901234567890123456789012'


def main():
    (options, args) = parser.parse_args()

    if options.file_to_encrypt is None and options.file_mode is True:
        parser.error("did not specify filename or -m/--message flag")

    if options.file_mode is True:
        with open(options.file_to_encrypt) as f:
            message = f.read()
    else:
        message = sys.stdin.read()

    try:
        print "opening connection to {} port {}".format(options.server_host, options.server_port)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((options.server_host, options.server_port))  # double parenthesis to make it a tuple?

        data_type = "file" if options.file_mode else "message"
        data = {"type": data_type, "content": message}
        if options.file_mode:
            data["filename"] = options.file_to_encrypt

        data_pickled = pickle.dumps(data)

        # encrypt data
        print "initializing crypto"
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        print "padding data"
        data_pickled_padded = padder.update(data_pickled) + padder.finalize()
        print "encrypting data"
        data_encrypted = encryptor.update(data_pickled_padded) + encryptor.finalize()

        # create signature
        print "creating signature"
        h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
        h.update(data_encrypted)
        h.update(iv)
        signature = h.finalize()

        print "sending data"
        s.sendall("{}.{}.{}".format(base64.b64encode(data_encrypted), base64.b64encode(iv), base64.b64encode(signature)))

        # according to <https://docs.python.org/2.7/howto/sockets.html> you should shutdown before closing
        s.shutdown(socket.SHUT_WR)
        s.close() # we close the connection in order to signal to the other side that we're finished
        print "connection closed"
    except socket.error as e:
        print "socket error: {}".format(e)


if __name__ == "__main__":
    main()
