#!/usr/bin/env python

import base64
import pickle
from optparse import OptionParser
import socket # I wish we could use https://docs.python.org/2.7/library/socketserver.html -- can we?
import sys
import threading

import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# see http://docopt.org/ for some info on command line argument formats
parser = OptionParser(usage="usage: %prog [options]")
parser.add_option("-s", "--server", action="store", type="string", dest="server_host",
                  default="localhost", help="server hostname/IP (defaults to localhost)")
parser.add_option("-p", "--port", action="store", type="int", dest="server_port",
                  default=8888, help="server port (defaults to 8888)")

aes_key = b'01234567890123456789012345678901'
hmac_key = b'12345678901234567890123456789012'


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
            if len(chunk) == 0:     # recv returns nothing when the client connection is closed
                break               # (client closes when finished sending)

        joined = ''.join(chunks)
        print "got message: {}".format(joined)
        parts = joined.split(".")
        # format: <base64 encoded encrypted payload>.<base64 encoded encryption IV>.<base64 encoded HMAC signature>
        # signature includes encrypted payload and IV (see below/client.py), general format inspired by JSON Web Tokens

        if len(parts) != 3:
            print "invalid received message; should be dot-separated and have three parts"
            print "received message: %{}s".format(joined)
            return
        else:
            try:
                payload_encrypted = base64.b64decode(parts[0])
                iv = base64.b64decode(parts[1])
                signature = base64.b64decode(parts[2])
            except TypeError:
                print "error decoding base64 data"
                return

            h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
            try:
                h.update(payload_encrypted)
                h.update(iv)
                h.verify(signature)
            except cryptography.exceptions.InvalidSignature:
                print "invalid signature for received message"
                return

            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            payload_decrypted_padded = decryptor.update(payload_encrypted) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            payload_pickled = unpadder.update(payload_decrypted_padded) + unpadder.finalize()
            try:
                payload = pickle.loads(payload_pickled)
            except:
                print "error unpickling decrypted data"
                return

            print "payload recieved: {}".format(payload)

            if "type" in payload and "content" in payload:
                if payload["type"] == "file":
                    if "filename" in payload:
                        # replace slashes with underscores as client may send full path
                        filename_no_slashes = payload["filename"].replace("/", "_")
                        with open(filename_no_slashes, "w") as f:
                            f.write(payload["content"])
                            f.close()
                    else:
                        print "payload is file type but missing filename"
                        return
                elif payload["type"] == "message":
                    print "message recieved: {}".format(payload["content"])
                else:
                    print "payload type neither message nor file?!"
                    return
            else:
                print "payload missing some fields, must have content and type at minimum"


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