from base64 import b64decode
from socketserver import BaseRequestHandler, ThreadingTCPServer
import os
import struct
from icecream import ic
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad


with open('../test/main', 'rb') as fh:
    main_bin = fh.read()


class RequestHandler(BaseRequestHandler):
    def recv_until(self, until: bytes):
        """Helper function to receive until a specific char is reached"""
        if not isinstance(until, bytes):
            raise Exception('"until" parameter should be a bytes object')

        buffer = b'' # type: bytes
        while not buffer.endswith(until):
            buffer += self.request.recv(1)
        return buffer[:-len(until)]

    def recv_until_close(self):
        """Helper function to receive until a socket is closed"""
        buffer = b'' # type: bytes
        while True:
            chunk = self.request.recv(4096)
            if len(chunk) == 0:
                return buffer
            else:
                buffer += chunk

    def recv_line(self):
        """Helper function to receive a line - will strip the newline off the end"""
        return self.recv_until(b'\n').strip()

    def recv_count(self, n: int):
        """Helper function to recv n bytes or return None if EOF is hit"""
        buffer = b''
        while len(buffer) < n:
            packet = self.request.recv(n - len(buffer))
            if not packet:
                return None
            buffer += packet
        return buffer

    def sendline(self, line: str):
        assert isinstance(line, str)
        return self.send(f'{line}\n'.encode())

    def send(self, data: bytes):
        self.request.sendall(data)

    def close(self):
        self.request.close()

    def handle(self):
        print('Sending...')

        # Recieve the public key from the client
        pubkey_len_buf = self.recv_count(4)
        if pubkey_len_buf is None:
            raise Exception('getting n_len_buf failed')
        pubkey_len = struct.unpack('<I', pubkey_len_buf)[0]
        pubkey_buf = self.recv_count(pubkey_len)
        if pubkey_buf is None:
            raise Exception('getting n_buf failed')
        pubkey = RSA.import_key(pubkey_buf)

        # Encrypt the main binary with AES
        aes_key = os.urandom(32)
        aes_iv = os.urandom(16)
        aes = AES.new(aes_key, AES.MODE_CBC, aes_iv)
        main_bin_encrypt = aes.encrypt(pad(main_bin, 16))
        ic(len(main_bin))
        ic(len(main_bin_encrypt))

        # Encrypt and send the AES key with the server's public key (send the iv in plain)
        rsa = PKCS1_OAEP.new(pubkey)
        aes_key_enc = rsa.encrypt(aes_key)
        self.send(b''.join([
            struct.pack('<I', len(aes_key_enc)),
            aes_key_enc,
            aes_iv,
            struct.pack('<I', len(main_bin_encrypt)),
            main_bin_encrypt, # Send encrypted binary
        ]))
        self.recv_until_close()
        print('Sent :)')


def main():
    # Change dir to scripts dir
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)
    os.chdir(dname)

    # Start the server
    ThreadingTCPServer.allow_reuse_address = True
    ThreadingTCPServer.timeout = 10
    server = ThreadingTCPServer(("0.0.0.0", 1337), RequestHandler)
    server.serve_forever()


if __name__ == '__main__':
    main()
