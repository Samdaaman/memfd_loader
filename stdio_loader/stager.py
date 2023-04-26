import os
import struct
from nacl.public import Box, PublicKey, PrivateKey
import subprocess


def main():
    # Change dir to scripts dir
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)
    os.chdir(dname)

    with open('../test/main', 'rb') as fh:
        main_bin = fh.read()

    proc = subprocess.Popen(['./main'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    sk_bob = PrivateKey.generate()
    pk_bob = sk_bob.public_key
    pk_alice = PublicKey(recv_count(proc, PublicKey.SIZE))
    box = Box(sk_bob, pk_alice)
    encypt_result = box.encrypt(main_bin) # main_bin_enc starts with the nonce (24 bytes)
    nonce = encypt_result[:Box.NONCE_SIZE]
    main_bin_enc = encypt_result[Box.NONCE_SIZE:]

    proc.stdin.write(b''.join([
        pk_bob.encode(), # 32
        nonce,
        struct.pack('<I', len(main_bin_enc)), # 4
        main_bin_enc, # +32-16
    ]))

    print('Sent executable')
    proc.wait()
    print('Terminated :)\n')


def recv_count(proc: subprocess.Popen, n: int):
    """Helper function to recv n bytes or return None if EOF is hit"""
    buffer = b''
    while len(buffer) < n:
        packet = proc.stdout.read(n - len(buffer))
        if not packet:
            raise Exception('read failed')
        buffer += packet
    return buffer


if __name__ == '__main__':
    main()
