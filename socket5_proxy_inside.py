#coding:gbk
import socket, sys, select, SocketServer, struct, time
from encrypt import Encryptor
from mycrypto import crypt_aes
from mycrypto import rc4, encrypt, decrypt

class ThreadingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer): pass
class Socks5Server(SocketServer.StreamRequestHandler):

    remote_ip_port = ('45.78.35.158',1080)
    # remote_ip_port = ('192.168.100.242',1080)
    key = 'rp1qaz@WSX'
    crypto = Encryptor(key,'table')
    # crypto = crypt_aes(key+'000000')

    def handle_tcp(self, sock, remote):
        fdset = [sock, remote]
        while True:
            r, w, e = select.select(fdset, [], [])
            if sock in r:
                data = sock.recv(4096)
                if len(data) <= 0:
                    break
                remote.send(self.crypto.encrypt(data))
                # data = rc4(data,op='encode',public_key='rp1qaz@WSX')
                # length = str(len(data))
                # if len(length) < 4:
                #     length = (4 - len(length)) * '0' + length
                # print str(len(data)) + '>>>'
                # remote.send(encrypt('rp1qaz@WSX',length) + data)
            if remote in r:
                # length = remote.recv(4)
                # if not length:
                #     break
                # data = rc4(remote.recv(int(decrypt('rp1qaz@WSX',length))),op='decode',public_key='rp1qaz@WSX')
                data = remote.recv(4096)
                if not data:
                    break
                # print str(len(data)) + '<<<' + length
                sock.send(self.crypto.decrypt(data))

                # data = remote.recv(4096)
                # if len(data) <= 0:
                #     break
                # sock.send(data)

    def handle(self):
        try:
            print 'socks connection from ', self.client_address
            sock = self.connection
            # 1. Version
            test = sock.recv(262)
            sock.send(b"\x05\x00");
            # 2. Request
            data = sock.recv(4)
            mode = ord(data[1])
            addrtype = ord(data[3])
            if addrtype == 1:       # IPv4
                addr = socket.inet_ntoa(sock.recv(4))
            elif addrtype == 3:     # Domain name
                addr = sock.recv(ord(sock.recv(1)[0]))
            port = struct.unpack('>H', sock.recv(2))

            reply = b"\x05\x00\x00\x01"
            try:
                if mode == 1:  # 1. Tcp connect
                    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    # remote.connect((addr, port[0]))
                    remote.connect(self.remote_ip_port)
                    # ip_port_crypto = self.crypto.encrypt('%s,%d' % (addr, port[0]))
                    ip_port_crypto = rc4('%s,%d' % (addr, port[0]),op='encode',public_key='rp1qaz@WSX')
                    length = str(len(ip_port_crypto))
                    if len(length) < 4:
                        length = (4 - len(length)) * '0' + length
                    remote.send(length + ip_port_crypto)
                    print 'Tcp connect to', self.remote_ip_port
                    sync_result = remote.recv(1024)
                    if sync_result != '0':
                        reply = b"\x05\x01\x00\x01"
                else:
                    reply = b"\x05\x07\x00\x01" # Command not supported
                local = remote.getsockname()
                reply += socket.inet_aton(local[0]) + struct.pack(">H", local[1])
            except socket.error:
                # Connection refused
                reply = '\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00'
            sock.send(reply)
            # 3. Transfering
            if reply[1] == '\x00':  # Success
                if mode == 1:    # 1. Tcp connect
                    self.handle_tcp(sock, remote)
        except socket.error,e:
            print 'socket error: %s' % e
def main():
    server = ThreadingTCPServer(('0.0.0.0', 1080), Socks5Server)
    server.serve_forever()
if __name__ == '__main__':
    main()