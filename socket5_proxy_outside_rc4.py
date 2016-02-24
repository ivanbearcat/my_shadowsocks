import socket, sys, select, SocketServer, struct, time
from encrypt import Encryptor
from mycrypto import crypt_aes
from mycrypto import rc4, encrypt, decrypt

class ThreadingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer): pass
class Socks5Server(SocketServer.StreamRequestHandler):

    key = 'rp1qaz@WSX'
    crypto_table = Encryptor(key,'table')
#    crypto = crypt_aes(key+'000000')

    def handle_tcp(self, sock, remote):
        fdset = [sock, remote]
        while True:
            r, w, e = select.select(fdset, [], [])
            if sock in r:
                length = sock.recv(4)
                if not length:
                    break
                data = sock.recv(int(self.crypto_table.decrypt(length)))
#                data = sock.recv(4096)
                if len(data) <= 0:
                    break
                print str(len(data)) + '<<<'
               # print self.crypto_rc4_md5.decrypt(data)
                crypto_rc4_md5 = Encryptor(self.key,'rc4-md5')
                remote.send(crypto_rc4_md5.decrypt(data))
            if remote in r:
                data = remote.recv(4096)
                if len(data) <= 0:
                    break
               # print data
                crypto_rc4_md5 = Encryptor(self.key,'rc4-md5')
                data = crypto_rc4_md5.encrypt(data)
                length = str(len(data))
                if len(length) < 4:
                    length = (4 - len(length)) * '0' + length
#                print str(len(data)) + '>>>'
                sock.send(self.crypto_table.encrypt(length) + data)

#                data = remote.recv(4096)
#                if len(data) <= 0:
#                    break
#                sock.send(self.crypto.encrypt(data))

    def handle(self):
        try:
            print 'socks connection from ', self.client_address
            sock = self.connection
            # 1. Version
            length = sock.recv(4)
            remote_ip_port = rc4(sock.recv(int(length)),op='decode',public_key='rp1qaz@WSX')
            print remote_ip_port
            if remote_ip_port:
                remote_ip_port = (remote_ip_port.split(',')[0],int(remote_ip_port.split(',')[1]))
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect(remote_ip_port)
                print 'Tcp connect to', remote_ip_port
                sock.send('0')
                self.handle_tcp(sock, remote)
        except socket.error,e:
            print 'socket error: %s' % e
def main():
    server = ThreadingTCPServer(('0.0.0.0', 1080), Socks5Server)
    server.serve_forever()
if __name__ == '__main__':
    main()
