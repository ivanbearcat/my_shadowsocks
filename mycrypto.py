#/usr/bin/python
#coding=utf-8
import sys,os,hashlib,time,base64
import base64
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex

class crypt_aes():
    def __init__(self,key):
        self.key = key
        self.mode = AES.MODE_CBC

    #加密函数，如果text不足16位就用空格补足为16位，
    #如果大于16当时不是16的倍数，那就补足为16的倍数。
    def encrypt_aes(self,text):
        cryptor = AES.new(self.key,self.mode,b'0000000000000000')
        #这里密钥key 长度必须为16（AES-128）,
        #24（AES-192）,或者32 （AES-256）Bytes 长度
        #目前AES-128 足够目前使用
        length = 16
        count = len(text)
        if count < length:
            add = (length-count)
            #\0 backspace
            text = text + ('\0' * add)
        elif count > length:
            add = (length-(count % length))
            text = text + ('\0' * add)
        self.ciphertext = cryptor.encrypt(text)
        #因为AES加密时候得到的字符串不一定是ascii字符集的，输出到终端或者保存时候可能存在问题
        #所以这里统一把加密后的字符串转化为16进制字符串
        return b2a_hex(self.ciphertext)

    #解密后，去掉补足的空格用strip() 去掉
    def decrypt_aes(self,text):
        cryptor = AES.new(self.key,self.mode,b'0000000000000000')
        plain_text  = cryptor.decrypt(a2b_hex(text))
        return plain_text.rstrip('\0')

def encrypt(key,text):
    l1 = []
    l2 = []
    a = 0
    if len(key) > len(text):
        length = len(text)
    else:
        length = len(key)
    for i in key:
        a += ord(i)
    num = a % len(key)
    if num == 0:
        num = 7
    for i in text:
        l1.append(ord(i) + num)
    for i in range(len(l1)/2):
        l1[i],l1[-(i+1)] = l1[-(i+1)],l1[i]
    for i in range(length):
        l1[i] += num
    for i in l1:
        l2.append(chr(i))
    t = ''.join(l2)
    return t

def decrypt(key,text):
    l1 = []
    l2 = []
    a = 0
    if len(key) > len(text):
        length = len(text)
    else:
        length = len(key)
    for i in key:
        a += ord(i)
    num = a % len(key)
    if num == 0:
        num = 7
    for i in text:
        l1.append(ord(i))
    for i in range(length):
        l1[i] -= num
    for i in range(len(l1)/2):
        l1[i],l1[-(i+1)] = l1[-(i+1)],l1[i]
    for i in range(len(text)):
        l1[i] -= num
    for i in l1:
        l2.append(chr(i))
    t = ''.join(l2)
    return t

def strong_encrypt(key,text):
    data = base64.b64encode(text)
    data = encrypt(key,data)
    return data

def strong_decrypt(key,text):
    data = decrypt(key,text)
    missing_padding = 4 - len(data) % 4
    if missing_padding:
            data += b'='* missing_padding
    return base64.decodestring(data)


def rc4(string, op = 'encode', public_key = 'ddd', expirytime = 0):
    ckey_lenth = 4
    public_key = public_key and public_key or ''
    key = hashlib.md5(public_key).hexdigest()
    keya = hashlib.md5(key[0:16]).hexdigest()
    keyb = hashlib.md5(key[16:32]).hexdigest()
    keyc = ckey_lenth and (op == 'decode' and string[0:ckey_lenth] or hashlib.md5(str(time.time())).hexdigest()[32 - ckey_lenth:32]) or ''
    cryptkey = keya + hashlib.md5(keya + keyc).hexdigest()
    key_lenth = len(cryptkey)
    string = op == 'decode' and base64.b64decode(string[4:]) or '0000000000' + hashlib.md5(string + keyb).hexdigest()[0:16] + string
    string_lenth = len(string)
        
    result = ''
    box = list(range(256))
    randkey = []
        
    for i in xrange(255):
        randkey.append(ord(cryptkey[i % key_lenth]))
        
    for i in xrange(255):
        j = 0
        j = (j + box[i] + randkey[i]) % 256
        tmp = box[i]
        box[i] = box[j]
        box[j] = tmp
        
    for i in xrange(string_lenth):
        a = j = 0
        a = (a + 1) % 256
        j = (j + box[a]) % 256
        tmp = box[a]
        box[a] = box[j]
        box[j] = tmp
        result += chr(ord(string[i]) ^ (box[(box[a] + box[j]) % 256]))
    
    if op == 'decode':
        if (result[0:10] == '0000000000' or int(result[0:10]) - int(time.time()) > 0) and result[10:26] == hashlib.md5(result[26:] + keyb).hexdigest()[0:16]:
            return result[26:]
        else:
            return None
    else:
        return keyc + base64.b64encode(result)