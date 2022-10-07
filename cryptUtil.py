import protocol
import os
from Crypto.Cipher import AES



def generateAESKey():
    return os.urandom(protocol.AES_KEY_SIZE)


def encryptWithPublicKey(content, publicKey):
    return content
    pass

def decrypt(buffer, AESKey):
    iv = b'\0' * protocol.AES_KEY_SIZE  # Default zero
    cipher = AES.new(os.urandom(protocol.AES_KEY_SIZE), AES.MODE_CBC, iv)
    decoded = cipher.decrypt(buffer)
    #decoded = bytes(decoded).decode("utf-8", 'ignore')