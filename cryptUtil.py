import protocol
import os
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import unpad
import base64

def generateAESKey():
    return os.urandom(protocol.AES_KEY_SIZE)


def encryptWithPublicKey(content, publicKey):
    key = RSA.importKey(publicKey)
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(content)

def decrypt(buffer, AESKey):
    iv = b'\0' * protocol.AES_KEY_SIZE  # Default zero
    cipher = AES.new(AESKey, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(buffer), AES.block_size)