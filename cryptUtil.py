import protocol
import os
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import unpad
import base64

#Generate random AES key
def generateAESKey():
    return os.urandom(protocol.AES_KEY_SIZE)

#Returns content encrypted using RSA with publicKey
def encryptWithPublicKey(content, publicKey):
    key = RSA.importKey(publicKey)
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(content)

class AESDecrypt:
    def __init__(self, AESKey):
        iv = b'\0' * protocol.AES_KEY_SIZE  # Default zero
        self.cipher = AES.new(AESKey, AES.MODE_CBC, iv)

    def getBytesToDecrypt(self, totalBytes):
        return (totalBytes // AES.block_size) * AES.block_size

    def decrypt(self, buffer):
        decrypted = self.cipher.decrypt(buffer)
        return decrypted
        return unpad(decrypted, AES.block_size)