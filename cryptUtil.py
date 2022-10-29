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
        iv = b'\0' * AES.block_size  # Default zero
        self.cipher = AES.new(AESKey, AES.MODE_CBC, iv)

    #Get number of bytes to decrypt, from total bytes (must be a multiple of block size)
    def getBytesToDecrypt(self, totalBytes):
        return (totalBytes // AES.block_size) * AES.block_size

    #Decrypt data in buffer, with optional unpadding (should be true for the last block of the data)
    def decrypt(self, buffer, shouldUnpad = False):
        decrypted = self.cipher.decrypt(buffer)
        if shouldUnpad:
            decrypted = unpad(decrypted, AES.block_size)
        return decrypted