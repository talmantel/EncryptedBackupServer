import struct
from enum import Enum

SERVER_VERSION = 3

PACKET_SIZE = 1024

CLIENT_ID_SIZE = 16
NAME_SIZE = 255
PUBLIC_KEY_SIZE = 160
AES_KEY_SIZE = 16
VERSION_SIZE = 1
CODE_SIZE = 2
PAYLOAD_SIZE_SIZE = 4
CONTENT_SIZE_SIZE = 4
CHECKSUM_SIZE = 4


FILE_NAME_SIZE = 255
PATH_NAME_SIZE = 255

# Request Codes
class RequestCode(Enum):
    REQUEST_REGISTRATION = 1100
    REQUEST_PUBLIC_KEY = 1101
    REQUEST_SEND_FILE = 1103
    REQUEST_VALID_CRC = 1104
    REQUEST_INVALID_CRC = 1105
    REQUEST_LAST_INVALID_CRC = 1106


# Response Codes
class ResponseCode(Enum):
    RESPONSE_REGISTRATION_SUCCESS = 2100
    RESPONSE_REGISTRATION_FAILED = 2101
    RESPONSE_AES_KEY = 2102
    RESPONSE_FILE_RECEIVED = 2103
    RESPONSE_MESSAGE_RECEIVED = 2104


class RequestHeader:

    def __init__(self):
        self.clientID = b""
        self.version = 0
        self.code = 0
        self.payloadSize = 0
        self.SIZE = CLIENT_ID_SIZE + VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE_SIZE

    def unpack(self, data):
        try:
            self.clientID, self.version, self.code, self.payloadSize = struct.unpack(f"<{CLIENT_ID_SIZE}sBHL", data[:self.SIZE])
        except Exception as e:
            raise Exception(f"Error parsing request header: {e}")


class RegistrationRequest:

    def __init__(self):
        self.name = b""
        self.SIZE = NAME_SIZE

    def unpack(self, data):
        try:
            # trim the byte array after the nul terminating character.
            self.name = str(struct.unpack(f"<{NAME_SIZE}s", data[:NAME_SIZE])[0].partition(b'\0')[0].decode('utf-8'))
        except:
            raise Exception(f"Error parsing registration request: {e}")

class PublicKeyRequest:

    def __init__(self):
        self.name = b""
        self.publicKey = b""
        self.SIZE = NAME_SIZE + PUBLIC_KEY_SIZE

    def unpack(self, data):
        try:
            # trim the byte array after the nul terminating character.
            self.name = str(struct.unpack(f"<{NAME_SIZE}s", data[:NAME_SIZE])[0].partition(b'\0')[0].decode('utf-8'))
            self.publicKey = struct.unpack(f"<{PUBLIC_KEY_SIZE}s", data[NAME_SIZE:self.SIZE])[0]
        except:
            raise Exception(f"Error parsing public key request: {e}")


class SendFileRequest:
    def __init__(self):
        self.clientID = b""
        self.contentSize = 0
        self.fileName = b""
        self.SIZE = CLIENT_ID_SIZE + CONTENT_SIZE_SIZE + FILE_NAME_SIZE

    def unpack(self, data):
        try:
            fileNameOffset = CLIENT_ID_SIZE + CONTENT_SIZE_SIZE
            self.clientID, self.contentSize = struct.unpack(f"<{CLIENT_ID_SIZE}sL", data[:fileNameOffset])
            self.fileName = str(struct.unpack(f"<{FILE_NAME_SIZE}s", data[fileNameOffset:self.SIZE])[0].partition(b'\0')[0].decode('utf-8'))
        except Exception as e:
            raise Exception(f"Error parsing send file request: {e}")


#Used by all three of the CRC requests:   REQUEST_VALID_CRC = 1104, REQUEST_INVALID_CRC = 1105, REQUEST_LAST_INVALID_CRC = 1106
class CRCRequest:
    def __init__(self):
        self.clientID = b""
        self.fileName = b""
        self.SIZE = CLIENT_ID_SIZE + FILE_NAME_SIZE

    def unpack(self, data):
        try:
            self.clientID = struct.unpack(f"<{CLIENT_ID_SIZE}s", data[:CLIENT_ID_SIZE])

            # trim the byte array after the nul terminating character.
            self.fileName = str(struct.unpack(f"<{FILE_NAME_SIZE}s", data[CLIENT_ID_SIZE:self.SIZE])[0].partition(b'\0')[0].decode('utf-8'))

        except Exception as e:
            raise Exception(f"Error parsing CRC request: {e}")






class ResponseHeader:
    def __init__(self, code):
        self.version = SERVER_VERSION
        self.code = code
        self.payloadSize = 0
        self.SIZE = VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE_SIZE

    def pack(self):
        try:
            return struct.pack(f"<BHL", self.version, self.code, self.payloadSize)
        except Exception as e:
            raise Exception(f"Error packing response header: {e}")

class RegistrationSuccessResponse():
    def __init__(self):
        self.header = ResponseHeader(ResponseCode.RESPONSE_REGISTRATION_SUCCESS.value)
        self.header.payloadSize = CLIENT_ID_SIZE
        self.clientID = b""

    def pack(self):
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.clientID)
            return data
        except Exception as e:
            raise Exception(f"Error packing registration success response: {e}")

class RegistrationFailedResponse:
    def __init__(self):
        self.header = ResponseHeader(ResponseCode.RESPONSE_REGISTRATION_FAILED.value)
        self.header.payloadSize = 0

    def pack(self):
        try:
            return self.header.pack()
        except Exception as e:
            raise Exception(f"Error packing registration failed response: {e}")

class AESKeyResponse:
    def __init__(self):
        self.header = ResponseHeader(ResponseCode.RESPONSE_AES_KEY.value)
        self.header.payloadSize = CLIENT_ID_SIZE + AES_KEY_SIZE
        self.clientID = b""
        self.AESKey = b""

    def pack(self):
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.clientID)
            data += struct.pack(f"<{AES_KEY_SIZE}s", self.AESKey)
            return data
        except Exception as e:
            raise Exception(f"Error packing AES key response: {e}")

class FileReceivedResponse:
    def __init__(self):
        self.header = ResponseHeader(ResponseCode.RESPONSE_FILE_RECEIVED.value)
        self.header.payloadSize = CLIENT_ID_SIZE + CONTENT_SIZE_SIZE + FILE_NAME_SIZE + CHECKSUM_SIZE
        self.clientID = b""
        self.contentSize = 0
        self.fileName = b""
        self.checksum = 0

    def pack(self):
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.clientID)
            data += struct.pack(f"<L", self.contentSize)

            encoded = self.fileName.encode('utf-8')
            fileNameByteArray = bytearray(encoded)
            if len(fileNameByteArray) < FILE_NAME_SIZE:
                fileNameByteArray += bytearray(FILE_NAME_SIZE - len(fileNameByteArray))

            data += struct.pack(f"<{FILE_NAME_SIZE}s", fileNameByteArray)
            data += struct.pack(f"<L", self.checksum)
            return data
        except Exception as e:
            raise Exception(f"Error packing AES key response: {e}")

class MessageReceivedResponse:
    def __init__(self):
        self.header = ResponseHeader(ResponseCode.RESPONSE_MESSAGE_RECEIVED.value)
        self.header.payloadSize = 0

    def pack(self):
        try:
            return self.header.pack()
        except Exception as e:
            raise Exception(f"Error packing message received response: {e}")
