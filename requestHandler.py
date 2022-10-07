import logging
import protocol
import cryptUtil
import database
import uuid
from datetime import datetime


class Handler:
    def __init__(self, packetSize, databaseFile):
        self.packetSize = packetSize
        self.database = database.Database(databaseFile)
        self.handlers = {
            protocol.RequestCode.REQUEST_REGISTRATION.value: self.handleRegistrationRequest,
            protocol.RequestCode.REQUEST_PUBLIC_KEY.value: self.handlePublicKeyRequest,
            protocol.RequestCode.REQUEST_SEND_FILE.value: self.handleSendFileRequest,
            protocol.RequestCode.REQUEST_VALID_CRC.value: self.handleValidCRCRequest,
            protocol.RequestCode.REQUEST_INVALID_CRC.value: self.handleInvalidCRCRequest,
            protocol.RequestCode.REQUEST_LAST_INVALID_CRC.value: self.handleLastInvalidCRCRequest
        }

    def write(self, conn, data):
        size = len(data)
        sent = 0
        while sent < size:
            leftover = size - sent
            if leftover > self.packetSize:
                leftover = self.packetSize
            toSend = data[sent:sent + leftover]
            if len(toSend) < self.packetSize:
                toSend += bytearray(self.packetSize - len(toSend))
            try:
                conn.send(toSend)
                sent += len(toSend)
            except Exception as e:
                print(f"Exception while sending response to {conn}: {e}")

    def handle(self, conn):
        data = conn.recv(self.packetSize)
        if data:
            try:
                requestHeader = protocol.RequestHeader()
                requestHeader.unpack(data)
                if requestHeader.code in self.handlers.keys():
                    self.handlers[requestHeader.code](conn, requestHeader, data[requestHeader.SIZE:])
                else:
                    raise Exception(f"Request code {requestHeader.code} doesn't exist!")
            except Exception as e:
                print(f"Exception in handle request: {e}")
                # Not sure what to do here. There are no details in the assignment what to do in case of any error (other than registration error).
                # Here I do nothing, but I could send some generic error code like the next two lines:
                #responseHeader = protocol.ResponseHeader(protocol.ResponseCode.RESPONSE_ERROR.value)
                #self.write(conn, responseHeader.pack())

    def handleRegistrationRequest(self, conn, requestHeader, data):
        request = protocol.RegistrationRequest()
        request.unpack(data)

        if (not request.name.isalnum()) or self.database.getClientByUsername(request.name) is not None:
            response = protocol.RegistrationFailedResponse()
            self.write(conn, response.pack())
            return

        client = database.Client(uuid.uuid4().hex, request.name, str(datetime.now()))
        self.database.storeClient(client)

        response = protocol.RegistrationSuccessResponse()
        response.clientID = client.ID
        self.write(conn, response.pack())
        print(f"Successful regustration of: {client}")


    def handlePublicKeyRequest(self, conn, requestHeader, data):
        request = protocol.PublicKeyRequest()
        request.unpack(data)

        client = self.database.getClientByUsername(request.name)
        if client is None:
            raise Exception(f"User with name {request.name} doesn't exist!")

        AESKey = cryptUtil.generateAESKey()
        self.database.updateClientLastSeen(client)
        self.database.setClientKeys(client, request.publicKey, AESKey)

        encryptedKey = cryptUtil.encryptWithPublicKey(AESKey, client.PublicKey)
        response = protocol.AESKeyResponse()
        response.clientID = client.ID
        response.AESKey = encryptedKey
        self.write(conn, response.pack())

    def handleSendFileRequest(self, conn, requestHeader, data):
        pass

    def handleValidCRCRequest(self, conn, requestHeader, data):
        pass

    def handleInvalidCRCRequest(self, conn, requestHeader, data):
        pass

    def handleLastInvalidCRCRequest(self, conn, requestHeader, data):
        pass
