import logging
import protocol
import cryptUtil
import database
import uuid
import struct
import os
from pathlib import Path
from datetime import datetime


class Handler:
    def __init__(self, databaseFile, clientFilesFolder):
        self.database = database.Database(databaseFile)
        self.clientFilesFolder = clientFilesFolder
        self.handlers = {
            protocol.RequestCode.REQUEST_REGISTRATION.value: self.handleRegistrationRequest,
            protocol.RequestCode.REQUEST_PUBLIC_KEY.value: self.handlePublicKeyRequest,
            protocol.RequestCode.REQUEST_SEND_FILE.value: self.handleSendFileRequest,
            protocol.RequestCode.REQUEST_VALID_CRC.value: self.handleValidCRCRequest,
            protocol.RequestCode.REQUEST_INVALID_CRC.value: self.handleInvalidCRCRequest,
            protocol.RequestCode.REQUEST_LAST_INVALID_CRC.value: self.handleInvalidCRCRequest
        }

    def write(self, conn, data):
        size = len(data)
        sent = 0
        while sent < size:
            leftover = size - sent
            if leftover > protocol.PACKET_SIZE:
                leftover = protocol.PACKET_SIZE
            toSend = data[sent:sent + leftover]
            if len(toSend) < protocol.PACKET_SIZE:
                toSend += bytearray(protocol.PACKET_SIZE - len(toSend))
            try:
                conn.send(toSend)
                sent += len(toSend)
            except Exception as e:
                print(f"Exception while sending response to {conn}: {e}")

    def handle(self, conn):
        data = conn.recv(protocol.PACKET_SIZE)
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

        if self.database.getClientByUsername(request.name) is not None:
            response = protocol.RegistrationFailedResponse()
            self.write(conn, response.pack())
            return

        client = database.Client(uuid.uuid4().bytes, request.name, None, None, None)
        self.database.storeClient(client)

        response = protocol.RegistrationSuccessResponse()
        response.clientID = client.ID
        self.write(conn, response.pack())
        print(f"Successful regustration of: \n{client}\n")


    def handlePublicKeyRequest(self, conn, requestHeader, data):
        client = self.database.getClientById(requestHeader.clientID)
        if client is None:
            raise Exception(f"User with id {requestHeader.clientID} doesn't exist!")

        self.database.updateClientLastSeen(client)

        request = protocol.PublicKeyRequest()
        request.unpack(data)

        AESKey = cryptUtil.generateAESKey()
        self.database.setClientKeys(client, request.publicKey, AESKey)

        encryptedKey = cryptUtil.encryptWithPublicKey(AESKey, client.PublicKey)
        response = protocol.AESKeyResponse()
        response.clientID = client.ID
        response.AESKey = encryptedKey
        self.write(conn, response.pack())
        print(f"Successful regustration of encryption keys for client: \n{client}\n")

    def handleSendFileRequest(self, conn, requestHeader, data):
        client = self.database.getClientById(requestHeader.clientID)
        if client is None:
            raise Exception(f"User with id {requestHeader.clientID} doesn't exist!")

        self.database.updateClientLastSeen(client)

        if client.AES is None:
            raise Exception(f"User with id {requestHeader.clientID} doesn't have AES key yet!")

        request = protocol.SendFileRequest()
        request.unpack(data)

        #TODO validate file name legal
        path = self.clientFilesFolder + "/" + client.ID.hex()
        Path(path).mkdir(parents=True, exist_ok=True)
        filePath =  path + "/" + request.fileName
        file = open(filePath, "wb+")

        bytesRead = len(data) - request.SIZE
        if bytesRead > request.contentSize:
            bytesRead = request.contentSize
        file.write(cryptUtil.decrypt(data[request.SIZE:request.SIZE + bytesRead], client.AES))
        while bytesRead < request.contentSize:
            data = conn.recv(protocol.PACKET_SIZE)
            dataSize = len(data)
            if (request.contentSize - bytesRead) < dataSize:
                dataSize = request.contentSize - bytesRead
            file.write(cryptUtil.decrypt(data[:dataSize], client.AES))
            bytesRead += dataSize

        file.close()

        self.database.saveFile(client, filePath, request.fileName)

        #TODO calculate CRC
        checksum = 1234

        response = protocol.FileReceivedResponse()
        response.clientID = client.ID
        response.contentSize = bytesRead
        response.fileName = request.fileName
        response.checksum = checksum
        self.write(conn, response.pack())
        print(f"Successful file upload for client: \n{client}\nName: {request.fileName}, Content size: {bytesRead}, Checksum: {checksum}\n")

    def handleValidCRCRequest(self, conn, requestHeader, data):
        client = self.database.getClientById(requestHeader.clientID)
        if client is None:
            raise Exception(f"User with id {requestHeader.clientID} doesn't exist!")

        self.database.updateClientLastSeen(client)

        request = protocol.CRCRequest()
        request.unpack(data)

        file = self.database.getFile(client, request.fileName)

        if file is None:
            raise Exception(f"File {request.fileName} doesn't exist for client {client.Name}!")

        self.database.verifyFile(file)

        response = protocol.MessageReceivedResponse()
        self.write(conn, response.pack())
        print(f"Successful validation of CRC of file: {file.FileName} for client {client.Name}\n")

    def handleInvalidCRCRequest(self, conn, requestHeader, data):
        client = self.database.getClientById(requestHeader.clientID)
        if client is None:
            raise Exception(f"User with id {requestHeader.clientID} doesn't exist!")

        self.database.updateClientLastSeen(client)

        request = protocol.CRCRequest()
        request.unpack(data)

        file = self.database.getFile(client, request.fileName)

        if file is None:
            raise Exception(f"File {request.fileName} doesn't exist for client {client.Name}!")
        if file.Verified:
            raise Exception(f"File {request.fileName} for client {client.Name} is alrealy verified!")

        path = self.clientFilesFolder + "/" + client.ID.hex()
        filePath = path + "/" + request.fileName
        if os.path.exists(filePath):
            os.remove(filePath)

        self.database.removeFile(file)

        response = protocol.MessageReceivedResponse()
        self.write(conn, response.pack())
        print(f"File: {file.FileName} of client {client.Name} removed due to invalid CRC\n")