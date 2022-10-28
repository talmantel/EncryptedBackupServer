import logging
import sqlite3
import protocol
from datetime import datetime

#Data model for client
class Client:
    def __init__(self, clientId, name, publicKey, lastSeen, AESKey):
        self.ID = clientId
        self.Name = name
        self.PublicKey = publicKey
        self.LastSeen = lastSeen
        self.AES = AESKey

    def __repr__(self):
        return f"{self.ID}, {self.Name}, {self.LastSeen}\n--PublicKey: {self.PublicKey}\n--AESKey: {self.AES}"

#Data model for file
class File:
    def __init__(self, clientId, fileName, pathName, verified):
        self.ID = clientId
        self.FileName = fileName
        self.PathName = pathName
        self.Verified = verified

    def __repr__(self):
        return f"{self.ID}, {self.FileName}, {self.PathName}, {self.Verified}"


#Database handler (SQLite persistent storage with in-memory cache)
#SQLite DB is loaded into memory on load
#Updates and inserts are done both on SQLite and memory cache, selects are performed directly from memory
class Database:
    CLIENTS_TABLE = 'clients'
    FILES_TABLE = 'files'

    def __init__(self, name):
        self.name = name
        self.clients = []
        self.files = []
        self.initialize()

    def connect(self):
        conn = sqlite3.connect(self.name)
        return conn

    #Initialize SQLite DB (if doesn't exist), and load DB into memory cache if it already exists
    def initialize(self):
        conn = self.connect()

        #Create tables in DB if don't exist
        conn.executescript(f"""
               CREATE TABLE IF NOT EXISTS {Database.CLIENTS_TABLE}(
                 ID CHAR({protocol.CLIENT_ID_SIZE}) NOT NULL PRIMARY KEY,
                 Name CHAR({protocol.NAME_SIZE}) NOT NULL,
                 PublicKey CHAR({protocol.PUBLIC_KEY_SIZE}),
                 LastSeen DATE,
                 AES CHAR({protocol.AES_KEY_SIZE})
               );
               
               CREATE TABLE IF NOT EXISTS  {Database.FILES_TABLE}(
                 ID CHAR({protocol.CLIENT_ID_SIZE}) NOT NULL,
                 FileName CHAR({protocol.FILE_NAME_SIZE}) NOT NULL,
                 PathName CHAR({protocol.PATH_NAME_SIZE}) NOT NULL,
                 Verified BOOLEAN NOT NULL
               );
               """)
        conn.commit()

        #Load DB into memory cache
        cur = conn.cursor()
        cur.execute(f"SELECT * FROM {Database.CLIENTS_TABLE}")
        results = cur.fetchall()
        for client in results:
            c = Client(client[0], client[1], client[2], client[3], client[4])
            self.clients.append(c)
            print(f"Loaded client from DB: {c}\n")

        cur.execute(f"SELECT * FROM {Database.FILES_TABLE}")
        results = cur.fetchall()
        for file in results:
            f = File(file[0], file[1], file[2], file[3])
            self.files.append(f)
            print(f"Loaded file from DB: {f}\n")

        conn.close()

    def execute(self, query, args):
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute(query, args)
            conn.commit()
        except Exception as e:
            logging.exception(f'Exception while updating the DB: {e}')
        conn.close()

    #Store new client in the system. LastSeen is set to current time
    def storeClient(self, client):
        self.clients.append(client)
        self.execute(f"INSERT INTO {Database.CLIENTS_TABLE} (ID, Name, LastSeen) VALUES (?, ?, CURRENT_TIMESTAMP)", [client.ID, client.Name])

    #Update LastSeen of client to the current timestamp
    def updateClientLastSeen(self, client):
        client.LastSeen = str(datetime.now())
        self.execute(f"UPDATE {Database.CLIENTS_TABLE} SET LastSeen = CURRENT_TIMESTAMP WHERE ID = ?", [client.ID])

    #Get Client by username
    def getClientByUsername(self, username):
        for client in self.clients:
            if client.Name == username:
                return client
        return None

    #Get Client by client ID
    def getClientById(self, clientId):
        for client in self.clients:
            if client.ID == clientId:
                return client
        return None

    #Set Client RSA public key and AES key
    def setClientKeys(self, client, publicKey, AESKey):
        client.PublicKey = publicKey
        client.AES = AESKey
        self.execute(f"UPDATE {Database.CLIENTS_TABLE} SET PublicKey = ?, AES = ? WHERE ID = ?", [publicKey, AESKey, client.ID])

    #Store new file in the system. If an entry with the same filename and client already exists - it replaces it
    def saveFile(self, client, filePath, fileName):
        file = self.getFile(client, fileName)
        if file is not None:
            self.removeFile(file)
        self.files.append(File(client.ID, fileName, filePath, False))
        self.execute(f"INSERT INTO {Database.FILES_TABLE} VALUES (?, ?, ?, ?)", [client.ID, fileName, filePath, False])

    #Get file by client and filename
    def getFile(self, client, fileName):
        for file in self.files:
            if file.ID == client.ID and file.FileName == fileName:
                return file
        return None

    #Update file CRC verified
    def verifyFile(self, file):
        file.Verified = True
        self.execute(f"UPDATE {Database.FILES_TABLE} SET Verified = true WHERE ID = ? AND FileName = ?", [file.ID, file.FileName])

    #Remove a file from the system
    def removeFile(self, file):
        self.files.remove(file)
        self.execute(f"DELETE FROM {Database.FILES_TABLE} WHERE ID = ? AND FileName = ?", [file.ID, file.FileName])