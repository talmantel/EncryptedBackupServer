import logging
import sqlite3
import protocol
from datetime import datetime


class Client:
    def __init__(self, clientId, name, lastSeen):
        self.ID = bytes.fromhex(clientId)
        self.Name = name
        self.PublicKey = None
        self.LastSeen = lastSeen
        self.AES = None

    def __repr__(self):
        return f"{self.ID}, {self.Name}, {self.PublicKey}, {self.LastSeen}, {self.AES}"

class File:
    def __init__(self, clientId, fileName, pathName, verified):
        self.ID = clientId
        self.FileName = fileName
        self.PathName = pathName
        self.Verified = verified


class Database:
    CLIENTS_TABLE = 'clients'
    FILES_TABLE = 'files'

    def __init__(self, name):
        self.name = name
        self.clients = []
        self.files = []

    def connect(self):
        conn = sqlite3.connect(self.name)  # doesn't raise exception.
        conn.text_factory = bytes
        return conn

    def executescript(self, script):
        conn = self.connect()
        try:
            conn.executescript(script)
            conn.commit()
        except:
            pass  # table might exist already
        conn.close()

    def execute(self, query, args, commit=False, get_last_row=False):
        """ Given an query and args, execute query, and return the results. """
        results = None
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute(query, args)
            if commit:
                conn.commit()
                results = True
            else:
                results = cur.fetchall()
            if get_last_row:
                results = cur.lastrowid  # special query.
        except Exception as e:
            logging.exception(f'database execute: {e}')
        conn.close()  # commit is not required.
        return results

    def initialize(self):
        # Try to create Clients table
        self.executescript(f"""
            CREATE TABLE {Database.CLIENTS_TABLE}(
              ID CHAR({protocol.CLIENT_ID_SIZE}) NOT NULL PRIMARY KEY,
              Name CHAR({protocol.NAME_SIZE}) NOT NULL,
              PublicKey CHAR({protocol.PUBLIC_KEY_SIZE}),
              LastSeen DATE,
              AES CHAR({protocol.AES_KEY_SIZE})
            );
            """)

        # Try to create Messages table
        self.executescript(f"""
            CREATE TABLE {Database.FILES_TABLE}(
              ID CHAR({protocol.CLIENT_ID_SIZE}) NOT NULL,
              FileName CHAR({protocol.FILE_NAME_SIZE}) NOT NULL,
              PathName CHAR({protocol.PATH_NAME_SIZE}) NOT NULL,
              Verified BOOLEAN NOT NULL,
            );
            """)

    def storeClient(self, client):

        self.clients.append(client)
        return

        """ Store a client into database """
        if not type(clnt) is Client or not clnt.validate():
            return False
        return self.execute(f"INSERT INTO {Database.CLIENTS_TABLE} VALUES (?, ?, ?, ?)",
                            [clnt.ID, clnt.Name, clnt.PublicKey, clnt.LastSeen], True)

    def updateClientLastSeen(self, client):
        client.LastSeen = str(datetime.now())
        return

        """ set last seen given a client_id """
        return self.execute(f"UPDATE {Database.CLIENTS_TABLE} SET LastSeen = ? WHERE ID = ?",
                            [str(datetime.now()), client_id], True)


    def getClientByUsername(self, username):
        for client in self.clients:
            if client.Name == username:
                return client
        return None
        pass  # TODO


    def setClientKeys(self, client, publicKey, AESKey):
        client.PublicKey = publicKey
        client.AES = AESKey
        return

        return self.execute(f"UPDATE {Database.CLIENTS_TABLE} VALUES set PublicKey = ?, AES = ?", [publicKey, AESKey], True)








    def clientIdExists(self, client_id):
        """ Check whether a client ID already exists within database """
        results = self.execute(f"SELECT * FROM {Database.CLIENTS_TABLE} WHERE ID = ?", [client_id])
        if not results:
            return False
        return len(results) > 0

    def storeMessage(self, msg):
        """ Store a message into database """
        if not type(msg) is Message or not msg.validate():
            return False
        results = self.execute(
            f"INSERT INTO {Database.MESSAGES}(ToClient, FromClient, Type, Content) VALUES (?, ?, ?, ?)",
            [msg.ToClient, msg.FromClient, msg.Type, msg.Content], True, True)
        return results

    def removeMessage(self, msg_id):
        """ remove a message by id from database """
        return self.execute(f"DELETE FROM {Database.MESSAGES} WHERE ID = ?", [msg_id], True)


    def getClientsList(self):
        """ query for all clients """
        return self.execute(f"SELECT ID, Name FROM {Database.CLIENTS_TABLE}", [])

    def getClientPublicKey(self, client_id):
        """ given a client id, return a public key. """
        results = self.execute(f"SELECT PublicKey FROM {Database.CLIENTS_TABLE} WHERE ID = ?", [client_id])
        if not results:
            return None
        return results[0][0]

    def getPendingMessages(self, client_id):
        """ given a client id, return pending messages for that client. """
        return self.execute(f"SELECT ID, FromClient, Type, Content FROM {Database.MESSAGES} WHERE ToClient = ?",
                            [client_id])
