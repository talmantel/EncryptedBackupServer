import requestHandler
import selectors
import socket


DATABASE_FILE = "server.db"
CLIENT_FILES_FILDER = "files"
QUEUE_SIZE = 100

sel = selectors.DefaultSelector()
handler = requestHandler.Handler(DATABASE_FILE, CLIENT_FILES_FILDER)

#Accept new connection
def accept(sock, mask):
    conn, addr = sock.accept()
    #print('accepted', conn, 'from', addr)
    conn.setblocking(False)
    sel.register(conn, selectors.EVENT_READ, read)

#Handle connection
def read(conn, mask):
    handler.handle(conn)
    sel.unregister(conn)
    conn.close()


def startServer(host, port):
    try:
        sock = socket.socket()
        sock.bind((host, port))
        sock.listen(QUEUE_SIZE)
        sock.setblocking(False)
        sel.register(sock, selectors.EVENT_READ, accept)
        print(f"Server is listening for connections on port {port}...")
        while True:
            try:
                events = sel.select()
                for key, mask in events:
                    callback = key.data
                    callback(key.fileobj, mask)
            except Exception as e:
                print(f"\nException in main loop: {e}\n")
    except Exception as e:
        print(f"\nServer start error: {e}\n")
