import server
from pathlib import Path

PORT_INFO_FILE = "port.info"
DEFAULT_PORT = 1234

#Parse post from port file, or default if no port file found
def getPort():
    p = Path(PORT_INFO_FILE)
    if p.exists():
        try:
            with open(PORT_INFO_FILE, "r") as portInfo:
                return int(portInfo.readline().strip())
        except Exception as e:
            print(f"Cannot read port number from {PORT_INFO_FILE}: {e}")
    else:
        print(f"File {PORT_INFO_FILE} doesn't exist")
    print(f"Using default port {DEFAULT_PORT}")
    return DEFAULT_PORT


def main():
    port = getPort()
    server.startServer('localhost', port)


if __name__ == '__main__':
    main()

