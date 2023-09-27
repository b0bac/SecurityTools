# -*- coding:utf-8 -*-

'''
对于应急中需要查看的域名和IP地址进行威胁情报的查询
'''


# 引入依赖的Py包、库、模块
import os
import sys
import json
import urllib
import base64
import urllib2
import hashlib
import datetime
import postfile
import simplejson
from optparse import OptionParser


#  配置APIKEY
APIKEY = 'MDMzZTFhMmFlMDcxZjg4MDBkNTU4YTk2ODcxN2MyNjc0ZjhlYjcyOGNmYjZiNDcwZDQ3MTNkZDc0NDYwMGZiNytjaGVucmFu'

#  定义VirusTotal类

class virustotal(object):
    def __init__(self,username='chenran'):
        self._key = base64.b64decode(APIKEY).split('+')[0]
        self._username = base64.b64decode(APIKEY).split('+')[-1]
        self._host = "www.virustotal.com"
        self._fields = [("apikey",self._key)]
        if self._username != username:
            raise Exception("Wrong Username")

    def _upload_check_file(self,_file):
        _file = os.path.basename(_file)
        try:
            __file = open(_file,'rb').read()
        except Exception, reason:
            print "上传文件错误"
            return None
        _file_struct = [("file",_file,__file)]
        try:
            _json = postfile.post_multipart(self._host,"https://www.virustotal.com/vtapi/v2/file/scan",self._fields,_file_struct)
        except Exception, reason:
            print "获取文件报告错误"
            return None
        return _json

    def _file_rescan(self,_id):
        _string = ''
        if isinstance(_id,list):
            for sid in _id:
                _string += "%s,"%sid
        else:
            _string = '%s,'%str(_id)
        _string = _string[0:-1]
        _parameters = {"resource":_string,"apikey":self._key}
        try:
            data = urllib.urlencode(_parameters)
            _request = urllib2.Request("https://www.virustotal.com/vtapi/v2/file/rescan",data)
            _response = urllib2.urlopen(_request)
            _json = _response.read()
        except Exception, reason:
            return None
        return _json

    def _fast_check(self,_file):
        _md5 = hashlib.md5()
        _md5.update(open(_file,'rb').read())
        _md5 = _md5.hexdigest()
        _json = self._upload_check_file(_file)
        if 'Error 400' in _json:
            _json = self._file_rescan(_md5)
        _json = simplejson.loads(_json)
        return _json["sha256"]


    def _upload_check_files(self,_file_list):
        _json_list = []
        if len(_file_list)  <= 0:
            return None
        for _file in _file_list:
            _json = self._fast_check(_file)
            _json_list.append(_json)
        return _json_list

    def _get_report(self,_sha256):
        _url = "https://www.virustotal.com/vtapi/v2/file/report"
        _parameters = {"resource":_sha256,"apikey":self._key}
        try:
            _data = urllib.urlencode(_parameters)
            _requset = urllib2.Request(_url,_data)
            _response = urllib2.urlopen(_requset)
            _json = _response.read()
        except Exception, reason:
            return None
        return _json

    def check_file(self,_hash=None,_file=None):
        if _file != None:
            self._fast_check(_file)
            _json = self._get_report(hashlib.sha256(open(_file,'rb').read()).hexdigest())
        elif _hash != None:
            _json = self._get_report(_hash)
        else:
            return 0
        _json = json.loads(_json)
        #print _json
        #print _json["verbose_msg"]
        #print (u'Invalid' in str(_json["verbose_msg"]))
        if 'Invalid' not in _json["verbose_msg"]:
            positives = _json['positives']
        else:
            positives = 0
        _list = [x for x in _json['scans'] if _json['scans'][x]['detected']]
        print "******************************************"
        print "检测时间: %s"%str(_json["scan_date"])
        print "报毒数量: %s"%positives
        print "报毒引擎: %s"%str(_list)
        print "引擎总数: %s"%_json["total"]
        print "******************************************"

    def ioc_check(self,ioc,ioctype='domain'):
        if ioctype not in ['url','domain','ip']:
            print "类型不对，请检查"
        _parameters = {ioctype:ioc,'apikey':self._key}
        _dict = {
            "url":"https://www.virustotal.com/vtapi/v2/url/scan",
            "domain":"https://www.virustotal.com/vtapi/v2/domain/report",
            "ip":"https://www.virustotal.com/vtapi/v2/ip-address/report",
        }
        _url = _dict[ioctype]
        try:
            _response = urllib2.urlopen('%s?%s'%(_url,urllib.urlencode(_parameters))).read()
            _json = json.loads(_response)
        except Exception, reason:
            if ioctype == 'url':
                try:
                    _data = urllib.urlencode(_parameters)
                    _request = urllib2.Request(_url,_data)
                    _response = urllib2.urlopen(_request)
                    _json = _response.read()
                    _json = json.loads(_json)
                    keylist = []
                    samples = 0
                    urls = 0
                    try:
                        resolv_domains = len(_json['resolutions'])
                    except Exception, reason:
                        resolv_domains = 0
                    for key in _json.keys():
                        if 'detected' in key and 'undetected' not in key:
                            keylist.append(key)
                    for key in keylist:
                        if 'samples' in key:
                            for stuff in _json[key]:
                                if stuff["positives"] > 0:
                                    samples += 1
                        if  'urls' in key:
                            for stuff in _json[key]:
                                try:
                                    if stuff['positives'] > 0:
                                         urls += 1
                                except Exception, reason:
                                    if int(stuff[2]) > 0:
                                        urls += 1
                    print "******************************************"
                    print "检测时间: %s"%str(datetime.datetime.now()).split(".")[0]
                    print "关联样本: %s"%str(samples)
                    print "关联连接: %s"%str(urls)
                    print "关联域名: %s"%str(resolv_domains)
                    print "******************************************"
                    return None
                except Exception, reason:
                    print reason
                    return None
            else:
                return None
        keylist = []
        samples = 0
        urls = 0
        try:
            resolv_domains = len(_json['resolutions'])
        except Exception, reason:
            resolv_domains = 0
        for key in _json.keys():
            if 'detected' in key and 'undetected' not in key:
                keylist.append(key)
        for key in keylist:
            if 'samples' in key:
                for stuff in _json[key]:
                    if stuff["positives"] > 0:
                        samples += 1
            if  'urls' in key:
                for stuff in _json[key]:
                    try:
                        if stuff['positives'] > 0:
                             urls += 1
                    except Exception, reason:
                        if int(stuff[2]) > 0:
                            urls += 1
        print "******************************************"
        print "检测时间: %s"%str(datetime.datetime.now()).split(".")[0]
        print "关联样本: %s"%str(samples)
        print "关联连接: %s"%str(urls)
        print "关联域名: %s"%str(resolv_domains)
        print "******************************************"


if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-f", "--file",dest="file",help="show process detail")
    parser.add_option("-a", "--addr",dest="addr",help="show process detail")
    parser.add_option("-d", "--domain",dest="domain",help="show process detail")
    parser.add_option("-u", "--url",dest="url",help="show process detail")
    (options, args) = parser.parse_args()
    obj = virustotal()
    if options.file not in [None,""]:
        obj.check_file(_file=options.file)
        exit(0)
    if options.addr not in [None,""]:
        obj.ioc_check(options.addr,"ip")
        exit(0)
    if options.domain not in [None,""]:
        obj.ioc_check(options.domain,"domain")
        exit(0)
    if options.url not in [None,""]:
        obj.ioc_check(options.url,"url")
        exit(0)
