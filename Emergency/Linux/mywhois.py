# -*- coding:UTF-8 -*-


# 引入依赖的Py库、包、模块
import re
import json
import socket
import datetime
from optparse import OptionParser


# 定义全局变量
whoisserver = {}

def config_read():
	global whoisserver
	with open("./tldconfig.conf", 'r') as fr:
		for line in fr.readlines():
			line = line.split("\n")[0].split("\r")[0]
			line = line.split(":")
			domain = line[0]
			server = line[1]
			if domain not in whoisserver:
				whoisserver[domain] = server


def get_whois_server(domain):
	domainlist = domain.split(".")
	tld = domainlist[-2]+"."+domainlist[-1]
	if tld in whoisserver:
		return whoisserver[tld]
	else:
		tld = domainlist[-1]
		if tld in whoisserver and tld not in ['net','com']:
			return whoisserver[tld]
		else:
			con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			con.connect(('whois.verisign-grs.com',43))
		except Exception, reason:
			con.close()
			return None
		tld = domainlist[-2]+"."+domainlist[-1]
		package = '=%s\r\n'%tld
		try:
			con.send(package)
		except Exception, reason:
			con.close()
			return None
		try:
			data = con.recv(1024)
		except Exception, reason:
			con.close()
			return None
		con.close()
		_dict = data.split('\n\n')
	if data.find('No match for') >= 0:
		return None
	key = 'Domain Name: %s' %(tld.upper())
	data = [x for x in _dict if key in x]
	try:
		server = re.findall(r'Whois Server: ([A-Za-z0-9\-\_\.]*)',str(data))[0]
	except Exception, reason:
		try:
			server = re.findall(r'WHOIS Server: ([A-Za-z0-9\-\_\.]*)',str(data))[0]
		except Exception, reason:
			return None
	return server


def whois_check(server,domain):
	con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		con.connect((server,43))
	except Exception, reason:
		con.close()
		return None
	package = '%s\r\n' %(domain)
	try:
		con.send(package)
	except Exception, reason:
		con.close()
		return None
	try:
		ret = con.recv(4096)
		xcount = 0
		while ret.find('For more information') < 0:
			xcount += 1
			ret += con.recv(4096)
			if xcount > 5:
				break
	except Exception, reason:
		con.close()
		return None
	con.close()
	print ret
	return 0

if __name__ == '__main__':
	parser = OptionParser("")
	parser.add_option("-d", dest="domain",help="domain to check", metavar="domain")
	(options, args) = parser.parse_args()
	config_read()
	if options.domain != None:
		server = get_whois_server(options.domain)
		whois_check(server,options.domain)
	else:
		print '请输入域名!'
