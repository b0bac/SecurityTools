# -*- coding:utf-8 -*-


import hashlib


# 定义TCP流解析类
class Stream(object):
    '''定义TCP流解析'''
    def __init__(self,streamhash):
        self.streamhash = streamhash
        self._packets = []

    @staticmethod
    def tuplehash(sip,dip,sport,dport):
        hashstring = sip + dip + sport + dport
        sha256 = hashlib.sha256()
        sha256.update(hashstring)
        return sha256.hexdigest()

    def addPacket(self,packet):
        if isinstance(packet,Packet):
            self._packets.append(packet)
            return True
        else:
            return False

    def getPackets(self):
        return slef._packets 
