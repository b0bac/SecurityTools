# -*- coding:utf-8 -*-

'''
网络层包解析
'''

import dpkt
import socket


#定义包解析类
class IPNetworkAnylast(object):
    '''数据报文网络层分解'''
    def __init__(self,packet):
        '''初始化网络层数据'''
        self.packet = packet

    def getSrc(self):
        '''返回源IP地址'''
        return socket.inet_ntoa(self.packet.src)

    def getDst(self):
        '''返回目的IP地址'''
        return socket.inet_ntoa(self.packet.dst)

    def getProcotol(self):
        '''返回传输层协议'''
        return str(self.packet.get_proto(self.packet.p).__name__)

    def getDontFragment(self):
        '''返回Don't Framment的值'''
        return self.packet.df

    def getMoreFragment(self):
        '''返回More Framment的值'''
        return self.packet.mf

    def getID(slef):
        '''返回报文的ID'''
        return self.packet.id

    def getSize(self):
        '''获取数据包大小'''
        return self.packet.len

    def getVersion(self):
        '''获取数据包版本'''
        return self.packet.v

    def getTTL(self):
        '''获取Time To Live'''
        return self.packet.ttl

    def getData(self):
        '''获取传输层数据'''
        return self.packet.data
