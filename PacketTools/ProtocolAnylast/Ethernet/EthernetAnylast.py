# -*- coding:utf-8 -*-

'''
链路层帧解析
'''

import dpkt


#定义帧解析类
class EthernetPacket(object):
    '''数据报文链路层分解'''
    def __init__(self,packet):
        '''初始化链路层数据'''
        self.packet = dpkt.ethernet.Ethernet(packet)

    @staticmethod
    def numhex(number):
        string = str(hex(number)).split('x')[-1]
        string = '0%s'%string if len(string) == 1 else string
        return string

    def getSrc(self):
        '''返回源mac地址'''
        return "".join(str(map(EthernetPacket.numhex,tuple(map(ord,list(self.packet.src))))))[1:-1].replace(',',':').replace("'","").replace(" ","")

    def getDst(self):
        '''返回目的mac地址'''
        return "".join(str(map(EthernetPacket.numhex,tuple(map(ord,list(self.packet.dst))))))[1:-1].replace(',',':').replace("'","").replace(" ","")

    def getType(self):
        '''获取数据链路层的Type'''
        _type = {
            2048:"IPv4",
            2054:"Arp",
            34525:"IPv6",
        }
        return _type.get(int(self.packet.type),"未解析")

    def getData(self):
        return self.packet.data
