# -*- coding:utf-8 -*-

class Frame(object):
    def __init__(self,smac,dmac,protocol):
        self.smac = smac
        self.dmac = dmac
        self.protocol = protocol


class Network(object):
    def __init__(self,sip,dip,protocol,df,mf,packetid,size,version,ttl):
        self.sip = sip
        self.dip = dip
        self.protocol = protocol
        self.df = df
        self.mf = mf
        self.packetid = packetid
        self.size = size
        self.version = version
        self.ttl = ttl


class Transport(object):
    def __init__(self,sport=None,dport=None,code=None,itype=None,size=None,data=None,ack=None,seq=None,flags=None,window=None,up=None):
        self.sport = sport
        self.dport = dport
        self.code = code
        self.itype = itype
        self.size = size
        self.ack = ack
        self.seq = seq
        self.flags = flags
        self.window = window
        self.up = up

class Data(object):
    def __init__(self,data):
        self.data = data


class Packet(object):
    def __init__(self,frame,network,transport,data):
        self.frame = frame if isinstance(frame,Frame) else raise Exception
        self.network = network if isinstance(network,Network) else raise Exception
        self.transport = transport if isinstance(transport,Transport) else raise Exception
        self.data = data if isinstance(data,Data) else raise Exception
