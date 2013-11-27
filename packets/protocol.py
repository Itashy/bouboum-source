#!/usr/bin/env python
import re
import struct
import warnings

from zope.interface import implements
from twisted.internet import protocol, reactor
from twisted.protocols import basic

class TFMClientProtocol(protocol.Protocol):
    recvd = ""
    structFormat = "!I"

    def stringReceived(self, string):
        raise NotImplementedError

    def inforequestReceived(self, string):
        raise NotImplementedError

    def dataReceived(self, data):

        if data.startswith("<policy-file-request/>"):
            self.inforequestReceived(data)
            return
            
        self.recvd += data
        while not self.recvd == "":
            datalength = len(self.recvd)
            if datalength>=4:
                packetlength = int((struct.unpack("%sL" % "!", self.recvd[:4]))[0])
                if datalength == packetlength:
                    self.stringReceived(self.recvd[4:])
                    self.recvd = ""
                elif datalength < packetlength:
                    break
                else:
                    self.stringReceived(self.recvd[4:packetlength])
                    self.recvd = self.recvd[packetlength:]
            else:
                break

    def sendString(self, string):

        if len(string) >= 2 ** (8 * 4):
            raise StringTooLongError(
                "Try to send %s bytes whereas maximum is %s" % (
                len(string), 2 ** (8 * 4)))
        self.transport.write(
            struct.pack(self.structFormat, len(string)) + string)
