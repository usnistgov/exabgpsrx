# encoding: utf-8
"""
bgpsec.py

Created by Kyehwan Lee on 2018-01-05.
ANTD NIST
"""

from struct import pack
#from struct import unpack
from exabgp.bgp.message.open.capability.capability import Capability

# =========================================================== BGPSEC open
# RFC 8205
"""
        0   1   2   3      4      5   6   7
        +---------------------------------------+
        | Version          | Dir |  Unassigned  |
        +---------------------------------------+
        |                                       |
        +------           AFI              -----+
        |                                       |
        +---------------------------------------+
        BGPSec version : 0
        Dir: 0 : to receive BGPSec Update
        Dir: 1 : to send BGPSec update
        AFI: only used two address families, IPv4:1, IPv6:2
"""

class BGPSEC (Capability, dict):

    ID = Capability.CODE.BGPSEC
    AFI_IPv4 = 1 # IPv4
    AFI_IPv6 = 2 # IPv6

    def __init__ (self, send_receive=0, ip_family=1):

        if send_receive > 1:
            send_receive = 1

        for i in range(send_receive +1) :
            self.add_conf(i)

        if ip_family == 1:
            self['ip_family'] = self.AFI_IPv4
        elif ip_family == 2:
            self['ip_family'] = self.AFI_IPv6


    def add_conf (self, send_receive):
        self[send_receive] =  send_receive << 3 # values are 0 or 8

    def __str__ (self):
        return "BGPSEC OPEN"

    def extract (self):
        #rs = ['\x08\x00\x01', '\x00\x00\x01' ]
        rs = []
        recv = 0
        send = 1
        rs.append(pack('!B',self[recv]) +  pack('!H', self['ip_family']))
        if send in self.keys() and self[send] :
            rs.append(pack('!B',self[send]) +  pack('!H', self['ip_family']))

        return rs

    @staticmethod
    def unpack_capability (instance, data, capability=None):  # pylint: disable=W0613
        return instance


