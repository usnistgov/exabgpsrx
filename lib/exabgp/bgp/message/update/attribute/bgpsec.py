"""
bgpsec.py

Created by Kyehwan Lee on 2018-01-19.
Copyright NIST. All rights reserved.
"""


from exabgp.bgp.message.update.attribute.attribute import Attribute
from struct import pack
#from exabgp.cryptobgpsec import *
from exabgp import cryptobgpsec
from exabgp.util import character
from exabgp.util import concat_bytes
#import ctypes
#from struct import unpack
import copy

from exabgp.logger import Logger

class BGPSEC (Attribute):
    ID = Attribute.CODE.BGPSEC
    FLAG = Attribute.Flag.OPTIONAL | Attribute.Flag.EXTENDED_LENGTH

    PCOUNT  = 0x01
    SP_FLAG = 0x00 # secure path segment flag
    ALGO_ID = 0x01
    SIG_LEN = 2
    SKI_LEN = 20
    SEC_PATH_LEN = 2
    SIG_BLOCK_LEN = 2
    PATH_SEG_UNIT_LEN = 6

    secure_path = []
    signature_block = []
    secure_path_segment = []
    signature_segment = []
    signature  = []
    secure_path_len = 0
    signature_block_len = 0
    nlri_ip = ''
    nlri_mask = 0

    _init_lib = False

    def __init__ (self, negotiated, nlri={}, packed=None):
        self.negotiated = negotiated
        self.packed = packed

        self.ski_str =''

        self.pre_asns = []
        self.pre_skis = []
        self.dict_asn_ski = {}

        self.all_asns = []
        self.all_skis = []

        self.bgpsec_pre_attrs = []
        self.dict_signatures = {}
        self.logger = Logger()

        if nlri:
            self.nlri_ip = nlri[(1,1)][1][0].cidr.top()  # nlri[(ipv4=1,uincast=1)][action=1 (ANNOUCE)]: [exabgp.bgp.message.update.nlri.inet.INET]
            self.nlri_mask = nlri[(1,1)][1][0].cidr.mask
        else:
            return None

        self.crtbgp = cryptobgpsec.CryptoBgpsec(negotiated)

        # fill all the asn ski
        self.all_asns.append(self.negotiated.local_as)
        self.all_skis.extend(self.negotiated.neighbor.ski)

        # TODO: need if-statmement for comparing the number of asns and skis
        if negotiated.neighbor.bgpsec_pre_asns and len(negotiated.neighbor.bgpsec_pre_asns) and len(negotiated.neighbor.bgpsec_pre_skis) :

          # pre asns, pre skis : came from the configuration 'bgpsec_pre_asns', 'bgpsec_pre_skis'
          self.pre_asns.extend([int(i) for i in negotiated.neighbor.bgpsec_pre_asns])
          self.pre_skis = negotiated.neighbor.bgpsec_pre_skis

          # all asns and skis include its own asn which doesn't belong to pre-asns
          self.all_asns.extend(self.pre_asns)
          self.all_skis.extend(self.pre_skis)

          #dict_asn_ski = dict (zip(self.pre_asns, self.pre_skis)) # python 3
          self.dict_asn_ski = {k: v for k, v in zip(self.pre_asns, self.pre_skis)} # python 2.7

          # making bgpsec stacks for encapsulation with recursive call
          bOrigin = True
          asns = []
          skis = []
          for asn in self.pre_asns[::-1] :

            if bOrigin :
              asns.append(asn)
              skis.append(self.dict_asn_ski[asn])
              bOrigin = False

            asns.reverse(), skis.reverse()
            battr = self.bgpsec_pack (negotiated, asns, skis)
            self.bgpsec_pre_attrs.append(battr)
            asns.reverse(), skis.reverse()

            if len(self.pre_asns) >1 and asn != self.pre_asns[0] :
              prev_asn = self.pre_asns[self.pre_asns.index(asn)-1]
              asns.append(prev_asn)
              skis.append(self.dict_asn_ski[prev_asn])

            # To generate  SCA_BGPSecValidationData #FIXME: asn below should be changed with peer_as (target) ??
            self.crtbgp.make_bgpsecValData(asn, self.nlri_ip, self.nlri_mask, battr)



    def _secure_path_segment (self, negotiated, asns=None):
        segment = []

        if not asns:
            asns = copy.deepcopy(self.all_asns)
            #asns.reverse()

        #for asn in reversed(asns):
        for asn in asns:
          segment.append(pack('!B', self.PCOUNT))
          segment.append(pack('!B', self.SP_FLAG))
          segment.append(pack('!L', asn))
          self.secure_path_len += self.PATH_SEG_UNIT_LEN  # secure path attribute (6)

        return segment


    def _secure_path (self, negotiated, asns=None):
        self.secure_path = self._secure_path_segment(negotiated, asns)
        return concat_bytes(pack('!H', (self.secure_path_len+self.SEC_PATH_LEN)), b''.join(self.secure_path))


    def _signature_from_lib (self, asn=None, ski=None):
        if BGPSEC._init_lib != True:
            #self.crtbgp.crypto_init(self.negotiated.neighbor.bgpsec_crypto_init[0], 7)
            ret = self.crtbgp.crypto_init()
            if not ret :
                print("CryptoAPI Init failed")
                return None
            BGPSEC._init_lib = True

        # TODO: need better comparison statement for asn and ski
        # TODO: ski_str need to be modified
        if not asn or not ski :
          ret_sig = self.crtbgp.crypto_sign(self.negotiated.local_as, self.negotiated.peer_as,
                      self.nlri_ip, self.nlri_mask, self.ski_str, self.bgpsec_pre_attrs)

        else:

          if asn in self.dict_signatures :
            return self.dict_signatures.get(asn)

          host_asn_index = self.all_asns.index(asn)
          if host_asn_index < 1:
            return None

          peer_asn = self.all_asns[host_asn_index-1]
          ret_sig = self.crtbgp.crypto_sign(asn, peer_asn, self.nlri_ip, self.nlri_mask,
                                            ski, self.bgpsec_pre_attrs)

          # store signatures with asn key
          self.dict_signatures.setdefault(asn, ret_sig)

        return ret_sig



    def _signature (self, asn=None, ski=None):
        signature = []
        signature = self._signature_from_lib(asn, ski)
        if not signature : # in case None
          #self.logger.BGPSEC("Signature is not made due to Key issues")
          return None

        self.signature_block_len += len(signature)
        return concat_bytes( pack('!H', len(signature)), b''.join(signature))


    def _signature_segment (self, asns=None, skis=None):
        sig_segment = []

        if not skis or not asns:
          skis = copy.deepcopy(self.all_skis)
          #skis.reverse()

        # split SKI string into 2 letters
        step = 2
        #for ski in reversed(skis):
        for ski in skis:
          #self.ski_str = self.negotiated.neighbor.ski[0]
          self.ski_str = ski
          splitSKI = [ski[i:i+step] for i in range(0, len(ski), step) ]

          # convert hexstring into integer
          result = [ character( int(splitSKI[i], 16)) for i in range (0, len(splitSKI))]
          sig_segment.extend(result)

          # processing signatures
          # dict-asn-ski.keys(): list of keys, dict.values(): list of values  list.index(n): index number
          if self.dict_asn_ski and ski in self.dict_asn_ski.values() :
            host_asn = list(self.dict_asn_ski.keys())[list(self.dict_asn_ski.values()).index(ski)]
          else :
            # TODO: need default action
            host_asn = None

          sig_segment_value = self._signature(host_asn, ski)
          if not sig_segment_value :
              return None

          sig_segment.append(sig_segment_value)
          self.signature_block_len += self.SIG_LEN + self.SKI_LEN
        return sig_segment


    def _signature_block (self, negotiated, asns=None, skis=None):
        sig_block = list()

        sig_block.append(pack('!B', self.ALGO_ID))
        self.signature_block_len += len(chr(self.ALGO_ID))
        self.signature_segment = self._signature_segment(asns, skis)
        if not self.signature_segment :
            return None
        sig_block.extend(self.signature_segment)
        return sig_block


    def _signature_blocks (self, negotiated, asns=None, skis=None):
        self.signature_block = self._signature_block(negotiated, asns, skis)
        if not self.signature_block :
            return None
        return concat_bytes(pack('!H', (self.signature_block_len+self.SIG_BLOCK_LEN)), b''.join(self.signature_block))


    def bgpsec_pack (self, negotiated, asns=None, skis=None):
        # Secure Path & Signature Block needed from here
        # extract the proper information from 'negotiated' variable

        self.secure_path_len = 0
        self.signature_block_len = 0

        attr_sp = self._secure_path(negotiated, asns)
        attr_sb = self._signature_blocks(negotiated, asns, skis)

        if not attr_sb :
            return None
        bgpsec_attr = attr_sp + attr_sb

        # make bgpsec_attr and packed have complete format of attribute (Flag, Type, Length, Value)
        self.packed = bgpsec_attr = self._attribute(bgpsec_attr)
        return bgpsec_attr #self.packed

    def pack (self, negotiated=None):
        #self.dict_asn_ski = None
        if negotiated:
            bp = self.bgpsec_pack(negotiated)
            if not bp :
                return b''
            return bp

    @classmethod
    def unpack (cls, data, negotiated):
        mpnlri={}
        return cls(negotiated, mpnlri)









"""
    +-----------------------------------------------+
    | Secure_Path Length                 (2 octets) |
    +-----------------------------------------------+
    | One or more Secure_Path Segments   (variable) |
    +-----------------------------------------------+
    Figure 4: Secure_Path Format


    +------------------------------------------------------+
    | pCount         (1 octet)                             |
    +------------------------------------------------------+
    | Confed_Segment flag (1 bit) |  Unassigned (7 bits)   | (Flags)
    +------------------------------------------------------+
    | AS Number      (4 octets)                            |
    +------------------------------------------------------+
    Figure 5: Secure_Path Segment Format


    +---------------------------------------------+
    | Signature_Block Length         (2 octets)   |
    +---------------------------------------------+
    | Algorithm Suite Identifier     (1 octet)    |
    +---------------------------------------------+
    | Sequence of Signature Segments (variable)   |
    +---------------------------------------------+
    Figure 6: Signature_Block Format


    +---------------------------------------------+
    | Subject Key Identifier (SKI)  (20 octets)   |
    +---------------------------------------------+
    | Signature Length              (2 octets)    |
    +---------------------------------------------+
    | Signature                     (variable)    |
    +---------------------------------------------+
    Figure 7: Signature Segment Format

"""
