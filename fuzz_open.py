import time
import random
import argparse
from boofuzz import *
from boofuzz import helpers
from boofuzz import constants
from base.bgp_open import BGPOpenFuzzerBase

'''
BGP OPEN #1

- BGP header length is correct
- 'Non-Ext OP Len' and 'Non-Ext OP Type' are set to 0xff (extended OPEN)
- Extended Optional parameter length (2 octets) is correct 
- The OPEN message contains between 1 and 4 optional parameters (at random)
- The 'Parameter value' and 'Parameter length' fields are fuzzable

NOTE: Triggers CVE-2022-40302 in FRRouting.
'''
class BgpOpenFuzzer_1(BGPOpenFuzzerBase):

    def __init__(self, bgp_id, asn_id, rhost, rpc_port=1234, rport='179', hold_time=240):
        super().__init__(bgp_id, asn_id, rhost, rpc_port, rport, hold_time)
        self.poc_name = 'BgpOpenFuzzer_1_testcase_%s.py'
        random.seed(time.time())

    def do_fuzz(self):
        PARAM_ASN_ID = self.asn_id
        PARAM_BGP_ID = self.bgp_id
        PARAM_HOLD_TIME = self.hold_time

        s_initialize('bgp_open')
        if s_block_start('BGP'):
            if s_block_start('Header'):
                s_bytes(value=b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF', padding=b'\xFF', size=16, name='Marker', fuzzable=False)
                s_size(block_name='Open', length=2, math=lambda x: x + 19, name='Length', endian=BIG_ENDIAN, fuzzable=False)
                s_byte(value=0x01, endian=BIG_ENDIAN, name='Type', fuzzable=False)
            s_block_end()
            if s_block_start('Open'):
                s_byte(value=0x04, endian=BIG_ENDIAN, name='version', fuzzable=False)
                s_word(value=PARAM_ASN_ID, endian=BIG_ENDIAN, name='ASN', fuzzable=False)
                s_word(value=PARAM_HOLD_TIME, endian=BIG_ENDIAN, name='Hold Time', fuzzable=False)
                s_dword(value=helpers.ip_str_to_bytes(PARAM_BGP_ID), endian=BIG_ENDIAN, name='BGP Identifier', fuzzable=False)
                s_byte(value=b'\xff', endian='>', name='Non-Ext OP Len', fuzzable=False)
                s_byte(value=b'\xff', endian='>', name = 'Non-Ext OP Type', fuzzable=False)
                s_size(block_name='Optional Parameters', length=2, name='Extended Opt. Parm Length', endian=BIG_ENDIAN, fuzzable=False)
                if s_block_start('Optional Parameters'):
                    for param_i in range(random.randint(1, 5)):
                        if s_block_start(f'Reserved {param_i}'):
                            s_byte(value=0x00, endian=BIG_ENDIAN, name='Parameter Type', fuzzable=False)
                            s_size(block_name=f'Reserved Parameter Value {param_i}', length=1, name='Parameter Length', endian=BIG_ENDIAN, fuzzable=True)
                            s_string(value='', name=f'Reserved Parameter Value {param_i}', padding=b'\x00', fuzzable=True, max_len=1500)
                        s_block_end()
                s_block_end()
            s_block_end()
        s_block_end()

        s_initialize('bgp_keepalive')
        if s_block_start('BGP'):
            if s_block_start('Header'):
                s_bytes(value=b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF', padding=b'\xFF', size=16, name='Marker', fuzzable=False)
                s_size(block_name='Keepalive', length=2, math=lambda x: x + 19, name='Length', endian=BIG_ENDIAN, fuzzable=False)
                s_byte(value=0x04, endian=BIG_ENDIAN, name='Type', fuzzable=False)
            s_block_end()
            if s_block_start('Keepalive'):
                pass
            s_block_end()
        s_block_end()

        self.session_handle.connect(s_get('bgp_open'))
        self.session_handle.connect(s_get('bgp_open'),s_get('bgp_keepalive'))
        self.session_handle.fuzz()

'''
BGP OPEN #2

- BGP header length is correct
- Optional Parameters length is fuzzable and is of the size of 1 octet (non-extended OPEN)
- Optional parameters are fuzzable with a random payload (4096 mutations) 

NOTE: Triggers CVE-2022-43681 in FRRouting.
'''
class BgpOpenFuzzer_2(BGPOpenFuzzerBase):
    def __init__(self, bgp_id, asn_id, rhost, rpc_port=1234, rport='179', hold_time=240):
        super().__init__(bgp_id, asn_id, rhost, rpc_port, rport, hold_time)
        self.poc_name = 'BgpOpenFuzzer_2_testcase_%s.py'

    def do_fuzz(self):
        PARAM_ASN_ID = self.asn_id
        PARAM_BGP_ID = self.bgp_id
        PARAM_HOLD_TIME = self.hold_time

        s_initialize('BGP_OPEN')
        with s_block('BGP'):
            with s_block('Header'):
                s_bytes(value=b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF', padding=b'\xFF', size=16, name='Marker', fuzzable=False)
                s_size(block_name='Open', length=2, math=lambda x: x + 19, name='Length', endian=BIG_ENDIAN, fuzzable=False)
                s_byte(value=0x01, endian=BIG_ENDIAN, name='Type', fuzzable=False)
            with s_block('Open'):
                s_byte(value=0x04, endian=BIG_ENDIAN, name='version', fuzzable=False)
                s_word(value=PARAM_ASN_ID, endian=BIG_ENDIAN, name='ASN', fuzzable=False)
                s_word(value=PARAM_HOLD_TIME, endian=BIG_ENDIAN, name='Hold Time', fuzzable=False)
                s_dword(value=helpers.ip_str_to_bytes(PARAM_BGP_ID), endian=BIG_ENDIAN, name='BGP Identifier', fuzzable=False)
                s_byte(value=b'\x00', endian=BIG_ENDIAN, name = 'Opt Parm Len', fuzzable=True)
                with s_block('Optional Parameters'):
                    s_random(name='params', max_length=4096, num_mutations=4096, fuzzable=True)

        s_initialize('BGP_KEEPALIVE')                                                                        
        with s_block('Header'):                                                                                     
            s_static(name='marker', value=b'\xff'*16)                                                               
            s_static(name='length', value=b'\x00\x13')                            
            s_static(name='type', value=b'\x04')  

        self.session_handle.connect(s_get('BGP_OPEN'))
        self.session_handle.connect(s_get('BGP_OPEN'),s_get('BGP_KEEPALIVE'))
        self.session_handle.fuzz()

'''
BGP OPEN #3

- BGP header length is correct
- Optional parameters and their length are fuzzable with a random payload (4096 mutations) 
'''
class BgpOpenFuzzer_3(BGPOpenFuzzerBase):
    def __init__(self, bgp_id, asn_id, rhost, rpc_port=1234, rport='179', hold_time=240):
        super().__init__(bgp_id, asn_id, rhost, rpc_port, rport, hold_time)
        self.poc_name = 'BgpOpenFuzzer_3_testcase_%s.py'

    def do_fuzz(self):
        PARAM_ASN_ID = self.asn_id
        PARAM_BGP_ID = self.bgp_id
        PARAM_HOLD_TIME = self.hold_time

        s_initialize('BGP_OPEN')
        with s_block('BGP'):
            with s_block('Header'):
                s_bytes(value=b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF', padding=b'\xFF', size=16, name='Marker', fuzzable=False)
                s_size(block_name='Open', length=2, math=lambda x: x + 19, name='Length', endian=BIG_ENDIAN, fuzzable=False)
                s_byte(value=0x01, endian=BIG_ENDIAN, name='Type', fuzzable=False)
            with s_block('Open'):
                s_byte(value=0x04, endian=BIG_ENDIAN, name='version', fuzzable=False)
                s_word(value=PARAM_ASN_ID, endian=BIG_ENDIAN, name='ASN', fuzzable=False)
                s_word(value=PARAM_HOLD_TIME, endian=BIG_ENDIAN, name='Hold Time', fuzzable=False)
                s_dword(value=helpers.ip_str_to_bytes(PARAM_BGP_ID), endian=BIG_ENDIAN, name='BGP Identifier', fuzzable=False)
                with s_block('Optional Parameters'):
                    s_random(name='params', max_length=4096, num_mutations=4096, fuzzable=True)

        s_initialize('BGP_KEEPALIVE')                                                                        
        with s_block('Header'):                                                                                     
            s_static(name='marker', value=b'\xff'*16)                                                               
            s_static(name='length', value=b'\x00\x13')                            
            s_static(name='type', value=b'\x04')  

        self.session_handle.connect(s_get('BGP_OPEN'))
        self.session_handle.connect(s_get('BGP_OPEN'),s_get('BGP_KEEPALIVE'))
        self.session_handle.fuzz()

'''
BGP OPEN #4

- BGP header length is correct
- Optional parameter length is correct
- Optional parameters are fuzzable with a random payload (4096 mutations) 
'''
class BgpOpenFuzzer_4(BGPOpenFuzzerBase):
    def __init__(self, bgp_id, asn_id, rhost, rpc_port=1234, rport='179', hold_time=240):
        super().__init__(bgp_id, asn_id, rhost, rpc_port, rport, hold_time)
        self.poc_name = 'BgpOpenFuzzer_4_testcase_%s.py'

    def do_fuzz(self):
        PARAM_ASN_ID = self.asn_id
        PARAM_BGP_ID = self.bgp_id
        PARAM_HOLD_TIME = self.hold_time

        s_initialize('BGP_OPEN')
        with s_block('BGP'):
            with s_block('Header'):
                s_bytes(value=b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF', padding=b'\xFF', size=16, name='Marker', fuzzable=False)
                s_size(block_name='Open', length=2, math=lambda x: x + 19, name='Length', endian=BIG_ENDIAN, fuzzable=False)
                s_byte(value=0x01, endian=BIG_ENDIAN, name='Type', fuzzable=False)
            with s_block('Open'):
                s_byte(value=0x04, endian=BIG_ENDIAN, name='version', fuzzable=False)
                s_word(value=PARAM_ASN_ID, endian=BIG_ENDIAN, name='ASN', fuzzable=False)
                s_word(value=PARAM_HOLD_TIME, endian=BIG_ENDIAN, name='Hold Time', fuzzable=False)
                s_dword(value=helpers.ip_str_to_bytes(PARAM_BGP_ID), endian=BIG_ENDIAN, name='BGP Identifier', fuzzable=False)
                s_size(block_name='Optional Parameters', length=1, name='Opt.Parm.Len.', endian=BIG_ENDIAN, fuzzable=False)
                with s_block('Optional Parameters'):
                    s_random(name='params', max_length=4096, num_mutations=4096, fuzzable=True)

        s_initialize('BGP_KEEPALIVE')                                                                        
        with s_block('Header'):                                                                                     
            s_static(name='marker', value=b'\xff'*16)                                                               
            s_static(name='length', value=b'\x00\x13')                            
            s_static(name='type', value=b'\x04')  

        self.session_handle.connect(s_get('BGP_OPEN'))
        self.session_handle.connect(s_get('BGP_OPEN'),s_get('BGP_KEEPALIVE'))
        self.session_handle.fuzz()

'''
BGP OPEN #5

- BGP header length is correct
- There's only one optional parameter and it's type is fuzzable
- The length of the optional parameter is correct
- The value of the optional parameter is fuzzable with a random payload (4096 mutations)
'''
class BgpOpenFuzzer_5(BGPOpenFuzzerBase):
    def __init__(self, bgp_id, asn_id, rhost, rpc_port=1234, rport='179', hold_time=240):
        super().__init__(bgp_id, asn_id, rhost, rpc_port, rport, hold_time)
        self.poc_name = 'BgpOpenFuzzer_5_testcase_%s.py'

    def do_fuzz(self):
        PARAM_ASN_ID = self.asn_id
        PARAM_BGP_ID = self.bgp_id
        PARAM_HOLD_TIME = self.hold_time

        s_initialize('BGP_OPEN')
        with s_block('BGP'):
            with s_block('Header'):
                s_bytes(value=b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF', padding=b'\xFF', size=16, name='Marker', fuzzable=False)
                s_size(block_name='Open', length=2, math=lambda x: x + 19, name='Length', endian=BIG_ENDIAN, fuzzable=False)
                s_byte(value=0x01, endian=BIG_ENDIAN, name='Type', fuzzable=False)
            with s_block('Open'):
                s_byte(value=0x04, endian=BIG_ENDIAN, name='version', fuzzable=False)
                s_word(value=PARAM_ASN_ID, endian=BIG_ENDIAN, name='ASN', fuzzable=False)
                s_word(value=PARAM_HOLD_TIME, endian=BIG_ENDIAN, name='Hold Time', fuzzable=False)
                s_dword(value=helpers.ip_str_to_bytes(PARAM_BGP_ID), endian=BIG_ENDIAN, name='BGP Identifier', fuzzable=False)
                s_size(block_name='Optional Parameters', length=1, name='Opt.Parm.Len.', endian=BIG_ENDIAN, fuzzable=False)
                with s_block('Optional Parameters'):
                    s_byte(name='PARM_TYPE', endian=BIG_ENDIAN, fuzzable=True)
                    s_size(block_name='PARM_VALUE', length=1, name='PARM_LEN', fuzzable=False)
                    with s_block('PARM_VALUE'):
                        s_random(max_length=255, num_mutations=4096, fuzzable=True)

        s_initialize('BGP_KEEPALIVE')                                                                        
        with s_block('Header'):                                                                                     
            s_static(name='marker', value=b'\xff'*16)                                                               
            s_static(name='length', value=b'\x00\x13')                            
            s_static(name='type', value=b'\x04')  

        self.session_handle.connect(s_get('BGP_OPEN'))
        self.session_handle.connect(s_get('BGP_OPEN'),s_get('BGP_KEEPALIVE'))
        self.session_handle.fuzz()

'''
BGP OPEN #6

- BGP header length is correct
- The OPEN message after the 'bgp identifier' octet is a random fuzzload 
'''
class BgpOpenFuzzer_6(BGPOpenFuzzerBase):
    def __init__(self, bgp_id, asn_id, rhost, rpc_port=1234, rport='179', hold_time=240):
        super().__init__(bgp_id, asn_id, rhost, rpc_port, rport, hold_time)
        self.poc_name = 'BgpOpenFuzzer_6_testcase_%s.py'

    def do_fuzz(self):
        PARAM_ASN_ID = self.asn_id
        PARAM_BGP_ID = self.bgp_id
        PARAM_HOLD_TIME = self.hold_time

        s_initialize('BGP_OPEN')
        with s_block('BGP'):
            with s_block('Header'):
                s_bytes(value=b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF', padding=b'\xFF', size=16, name='Marker', fuzzable=False)
                s_size(block_name='Open', length=2, math=lambda x: x + 19, name='Length', endian=BIG_ENDIAN, fuzzable=False)
                s_byte(value=0x01, endian=BIG_ENDIAN, name='Type', fuzzable=False)
            with s_block('Open'):
                s_byte(value=0x04, endian=BIG_ENDIAN, name='version', fuzzable=False)
                s_word(value=PARAM_ASN_ID, endian=BIG_ENDIAN, name='ASN', fuzzable=False)
                s_word(value=PARAM_HOLD_TIME, endian=BIG_ENDIAN, name='Hold Time', fuzzable=False)
                s_dword(value=helpers.ip_str_to_bytes(PARAM_BGP_ID), endian=BIG_ENDIAN, name='BGP Identifier', fuzzable=False)
                s_random(name='FUZZLOAD', min_length=0, max_length=1024, num_mutations=65535, fuzzable=True)

        s_initialize('BGP_KEEPALIVE')                                                                        
        with s_block('Header'):                                                                                     
            s_static(name='marker', value=b'\xff'*16)                                                               
            s_static(name='length', value=b'\x00\x13')                            
            s_static(name='type', value=b'\x04')  

        self.session_handle.connect(s_get('BGP_OPEN'))
        self.session_handle.connect(s_get('BGP_OPEN'),s_get('BGP_KEEPALIVE'))
        self.session_handle.fuzz()

'''
Modify this code to choose different test suites and parameters.
'''
if __name__ == '__main__':
    '''
    Set the parameters
    '''
    argparser = argparse.ArgumentParser()
    argparser.add_argument('--fbgp_id', dest='fbgp_id', type=str, required=True, help='Fuzzer BGP ID.')
    argparser.add_argument('--fasn', dest='fasn', type=int, required=True, default=2, help='Fuzzer ASN number.')
    argparser.add_argument('--tip', dest='tip', type=str, required=True, help='Target IP address.')
    argparser.add_argument('--trpc_port', dest='trpc_port', type=int, required=True, default=1234, help='Target RPC port.')
    args = argparser.parse_args()

    FBGP_ID = args.fbgp_id
    FASN = args.fasn
    TIP = args.tip
    TRPC_PORT = args.trpc_port

    '''
    Instantiate and run a test suite
    '''
    fuzzer = BgpOpenFuzzer_1(bgp_id=FBGP_ID, asn_id=FASN, rhost=TIP, rpc_port=TRPC_PORT)
    #fuzzer = BgpOpenFuzzer_2(bgp_id=FBGP_ID, asn_id=FASN, rhost=TIP, rpc_port=TRPC_PORT)
    #fuzzer = BgpOpenFuzzer_3(bgp_id=FBGP_ID, asn_id=FASN, rhost=TIP, rpc_port=TRPC_PORT)
    #fuzzer = BgpOpenFuzzer_4(bgp_id=FBGP_ID, asn_id=FASN, rhost=TIP, rpc_port=TRPC_PORT)
    #fuzzer = BgpOpenFuzzer_5(bgp_id=FBGP_ID, asn_id=FASN, rhost=TIP, rpc_port=TRPC_PORT)
    #fuzzer = BgpOpenFuzzer_6(bgp_id=FBGP_ID, asn_id=FASN, rhost=TIP, rpc_port=TRPC_PORT)
    fuzzer.do_fuzz()
