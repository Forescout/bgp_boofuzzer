import argparse
from boofuzz import *
from boofuzz import helpers
from boofuzz import constants
from base.bgp_route_refresh import BaseRouteRefreshFuzzer

'''
BGP ROUTE REFRESH #1

- The BGP header length is correct
- The "AFI" field is fuzzable
- The "Subtype" field is set to supported values, as per RFC 7313 (plus, one "unknown" value 0x03)
- The "SAFI' field is fuzzable
'''
class BgpRouteRefreshFuzzer_1(BaseRouteRefreshFuzzer):
    def __init__(self, bgp_id, asn_id, rhost, rpc_port=1234, rport='179', hold_time=240):
        super().__init__(bgp_id, asn_id, rhost, rpc_port, rport, hold_time)
        self.poc_name = 'BgpRouteRefreshFuzzer_1_testcase_%s.py'

    def do_fuzz(self):
        PARAM_ASN_ID = self.asn_id
        PARAM_BGP_ID = self.bgp_id
        PARAM_HOLD_TIME = self.hold_time

        s_initialize("bgp_open")
        if s_block_start("BGP"):
            if s_block_start("Header"):
                s_bytes(value=b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", padding=b"\xFF", size=16, name="Marker", fuzzable=False)
                s_size(block_name="Open", length=2, math=lambda x: x + 19, name="Length", endian=BIG_ENDIAN, fuzzable=False) # keep right length
                s_byte(value=0x01, endian=BIG_ENDIAN, name="Type", fuzzable=False)
            s_block_end()
            if s_block_start("Open"):
                s_byte(value=0x04, endian=BIG_ENDIAN, name="version", fuzzable=False)
                s_word(value=PARAM_ASN_ID, endian=BIG_ENDIAN, name="ASN", fuzzable=False)
                s_word(value=PARAM_HOLD_TIME, endian=BIG_ENDIAN, name="Hold Time", fuzzable=False)
                s_dword(value=helpers.ip_str_to_bytes(PARAM_BGP_ID), endian=BIG_ENDIAN, name="BGP Identifier", fuzzable=False)
                s_bytes(value=b"\x42\x02\x06\x01\x04\x00\x01\x00\x01\x02\x02\x80\x00\x02\x02\x02\x00\x02\x02\x46\x00\x02\x06\x41\x04\x00\x00" + PARAM_ASN_ID.to_bytes(2, 'big') + b"\x02\x02\x06\x00\x02\x06\x45\x04\x00\x01\x01\x01\x02\x07\x49\x05\x03\x62\x6f\x78\x00\x02\x04\x40\x02\x40\x78\x02\x09\x47\x07\x00\x01\x01\x80\x00\x00\x00", fuzzable=False)
            s_block_end()
        s_block_end()

        s_initialize("bgp_keepalive")
        if s_block_start("BGP"):
            if s_block_start("Header"):
                s_bytes(value=b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", padding=b"\xFF", size=16, name="Marker", fuzzable=False)
                s_size(block_name="Keepalive", length=2, math=lambda x: x + 19, name="Length", endian=BIG_ENDIAN, fuzzable=False)
                s_byte(value=0x04, endian=BIG_ENDIAN, name="Type", fuzzable=False)
            s_block_end()
            if s_block_start("Keepalive"):
                pass
            s_block_end()
        s_block_end()

        s_initialize("bgp_refresh")
        if s_block_start("BGP"):
            if s_block_start("Header"):
                s_bytes(value=b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", padding=b"\xFF", size=16, name="Marker", fuzzable=False)
                s_size(block_name="Refresh", length=2, math=lambda x: x + 19, name="Length", endian=BIG_ENDIAN, fuzzable=False) # keep right length
                s_byte(value=0x05, endian=BIG_ENDIAN, name="Type", fuzzable=False)
            s_block_end()
            if s_block_start("Refresh"):
                s_word(value=0x0, endian=BIG_ENDIAN, name="afi", fuzzable=True)
                s_group(values=[b'\x00', b'\x01', b'\x02', b'\x03', b'\xff'], name='subtype')
                s_byte(value=0x0, endian=BIG_ENDIAN, name="safi", fuzzable=True)
            s_block_end()
        s_block_end()

        self.session_handle.connect(s_get("bgp_open"))
        self.session_handle.connect(s_get("bgp_open"),s_get("bgp_keepalive"))
        self.session_handle.connect(s_get("bgp_keepalive"), s_get("bgp_refresh"))
        self.session_handle.fuzz()

'''
BGP ROUTE REFRESH #2

- The BGP header length is correct
- The message body is a random fuzzload
'''
class BgpRouteRefreshFuzzer_2(BaseRouteRefreshFuzzer):
    def __init__(self, bgp_id, asn_id, rhost, rpc_port=1234, rport='179', hold_time=240):
        super().__init__(bgp_id, asn_id, rhost, rpc_port, rport, hold_time)
        self.poc_name = 'BgpRouteRefreshFuzzer_2_testcase_%s.py'

    def do_fuzz(self):
        PARAM_ASN_ID = self.asn_id
        PARAM_BGP_ID = self.bgp_id
        PARAM_HOLD_TIME = self.hold_time

        s_initialize("bgp_open")
        if s_block_start("BGP"):
            if s_block_start("Header"):
                s_bytes(value=b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", padding=b"\xFF", size=16, name="Marker", fuzzable=False)
                s_size(block_name="Open", length=2, math=lambda x: x + 19, name="Length", endian=BIG_ENDIAN, fuzzable=False) # keep right length
                s_byte(value=0x01, endian=BIG_ENDIAN, name="Type", fuzzable=False)
            s_block_end()
            if s_block_start("Open"):
                s_byte(value=0x04, endian=BIG_ENDIAN, name="version", fuzzable=False)
                s_word(value=PARAM_ASN_ID, endian=BIG_ENDIAN, name="ASN", fuzzable=False)
                s_word(value=PARAM_HOLD_TIME, endian=BIG_ENDIAN, name="Hold Time", fuzzable=False)
                s_dword(value=helpers.ip_str_to_bytes(PARAM_BGP_ID), endian=BIG_ENDIAN, name="BGP Identifier", fuzzable=False)
                s_bytes(value=b"\x42\x02\x06\x01\x04\x00\x01\x00\x01\x02\x02\x80\x00\x02\x02\x02\x00\x02\x02\x46\x00\x02\x06\x41\x04\x00\x00" + PARAM_ASN_ID.to_bytes(2, 'big') + b"\x02\x02\x06\x00\x02\x06\x45\x04\x00\x01\x01\x01\x02\x07\x49\x05\x03\x62\x6f\x78\x00\x02\x04\x40\x02\x40\x78\x02\x09\x47\x07\x00\x01\x01\x80\x00\x00\x00", fuzzable=False)
            s_block_end()
        s_block_end()

        s_initialize("bgp_keepalive")
        if s_block_start("BGP"):
            if s_block_start("Header"):
                s_bytes(value=b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", padding=b"\xFF", size=16, name="Marker", fuzzable=False)
                s_size(block_name="Keepalive", length=2, math=lambda x: x + 19, name="Length", endian=BIG_ENDIAN, fuzzable=False)
                s_byte(value=0x04, endian=BIG_ENDIAN, name="Type", fuzzable=False)
            s_block_end()
            if s_block_start("Keepalive"):
                pass
            s_block_end()
        s_block_end()

        s_initialize("bgp_refresh")
        if s_block_start("BGP"):
            if s_block_start("Header"):
                s_bytes(value=b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", padding=b"\xFF", size=16, name="Marker", fuzzable=False)
                s_size(block_name="Refresh", length=2, math=lambda x: x + 19, name="Length", endian=BIG_ENDIAN, fuzzable=False) # keep right length
                s_byte(value=0x05, endian=BIG_ENDIAN, name="Type", fuzzable=False)
            s_block_end()
            if s_block_start("Refresh"):
               s_random(num_mutations=1024, min_length=0, max_length=1024, fuzzable=True)
            s_block_end()
        s_block_end()

        self.session_handle.connect(s_get("bgp_open"))
        self.session_handle.connect(s_get("bgp_open"),s_get("bgp_keepalive"))
        self.session_handle.connect(s_get("bgp_keepalive"), s_get("bgp_refresh"))
        self.session_handle.fuzz()


'''
BGP ROUTE REFRESH #3

- The BGP header length is correct
- This one is to test specific stuff in the FRRouting project 
'''
class BgpRouteRefreshFuzzer_3(BaseRouteRefreshFuzzer):
    def __init__(self, bgp_id, asn_id, rhost, rpc_port=1234, rport='179', hold_time=240):
        super().__init__(bgp_id, asn_id, rhost, rpc_port, rport, hold_time)
        self.poc_name = 'BgpRouteRefreshFuzzer_3_testcase_%s.py'

    def do_fuzz(self):
        PARAM_ASN_ID = self.asn_id
        PARAM_BGP_ID = self.bgp_id
        PARAM_HOLD_TIME = self.hold_time

        s_initialize("bgp_open")
        if s_block_start("BGP"):
            if s_block_start("Header"):
                s_bytes(value=b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", padding=b"\xFF", size=16, name="Marker", fuzzable=False)
                s_size(block_name="Open", length=2, math=lambda x: x + 19, name="Length", endian=BIG_ENDIAN, fuzzable=False) # keep right length
                s_byte(value=0x01, endian=BIG_ENDIAN, name="Type", fuzzable=False)
            s_block_end()
            if s_block_start("Open"):
                s_byte(value=0x04, endian=BIG_ENDIAN, name="version", fuzzable=False)
                s_word(value=PARAM_ASN_ID, endian=BIG_ENDIAN, name="ASN", fuzzable=False)
                s_word(value=PARAM_HOLD_TIME, endian=BIG_ENDIAN, name="Hold Time", fuzzable=False)
                s_dword(value=helpers.ip_str_to_bytes(PARAM_BGP_ID), endian=BIG_ENDIAN, name="BGP Identifier", fuzzable=False)
                s_bytes(value=b"\x42\x02\x06\x01\x04\x00\x01\x00\x01\x02\x02\x80\x00\x02\x02\x02\x00\x02\x02\x46\x00\x02\x06\x41\x04\x00\x00" + PARAM_ASN_ID.to_bytes(2, 'big') + b"\x02\x02\x06\x00\x02\x06\x45\x04\x00\x01\x01\x01\x02\x07\x49\x05\x03\x62\x6f\x78\x00\x02\x04\x40\x02\x40\x78\x02\x09\x47\x07\x00\x01\x01\x80\x00\x00\x00", fuzzable=False)
            s_block_end()
        s_block_end()

        s_initialize("bgp_keepalive")
        if s_block_start("BGP"):
            if s_block_start("Header"):
                s_bytes(value=b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", padding=b"\xFF", size=16, name="Marker", fuzzable=False)
                s_size(block_name="Keepalive", length=2, math=lambda x: x + 19, name="Length", endian=BIG_ENDIAN, fuzzable=False)
                s_byte(value=0x04, endian=BIG_ENDIAN, name="Type", fuzzable=False)
            s_block_end()
            if s_block_start("Keepalive"):
                pass
            s_block_end()
        s_block_end()

        s_initialize("bgp_refresh")
        with s_block("BGP"):
            with s_block("Header"):
                s_bytes(value=b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", padding=b"\xFF", size=16, name="Marker", fuzzable=False)
                s_size(block_name="Refresh", length=2, math=lambda x: x + 19, name="Length", endian=BIG_ENDIAN, fuzzable=False) # keep right length
                s_byte(value=0x05, endian=BIG_ENDIAN, name="Type", fuzzable=False)
            with s_block("Refresh"):
                s_word(value=0x1, endian=BIG_ENDIAN, name="afi", fuzzable=False)
                s_byte(value=0x0, endian=BIG_ENDIAN, name="type", fuzzable=False)
                s_byte(value=0x1, endian=BIG_ENDIAN, name="safi", fuzzable=False)
                with s_block('FUZZLOAD'):
                   s_byte(name='when_to_refresh', value=0, fuzzable=False)
                   s_byte(name='orf_type', value=64, fuzzable=False)
                   s_word(name='orf_len', endian=BIG_ENDIAN, value=7, fuzzable=False)
                   s_random(num_mutations=1024, min_length=13, max_length=13, fuzzable=True)

        self.session_handle.connect(s_get("bgp_open"))
        self.session_handle.connect(s_get("bgp_open"),s_get("bgp_keepalive"))
        self.session_handle.connect(s_get("bgp_keepalive"), s_get("bgp_refresh"))
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
    fuzzer = BgpRouteRefreshFuzzer_1(bgp_id=FBGP_ID, asn_id=FASN, rhost=TIP, rpc_port=TRPC_PORT)
    #fuzzer = BgpRouteRefreshFuzzer_2(bgp_id=FBGP_ID, asn_id=FASN, rhost=TIP, rpc_port=TRPC_PORT)
    #fuzzer = BgpRouteRefreshFuzzer_3(bgp_id=FBGP_ID, asn_id=FASN, rhost=TIP, rpc_port=TRPC_PORT)
    fuzzer.do_fuzz()
