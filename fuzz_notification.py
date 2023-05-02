import argparse
from boofuzz import *
from base.bgp_notification import BaseNotificationFuzzer

'''
BGP NOTIFICATION #1

- Error code is fuzzable
- Error subcode is fuzzable
- Error data is a random fuzzload
'''

class BgpNotificationFuzzer_1(BaseNotificationFuzzer):
    def __init__(self, bgp_id, asn_id, rhost, rpc_port=1234, rport='179', hold_time=240):
        super().__init__(bgp_id, asn_id, rhost, rpc_port, rport, hold_time)
        self.poc_name = 'BgpNotificationFuzzer_1_testcase_%s.py'

    def do_fuzz(self):
        s_initialize("BGP_NOTIFICATION")
        with s_block("BGP"):
            with s_block("Header"):
                s_bytes(value=b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", padding=b"\xFF", size=16, name="Marker", fuzzable=False)
                s_size(block_name="Notification", length=2, math=lambda x: x + 19, name="Length", endian=BIG_ENDIAN, fuzzable=False)
                s_byte(value=0x03, endian=BIG_ENDIAN, name="Type", fuzzable=False)
            with s_block("Notification"):
                s_byte(name='error_code', value=0x00, fuzzable=False)
                s_byte(name='error_subcode', value=0x00, fuzzable=False)
                s_random(name='data', min_length=0, max_length=4096, num_mutations=4096, fuzzable=True)

        self.session_handle.connect(s_get("BGP_NOTIFICATION"))
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
    fuzzer = BgpNotificationFuzzer_1(bgp_id=FBGP_ID, asn_id=FASN, rhost=TIP, rpc_port=TRPC_PORT)
    fuzzer.do_fuzz()
