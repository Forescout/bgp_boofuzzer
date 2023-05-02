import argparse
from boofuzz import *
from boofuzz import helpers
from boofuzz import constants
from base.bgp_update import BaseUpdateFuzzer

'''
BGP UPDATE #1

- BGP header length is correct
- Everything past the "type" octet is the fuzzload 
'''
class BgpUpdateFuzzer_1(BaseUpdateFuzzer):
    def __init__(self, bgp_id, asn_id, rhost, rpc_port=1234, rport='179', hold_time=240):
        super().__init__(bgp_id, asn_id, rhost, rpc_port, rport, hold_time)
        self.poc_name = 'BgpUpdateFuzzer_1_testcase_%s.py'

    def do_fuzz(self):
        PARAM_ASN_ID = self.asn_id
        PARAM_BGP_ID = self.bgp_id
        PARAM_HOLD_TIME = self.hold_time

        s_initialize('BGP_OPEN')    
        with s_block('HEADER'):    
            s_static(name='marker', value=b'\xff'*16)     
            s_static(name='length', value=b'\x00\x6b')    
            s_static(name='type', value=b'\x01')    
        with s_block('OPEN_MSG'):    
            s_static(name='version', value=b'\x04')    
            s_word(name='my_as', value=PARAM_ASN_ID, endian=BIG_ENDIAN, fuzzable=False)    
            s_word(value=PARAM_HOLD_TIME, endian=BIG_ENDIAN, name="Hold Time", fuzzable=False)
            s_static(name='bgp_identifier', value=helpers.ip_str_to_bytes(PARAM_BGP_ID))    
            s_static(name='opt_params_len', value=b'\x4e')    
            s_static(name='opt_params', value=b'\x02\x06\x01\x04\x00\x01\x00\x01\x02\x02\x80\x00\x02\x02\x02\x00' \
                                              b'\x02\x02\x46\x00\x02\x06\x41\x04\x00\x00\x00\x02\x02\x02\x06\x00' \
                                              b'\x02\x06\x45\x04\x00\x01\x01\x01\x02\x13\x49\x11\x0f\x73\x74\x61' \
                                              b'\x6e\x64\x61\x73\x68\x2d\x75\x62\x75\x6e\x74\x75\x00\x02\x04\x40' \
                                              b'\x02\xc0\x78\x02\x09\x47\x07\x00\x01\x01\x80\x00\x00\x00'                      
            )                                                                  
                                                                              
        s_initialize('BGP_KEEPALIVE')                                                                    
        with s_block('HEADER'):                                                                                 
            s_static(name='marker', value=b'\xff'*16)                                                           
            s_static(name='length', value=b'\x00\x13')                        
            s_static(name='type', value=b'\x04')     
                                                                                                     
                                                     
        s_initialize('BGP_UPDATE')                                                                    
        with s_block('HEADER'):                                      
           s_static(name='marker', value=b'\xff'*16)                  
           s_size(name='header_len', length=2, math=lambda x: x + 19, block_name='FUZZLOAD', endian=BIG_ENDIAN, fuzzable=False)
           s_static(name='type', value=b'\x02')                                                                                                                                                  
           with s_block('FUZZLOAD'):
               s_random(min_length=0, max_length=1024, num_mutations=1024, fuzzable=True)

        self.session_handle.connect(s_get('BGP_OPEN'))
        self.session_handle.connect(s_get('BGP_OPEN'),s_get('BGP_KEEPALIVE'))
        self.session_handle.connect(s_get('BGP_KEEPALIVE'),s_get('BGP_UPDATE'))
        self.session_handle.fuzz()


'''
BGP UPDATE #2

- BGP header length is correct
- Withdrawn routes length is set to 0x0000
- Total path attr. length is correct (dynamic)
- Path attributes is fuzzable (min len = 0, max len = 4068, mutations = 4096)
'''
class BgpUpdateFuzzer_2(BaseUpdateFuzzer):
    def __init__(self, bgp_id, asn_id, rhost, rpc_port=1234, rport='179', hold_time=240):
        super().__init__(bgp_id, asn_id, rhost, rpc_port, rport, hold_time)
        self.poc_name = 'BgpUpdateFuzzer_2_testcase_%s.py'

    def do_fuzz(self):
        PARAM_ASN_ID = self.asn_id
        PARAM_BGP_ID = self.bgp_id
        PARAM_HOLD_TIME = self.hold_time

        s_initialize('BGP_OPEN')    
        with s_block('HEADER'):    
            s_static(name='marker', value=b'\xff'*16)     
            s_static(name='length', value=b'\x00\x6b')    
            s_static(name='type', value=b'\x01')    
        with s_block('OPEN_MSG'):    
            s_static(name='version', value=b'\x04')    
            s_word(name='my_as', value=PARAM_ASN_ID, endian=BIG_ENDIAN, fuzzable=False)    
            s_word(value=PARAM_HOLD_TIME, endian=BIG_ENDIAN, name="Hold Time", fuzzable=False)
            s_static(name='bgp_identifier', value=helpers.ip_str_to_bytes(PARAM_BGP_ID))    
            s_static(name='opt_params_len', value=b'\x4e')    
            s_static(name='opt_params', value=b'\x02\x06\x01\x04\x00\x01\x00\x01\x02\x02\x80\x00\x02\x02\x02\x00' \
                                              b'\x02\x02\x46\x00\x02\x06\x41\x04\x00\x00\x00\x02\x02\x02\x06\x00' \
                                              b'\x02\x06\x45\x04\x00\x01\x01\x01\x02\x13\x49\x11\x0f\x73\x74\x61' \
                                              b'\x6e\x64\x61\x73\x68\x2d\x75\x62\x75\x6e\x74\x75\x00\x02\x04\x40' \
                                              b'\x02\xc0\x78\x02\x09\x47\x07\x00\x01\x01\x80\x00\x00\x00'                      
            )                                                                  
                                                                              
        s_initialize('BGP_KEEPALIVE')                                                                    
        with s_block('HEADER'):                                                                                 
            s_static(name='marker', value=b'\xff'*16)                                                           
            s_static(name='length', value=b'\x00\x13')                        
            s_static(name='type', value=b'\x04')     
                                                                                                     
                                                     
        s_initialize('BGP_UPDATE')                                                                    
        with s_block('HEADER'):                                      
           s_static(name='marker', value=b'\xff'*16)                  
           s_size(name='header_len', length=2, math=lambda x: x + 19, block_name='UPDATE', endian=BIG_ENDIAN, fuzzable=False)
           s_static(name='type', value=b'\x02')                                                                                                                                                  

           with s_block('UPDATE'):
               s_word(name='withdrawn_len', value=b'\x00\x00', endian=BIG_ENDIAN, fuzzable=False)          
               s_size(name='total_path_attr_len', length=2, block_name='FUZZLOAD', endian=BIG_ENDIAN, fuzzable=False)
               with s_block('FUZZLOAD'):
                   s_random(num_mutations=1024, min_length=0, max_length=1024, fuzzable=True)
      
        self.session_handle.connect(s_get('BGP_OPEN'))
        self.session_handle.connect(s_get('BGP_OPEN'),s_get('BGP_KEEPALIVE'))
        self.session_handle.connect(s_get('BGP_KEEPALIVE'),s_get('BGP_UPDATE'))
        self.session_handle.fuzz()

'''
BGP UPDATE #3

- BGP header length is correct
- Withdrawn routes length is set to 0x0000
- fuzz single attribute (non-extended length of 1 octet)
'''
class BgpUpdateFuzzer_3(BaseUpdateFuzzer):
    def __init__(self, bgp_id, asn_id, rhost, rpc_port=1234, rport='179', hold_time=240):
        super().__init__(bgp_id, asn_id, rhost, rpc_port, rport, hold_time)
        self.poc_name = 'BgpUpdateFuzzer_3_testcase_%s.py'

    def do_fuzz(self):
        PARAM_ASN_ID = self.asn_id
        PARAM_BGP_ID = self.bgp_id
        PARAM_HOLD_TIME = self.hold_time

        s_initialize('BGP_OPEN')    
        with s_block('HEADER'):    
            s_static(name='marker', value=b'\xff'*16)     
            s_static(name='length', value=b'\x00\x6b')    
            s_static(name='type', value=b'\x01')    
        with s_block('OPEN_MSG'):    
            s_static(name='version', value=b'\x04')    
            s_word(name='my_as', value=PARAM_ASN_ID, endian=BIG_ENDIAN, fuzzable=False)    
            s_word(value=PARAM_HOLD_TIME, endian=BIG_ENDIAN, name="Hold Time", fuzzable=False)
            s_static(name='bgp_identifier', value=helpers.ip_str_to_bytes(PARAM_BGP_ID))    
            s_static(name='opt_params_len', value=b'\x4e')    
            s_static(name='opt_params', value=b'\x02\x06\x01\x04\x00\x01\x00\x01\x02\x02\x80\x00\x02\x02\x02\x00' \
                                              b'\x02\x02\x46\x00\x02\x06\x41\x04\x00\x00\x00\x02\x02\x02\x06\x00' \
                                              b'\x02\x06\x45\x04\x00\x01\x01\x01\x02\x13\x49\x11\x0f\x73\x74\x61' \
                                              b'\x6e\x64\x61\x73\x68\x2d\x75\x62\x75\x6e\x74\x75\x00\x02\x04\x40' \
                                              b'\x02\xc0\x78\x02\x09\x47\x07\x00\x01\x01\x80\x00\x00\x00'                      
            )                                                                  
                                                                              
        s_initialize('BGP_KEEPALIVE')                                                                    
        with s_block('HEADER'):                                                                                 
            s_static(name='marker', value=b'\xff'*16)                                                           
            s_static(name='length', value=b'\x00\x13')                        
            s_static(name='type', value=b'\x04')     
                                                                                                     
                                                     
        s_initialize('BGP_UPDATE')                                                                    
        with s_block('HEADER'):                                      
           s_static(name='marker', value=b'\xff'*16)                  
           s_size(name='header_len', length=2, math=lambda x: x + 19, block_name='UPDATE', endian=BIG_ENDIAN, fuzzable=False)
           s_static(name='type', value=b'\x02')                                                                                                                                                  

           with s_block('UPDATE'):
               s_word(name='withdrawn_len', value=b'\x00\x00', endian=BIG_ENDIAN, fuzzable=False)          
               s_size(name='total_path_attr_len', length=2, block_name='ATTRS', endian=BIG_ENDIAN, fuzzable=False)
               with s_block('ATTRS'):
                   s_group(name='flags', values=[b'\xe0', b'\xc0', b'\xa0', b'\x80', b'\x60', b'\x40', b'\x20', b'\x00'])
                   s_byte(name='type_code', value=0x00, fuzzable=True)
                   s_byte(name='attr_len', value=0x00, fuzzable=True)
                   with s_block('FUZZLOAD'):
                       s_random(num_mutations=1024, min_length=0, max_length=1024, fuzzable=True)

      
        self.session_handle.connect(s_get('BGP_OPEN'))
        self.session_handle.connect(s_get('BGP_OPEN'),s_get('BGP_KEEPALIVE'))
        self.session_handle.connect(s_get('BGP_KEEPALIVE'),s_get('BGP_UPDATE'))
        self.session_handle.fuzz()

'''
BGP UPDATE #4

- BGP header length is correct
- Withdrawn routes length is set to 0x0000
- fuzz single attribute (extended length of 2 octets)
'''
class BgpUpdateFuzzer_4(BaseUpdateFuzzer):
    def __init__(self, bgp_id, asn_id, rhost, rpc_port=1234, rport='179', hold_time=240):
        super().__init__(bgp_id, asn_id, rhost, rpc_port, rport, hold_time)
        self.poc_name = 'BgpUpdateFuzzer_4_testcase_%s.py'

    def do_fuzz(self):
        PARAM_ASN_ID = self.asn_id
        PARAM_BGP_ID = self.bgp_id
        PARAM_HOLD_TIME = self.hold_time

        s_initialize('BGP_OPEN')    
        with s_block('HEADER'):    
            s_static(name='marker', value=b'\xff'*16)     
            s_static(name='length', value=b'\x00\x6b')    
            s_static(name='type', value=b'\x01')    
        with s_block('OPEN_MSG'):    
            s_static(name='version', value=b'\x04')    
            s_word(name='my_as', value=PARAM_ASN_ID, endian=BIG_ENDIAN, fuzzable=False)    
            s_word(value=PARAM_HOLD_TIME, endian=BIG_ENDIAN, name="Hold Time", fuzzable=False)
            s_static(name='bgp_identifier', value=helpers.ip_str_to_bytes(PARAM_BGP_ID))    
            s_static(name='opt_params_len', value=b'\x4e')    
            s_static(name='opt_params', value=b'\x02\x06\x01\x04\x00\x01\x00\x01\x02\x02\x80\x00\x02\x02\x02\x00' \
                                              b'\x02\x02\x46\x00\x02\x06\x41\x04\x00\x00\x00\x02\x02\x02\x06\x00' \
                                              b'\x02\x06\x45\x04\x00\x01\x01\x01\x02\x13\x49\x11\x0f\x73\x74\x61' \
                                              b'\x6e\x64\x61\x73\x68\x2d\x75\x62\x75\x6e\x74\x75\x00\x02\x04\x40' \
                                              b'\x02\xc0\x78\x02\x09\x47\x07\x00\x01\x01\x80\x00\x00\x00'                      
            )                                                                  
                                                                              
        s_initialize('BGP_KEEPALIVE')                                                                    
        with s_block('HEADER'):                                                                                 
            s_static(name='marker', value=b'\xff'*16)                                                           
            s_static(name='length', value=b'\x00\x13')                        
            s_static(name='type', value=b'\x04')     
                                                                                                     
                                                     
        s_initialize('BGP_UPDATE')                                                                    
        with s_block('HEADER'):                                      
           s_static(name='marker', value=b'\xff'*16)                  
           s_size(name='header_len', length=2, math=lambda x: x + 19, block_name='UPDATE', endian=BIG_ENDIAN, fuzzable=False)
           s_static(name='type', value=b'\x02')                                                                                                                                                  

           with s_block('UPDATE'):
               s_word(name='withdrawn_len', value=b'\x00\x00', endian=BIG_ENDIAN, fuzzable=False)          
               s_size(name='total_path_attr_len', length=2, block_name='ATTRS', endian=BIG_ENDIAN, fuzzable=False)
               with s_block('ATTRS'):
                   s_group(name='flags', values=[b'\xf0', b'\xd0', b'\xb0', b'\x90', b'\x70', b'\x50', b'\x30', b'\x10'])
                   s_byte(name='type_code', value=0x00, fuzzable=True)
                   s_word(name='attr_len', value=0x0000, fuzzable=True)
                   with s_block('FUZZLOAD'):
                       s_random(num_mutations=1024, min_length=0, max_length=1024, fuzzable=True)

      
        self.session_handle.connect(s_get('BGP_OPEN'))
        self.session_handle.connect(s_get('BGP_OPEN'),s_get('BGP_KEEPALIVE'))
        self.session_handle.connect(s_get('BGP_KEEPALIVE'),s_get('BGP_UPDATE'))
        self.session_handle.fuzz()

'''
BGP UPDATE #5

- BGP header length is correct
- Withdrawn routes length is set to 0x0000
- fuzz single attribute (non-extended length of 1 octet)
- attribute length is correct
'''
class BgpUpdateFuzzer_5(BaseUpdateFuzzer):
    def __init__(self, bgp_id, asn_id, rhost, rpc_port=1234, rport='179', hold_time=240):
        super().__init__(bgp_id, asn_id, rhost, rpc_port, rport, hold_time)
        self.poc_name = 'BgpUpdateFuzzer_5_testcase_%s.py'

    def do_fuzz(self):
        PARAM_ASN_ID = self.asn_id
        PARAM_BGP_ID = self.bgp_id
        PARAM_HOLD_TIME = self.hold_time

        s_initialize('BGP_OPEN')    
        with s_block('HEADER'):    
            s_static(name='marker', value=b'\xff'*16)     
            s_static(name='length', value=b'\x00\x6b')    
            s_static(name='type', value=b'\x01')    
        with s_block('OPEN_MSG'):    
            s_static(name='version', value=b'\x04')    
            s_word(name='my_as', value=PARAM_ASN_ID, endian=BIG_ENDIAN, fuzzable=False)    
            s_word(value=PARAM_HOLD_TIME, endian=BIG_ENDIAN, name="Hold Time", fuzzable=False)
            s_static(name='bgp_identifier', value=helpers.ip_str_to_bytes(PARAM_BGP_ID))    
            s_static(name='opt_params_len', value=b'\x4e')    
            s_static(name='opt_params', value=b'\x02\x06\x01\x04\x00\x01\x00\x01\x02\x02\x80\x00\x02\x02\x02\x00' \
                                              b'\x02\x02\x46\x00\x02\x06\x41\x04\x00\x00\x00\x02\x02\x02\x06\x00' \
                                              b'\x02\x06\x45\x04\x00\x01\x01\x01\x02\x13\x49\x11\x0f\x73\x74\x61' \
                                              b'\x6e\x64\x61\x73\x68\x2d\x75\x62\x75\x6e\x74\x75\x00\x02\x04\x40' \
                                              b'\x02\xc0\x78\x02\x09\x47\x07\x00\x01\x01\x80\x00\x00\x00'                      
            )                                                                  
                                                                              
        s_initialize('BGP_KEEPALIVE')                                                                    
        with s_block('HEADER'):                                                                                 
            s_static(name='marker', value=b'\xff'*16)                                                           
            s_static(name='length', value=b'\x00\x13')                        
            s_static(name='type', value=b'\x04')     
                                                                                                     
                                                     
        s_initialize('BGP_UPDATE')                                                                    
        with s_block('HEADER'):                                      
           s_static(name='marker', value=b'\xff'*16)                  
           s_size(name='header_len', length=2, math=lambda x: x + 19, block_name='UPDATE', endian=BIG_ENDIAN, fuzzable=False)
           s_static(name='type', value=b'\x02')                                                                                                                                                  

           with s_block('UPDATE'):
               s_word(name='withdrawn_len', value=b'\x00\x00', endian=BIG_ENDIAN, fuzzable=False)          
               s_size(name='total_path_attr_len', length=2, block_name='ATTRS', endian=BIG_ENDIAN, fuzzable=False)
               with s_block('ATTRS'):
                   s_group(name='flags', values=[b'\xe0', b'\xc0', b'\xa0', b'\x80', b'\x60', b'\x40', b'\x20', b'\x00'])
                   s_byte(name='type_code', value=0x00, fuzzable=True)
                   s_size(name='attr_len', length=1, block_name='FUZZLOAD', fuzzable=False)
                   with s_block('FUZZLOAD'):
                       s_random(num_mutations=1024, min_length=0, max_length=1024, fuzzable=True)

      
        self.session_handle.connect(s_get('BGP_OPEN'))
        self.session_handle.connect(s_get('BGP_OPEN'),s_get('BGP_KEEPALIVE'))
        self.session_handle.connect(s_get('BGP_KEEPALIVE'),s_get('BGP_UPDATE'))
        self.session_handle.fuzz()

'''
BGP UPDATE #6

- BGP header length is correct
- Withdrawn routes length is set to 0x0000
- fuzz single attribute (extended length of 2 octets)
- attribute length is correct
'''
class BgpUpdateFuzzer_6(BaseUpdateFuzzer):
    def __init__(self, bgp_id, asn_id, rhost, rpc_port=1234, rport='179', hold_time=240):
        super().__init__(bgp_id, asn_id, rhost, rpc_port, rport, hold_time)
        self.poc_name = 'BgpUpdateFuzzer_6_testcase_%s.py'

    def do_fuzz(self):
        PARAM_ASN_ID = self.asn_id
        PARAM_BGP_ID = self.bgp_id
        PARAM_HOLD_TIME = self.hold_time

        s_initialize('BGP_OPEN')    
        with s_block('HEADER'):    
            s_static(name='marker', value=b'\xff'*16)     
            s_static(name='length', value=b'\x00\x6b')    
            s_static(name='type', value=b'\x01')    
        with s_block('OPEN_MSG'):    
            s_static(name='version', value=b'\x04')    
            s_word(name='my_as', value=PARAM_ASN_ID, endian=BIG_ENDIAN, fuzzable=False)    
            s_word(value=PARAM_HOLD_TIME, endian=BIG_ENDIAN, name="Hold Time", fuzzable=False)
            s_static(name='bgp_identifier', value=helpers.ip_str_to_bytes(PARAM_BGP_ID))    
            s_static(name='opt_params_len', value=b'\x4e')    
            s_static(name='opt_params', value=b'\x02\x06\x01\x04\x00\x01\x00\x01\x02\x02\x80\x00\x02\x02\x02\x00' \
                                              b'\x02\x02\x46\x00\x02\x06\x41\x04\x00\x00\x00\x02\x02\x02\x06\x00' \
                                              b'\x02\x06\x45\x04\x00\x01\x01\x01\x02\x13\x49\x11\x0f\x73\x74\x61' \
                                              b'\x6e\x64\x61\x73\x68\x2d\x75\x62\x75\x6e\x74\x75\x00\x02\x04\x40' \
                                              b'\x02\xc0\x78\x02\x09\x47\x07\x00\x01\x01\x80\x00\x00\x00'                      
            )                                                                  
                                                                              
        s_initialize('BGP_KEEPALIVE')                                                                    
        with s_block('HEADER'):                                                                                 
            s_static(name='marker', value=b'\xff'*16)                                                           
            s_static(name='length', value=b'\x00\x13')                        
            s_static(name='type', value=b'\x04')     
                                                                                                     
                                                     
        s_initialize('BGP_UPDATE')                                                                    
        with s_block('HEADER'):                                      
           s_static(name='marker', value=b'\xff'*16)                  
           s_size(name='header_len', length=2, math=lambda x: x + 19, block_name='UPDATE', endian=BIG_ENDIAN, fuzzable=False)
           s_static(name='type', value=b'\x02')                                                                                                                                                  

           with s_block('UPDATE'):
               s_word(name='withdrawn_len', value=b'\x00\x00', endian=BIG_ENDIAN, fuzzable=False)          
               s_size(name='total_path_attr_len', length=2, block_name='ATTRS', endian=BIG_ENDIAN, fuzzable=False)
               with s_block('ATTRS'):
                   s_group(name='flags', values=[b'\xf0', b'\xd0', b'\xb0', b'\x90', b'\x70', b'\x50', b'\x30', b'\x10'])
                   s_byte(name='type_code', value=0x00, fuzzable=True)
                   s_size(name='attr_len', length=2, block_name='FUZZLOAD', endian=BIG_ENDIAN, fuzzable=False)
                   with s_block('FUZZLOAD'):
                       s_random(num_mutations=1024, min_length=0, max_length=1024, fuzzable=True)

      
        self.session_handle.connect(s_get('BGP_OPEN'))
        self.session_handle.connect(s_get('BGP_OPEN'),s_get('BGP_KEEPALIVE'))
        self.session_handle.connect(s_get('BGP_KEEPALIVE'),s_get('BGP_UPDATE'))
        self.session_handle.fuzz()

'''
BGP UPDATE #7

- BGP header length is correct
- withdrawn routes length is fuzzable
- ... followed by a random fuzzload
'''
class BgpUpdateFuzzer_7(BaseUpdateFuzzer):
    def __init__(self, bgp_id, asn_id, rhost, rpc_port=1234, rport='179', hold_time=240):
        super().__init__(bgp_id, asn_id, rhost, rpc_port, rport, hold_time)
        self.poc_name = 'BgpUpdateFuzzer_7_testcase_%s.py'

    def do_fuzz(self):
        PARAM_ASN_ID = self.asn_id
        PARAM_BGP_ID = self.bgp_id
        PARAM_HOLD_TIME = self.hold_time

        s_initialize('BGP_OPEN')    
        with s_block('HEADER'):    
            s_static(name='marker', value=b'\xff'*16)     
            s_static(name='length', value=b'\x00\x6b')    
            s_static(name='type', value=b'\x01')    
        with s_block('OPEN_MSG'):    
            s_static(name='version', value=b'\x04')    
            s_word(name='my_as', value=PARAM_ASN_ID, endian=BIG_ENDIAN, fuzzable=False)    
            s_word(value=PARAM_HOLD_TIME, endian=BIG_ENDIAN, name="Hold Time", fuzzable=False)
            s_static(name='bgp_identifier', value=helpers.ip_str_to_bytes(PARAM_BGP_ID))    
            s_static(name='opt_params_len', value=b'\x4e')    
            s_static(name='opt_params', value=b'\x02\x06\x01\x04\x00\x01\x00\x01\x02\x02\x80\x00\x02\x02\x02\x00' \
                                              b'\x02\x02\x46\x00\x02\x06\x41\x04\x00\x00\x00\x02\x02\x02\x06\x00' \
                                              b'\x02\x06\x45\x04\x00\x01\x01\x01\x02\x13\x49\x11\x0f\x73\x74\x61' \
                                              b'\x6e\x64\x61\x73\x68\x2d\x75\x62\x75\x6e\x74\x75\x00\x02\x04\x40' \
                                              b'\x02\xc0\x78\x02\x09\x47\x07\x00\x01\x01\x80\x00\x00\x00'                      
            )                                                                  
                                                                              
        s_initialize('BGP_KEEPALIVE')                                                                    
        with s_block('HEADER'):                                                                                 
            s_static(name='marker', value=b'\xff'*16)                                                           
            s_static(name='length', value=b'\x00\x13')                        
            s_static(name='type', value=b'\x04')     
                                                                                                     
                                                     
        s_initialize('BGP_UPDATE')                                                                    
        with s_block('HEADER'):                                      
           s_static(name='marker', value=b'\xff'*16)                  
           s_size(name='header_len', length=2, math=lambda x: x + 19, block_name='UPDATE', endian=BIG_ENDIAN, fuzzable=False)
           s_static(name='type', value=b'\x02')                                                                                                                                                  

           with s_block('UPDATE'):
               s_word(name='withdrawn_len', value=b'\x00\x00', endian=BIG_ENDIAN, fuzzable=True)          
               with s_block('FUZZLOAD'):
                   s_random(num_mutations=1024, min_length=0, max_length=1024, fuzzable=True)

      
        self.session_handle.connect(s_get('BGP_OPEN'))
        self.session_handle.connect(s_get('BGP_OPEN'),s_get('BGP_KEEPALIVE'))
        self.session_handle.connect(s_get('BGP_KEEPALIVE'),s_get('BGP_UPDATE'))
        self.session_handle.fuzz()

'''
BGP UPDATE #8

- BGP header length is correct
- withdrawn routes length is correct
- ... followed by a random fuzzload
'''
class BgpUpdateFuzzer_8(BaseUpdateFuzzer):
    def __init__(self, bgp_id, asn_id, rhost, rpc_port=1234, rport='179', hold_time=240):
        super().__init__(bgp_id, asn_id, rhost, rpc_port, rport, hold_time)
        self.poc_name = 'BgpUpdateFuzzer_8_testcase_%s.py'

    def do_fuzz(self):
        PARAM_ASN_ID = self.asn_id
        PARAM_BGP_ID = self.bgp_id
        PARAM_HOLD_TIME = self.hold_time

        s_initialize('BGP_OPEN')    
        with s_block('HEADER'):    
            s_static(name='marker', value=b'\xff'*16)     
            s_static(name='length', value=b'\x00\x6b')    
            s_static(name='type', value=b'\x01')    
        with s_block('OPEN_MSG'):    
            s_static(name='version', value=b'\x04')    
            s_word(name='my_as', value=PARAM_ASN_ID, endian=BIG_ENDIAN, fuzzable=False)    
            s_word(value=PARAM_HOLD_TIME, endian=BIG_ENDIAN, name="Hold Time", fuzzable=False)
            s_static(name='bgp_identifier', value=helpers.ip_str_to_bytes(PARAM_BGP_ID))    
            s_static(name='opt_params_len', value=b'\x4e')    
            s_static(name='opt_params', value=b'\x02\x06\x01\x04\x00\x01\x00\x01\x02\x02\x80\x00\x02\x02\x02\x00' \
                                              b'\x02\x02\x46\x00\x02\x06\x41\x04\x00\x00\x00\x02\x02\x02\x06\x00' \
                                              b'\x02\x06\x45\x04\x00\x01\x01\x01\x02\x13\x49\x11\x0f\x73\x74\x61' \
                                              b'\x6e\x64\x61\x73\x68\x2d\x75\x62\x75\x6e\x74\x75\x00\x02\x04\x40' \
                                              b'\x02\xc0\x78\x02\x09\x47\x07\x00\x01\x01\x80\x00\x00\x00'                      
            )                                                                  
                                                                              
        s_initialize('BGP_KEEPALIVE')                                                                    
        with s_block('HEADER'):                                                                                 
            s_static(name='marker', value=b'\xff'*16)                                                           
            s_static(name='length', value=b'\x00\x13')                        
            s_static(name='type', value=b'\x04')     
                                                                                                     
                                                     
        s_initialize('BGP_UPDATE')                                                                    
        with s_block('HEADER'):                                      
           s_static(name='marker', value=b'\xff'*16)                  
           s_size(name='header_len', length=2, math=lambda x: x + 19, block_name='UPDATE', endian=BIG_ENDIAN, fuzzable=False)
           s_static(name='type', value=b'\x02')                                                                                                                                                  

           with s_block('UPDATE'):
               s_size(name='withdrawn_len', block_name='FUZZLOAD', length=2, endian=BIG_ENDIAN, fuzzable=False)          
               with s_block('FUZZLOAD'):
                   s_random(num_mutations=1024, min_length=0, max_length=1024, fuzzable=True)

      
        self.session_handle.connect(s_get('BGP_OPEN'))
        self.session_handle.connect(s_get('BGP_OPEN'),s_get('BGP_KEEPALIVE'))
        self.session_handle.connect(s_get('BGP_KEEPALIVE'),s_get('BGP_UPDATE'))
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
    fuzzer = BgpUpdateFuzzer_1(bgp_id=FBGP_ID, asn_id=FASN, rhost=TIP, rpc_port=TRPC_PORT)
    #fuzzer = BgpUpdateFuzzer_2(bgp_id=FBGP_ID, asn_id=FASN, rhost=TIP, rpc_port=TRPC_PORT)
    #fuzzer = BgpUpdateFuzzer_3(bgp_id=FBGP_ID, asn_id=FASN, rhost=TIP, rpc_port=TRPC_PORT)
    #fuzzer = BgpUpdateFuzzer_4(bgp_id=FBGP_ID, asn_id=FASN, rhost=TIP, rpc_port=TRPC_PORT)
    #fuzzer = BgpUpdateFuzzer_5(bgp_id=FBGP_ID, asn_id=FASN, rhost=TIP, rpc_port=TRPC_PORT)
    #fuzzer = BgpUpdateFuzzer_6(bgp_id=FBGP_ID, asn_id=FASN, rhost=TIP, rpc_port=TRPC_PORT)
    #fuzzer = BgpUpdateFuzzer_7(bgp_id=FBGP_ID, asn_id=FASN, rhost=TIP, rpc_port=TRPC_PORT)
    #fuzzer = BgpUpdateFuzzer_8(bgp_id=FBGP_ID, asn_id=FASN, rhost=TIP, rpc_port=TRPC_PORT)
    fuzzer.do_fuzz()
