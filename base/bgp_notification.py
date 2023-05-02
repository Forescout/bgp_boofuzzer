import time
from boofuzz import *
from boofuzz import helpers
from boofuzz import constants
from base.fuzzer import BaseFuzzer

class BaseNotificationFuzzer(BaseFuzzer):
    def __init__(self, bgp_id, asn_id, rhost, rpc_port=1234, rport='179', hold_time=240):
        super().__init__(bgp_id, asn_id, rhost, rpc_port, rport, hold_time)

    def do_fuzz(self):
        pass

    def get_payload(self, session, index):
        data = None
        payload = None
        data = session.test_case_data(index)
        if data != None:
            for step in data.steps:
                if step.type == 'send':
                    payload = step.data
                    break
        return payload

    def generate_poc(self, test_suite, mutant_index, payload):
        poc = '''
\"\"\"    
%s:%s    
\"\"\"    
    
import socket        
import signal        
import sys        
        
sock = None        
        
def session(rhost):        
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)        
    s.connect((rhost, 179))        
        
    # BGP OPEN message         
    bgp_notification_msg = %s    
         
    print('SEND NOTIFICATION')        
    s.send(bgp_notification_msg)        
    
def signal_handler(signal, frame):    
    try:    
        sock.close()    
    finally:    
        sys.exit(0)    

if __name__ == '__main__':    
    if len(sys.argv) < 2:
        print('Provide the remote host IP address!')
        sys.exit(-1)
    signal.signal(signal.SIGINT, signal_handler)
    sock = session(sys.argv[1])
    while True:
        pass
''' 
        return poc % (test_suite, mutant_index, payload)
