from base.fuzzer import BaseFuzzer

class BaseUpdateFuzzer(BaseFuzzer):
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
                print(step)
                if step.type == 'send':
                    payload = step.data
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

def session(rhost, asn_id, bgp_id):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((rhost, 179))

    # BGP OPEN message 
    marker              = b\'\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\'
    length              = b\'\\x00\\x6b\'
    m_type_version      = b\'\\x01\\x04\'
    my_as               = int(asn_id).to_bytes(2, 'big')
    hold_time           = b\'\\x00\\xb4\'
    bgp_identifier      = socket.inet_aton(bgp_id)
    opt_params_len      = b\'\\x4e\'
    opt_params          = b\'\\x02\\x06\\x01\\x04\\x00\\x01\\x00\\x01\\x02\\x02\\x80\\x00\\x02\\x02\\x02\\x00\' \\
                          b\'\\x02\\x02\\x46\\x00\\x02\\x06\\x41\\x04\\x00\\x00\\x00\\x02\\x02\\x02\\x06\\x00\' \\
                          b\'\\x02\\x06\\x45\\x04\\x00\\x01\\x01\\x01\\x02\\x13\\x49\\x11\\x0f\\x73\\x74\\x61\' \\
                          b\'\\x6e\\x64\\x61\\x73\\x68\\x2d\\x75\\x62\\x75\\x6e\\x74\\x75\\x00\\x02\\x04\\x40\' \\
                          b\'\\x02\\xc0\\x78\\x02\\x09\\x47\\x07\\x00\\x01\\x01\\x80\\x00\\x00\\x00\'

    bgp_open_msg = marker + length + m_type_version + my_as + hold_time + bgp_identifier + opt_params_len + opt_params

    # BGP KEEPALIVE message            
    marker              = b\'\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\'        
    length              = b\'\\x00\\x13\'        
    m_type              = b\'\\x04\'            

    keepalive_msg = marker + length + m_type

    # BGP UPDATE message
    update_msg = %s

    print('SEND BGP OPEN')
    s.send(bgp_open_msg)
    keepalive = s.recv(1024)

    print('SEND KEEPALIVE')
    s.send(keepalive_msg)
    ack = s.recv(1024)

    print('SEND UPDATE')
    s.send(update_msg)

    return s

def signal_handler(signal, frame):
    try:
        sock.close()
    finally:
        sys.exit(0)

if __name__ == '__main__':
    if len(sys.argv) < 4:
        print('Provide the remote host IP address, ASN identifier, and BGP identifier!')
        sys.exit(-1)
    signal.signal(signal.SIGINT, signal_handler)
    sock = session(sys.argv[1], sys.argv[2], sys.argv[3])
    while True:
        pass
'''
        return poc % (test_suite, mutant_index, payload)
