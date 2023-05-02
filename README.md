# A simple BGP fuzzer based on BooFuzz

The goal of this project was to implement a simple black-box fuzzer for various
BGP protocol implementations. For the moment, the focus of the fuzzer is
malformed packets, but we believe that it can be extended to cover some of the
bugs related to the BGP state machine. We chose to build upon
[BooFuzz](https://boofuzz.readthedocs.io/en/stable/).

# Usage

Before running the tool for the first time, make sure you have installed all the
necessary python packages:

```bash
$ pip install -r requirements.txt
```

## Starting the "crash" monitor on a target machine

The fuzzer provides a simple "crash" monitor (we use quotes here because there's
actually no way to tell whether the actual crash has occurred, we merely query
the target's PID to check if the target is still alive).

This feature is experimental and does not work reliably for all possible
targets. Still, when it works, it's quite handy, as it allows to quickly check
whether the latest test case has potentially crashed the target. In addition, it
generates a PoC out of the latest failed test case, which is also quite handy
for test cases with random fuzzload that cannot be generated in a deterministic
manner. Finally, the monitor will attempt to restart the target if its process
dies for whatever reason - this is quite convenient for running long campaigns.

Currently, the monitor supports: `FRRouting`, `BIRD`, and `OpenBGPD`, but can be
extended to other targets as well (see the comments in the `myrpc.py` file).

To start the monitor on a target machine, copy the code (also, make sure to
install the python packages mentioned in the `requirements.txt` file), and run
the following command:

```bash
$ python myrpc.py --ip [TARGET'S IP] --port [RPC port] --monitor [frr | bird | openbgpd]
```

If everything goes well, you should see something like this (the target's PID is
shown in the square brackets): 

```bash
$ python myrpc.py --ip 192.168.56.127 --port 1234 --monitor frr

Resetting the target...
Attached to [14292] -> /usr/lib/frr/bgpd
```
Note, the above command might require root permissions, depending on your setup.

## Choosing a fuzz suite to run

There are several fuzzer scripts that are currently available out of the box:

* `fuzz_open.py` - Provides fuzz suites related the BGP OPEN message.
* `fuzz_update.py` - Provides fuzz suites related the BGP UPDATE message.
* `fuzz_route_refresh.py` - Provides fuzz suites related the BGP ROUTE REFRESH message.
* `fuzz_notification.py` - Provides fuzz suites related the BGP NOTIFICATION message.

To switch between test cases, simply comment/uncomment those that you wish to
discard/use. For example, here's an excerpt from `fuzz_open.py` where we'd like
to run only the first one:

```python
'''
Modify this code to choose different test suites and parameters.
'''
if __name__ == '__main__':

    # code omitted for brevity

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
```

Each test suite contains a short description that explains what kind of
malformed packets it aims to generate.

## Running the fuzzer

To run a specific fuzz suite, execute the following command:

```bash
$ [FUZZ SUITE].py --fbgp_id [FUZZER'S BGP IDENTIFIER] --fasn [FUZZER'S ASN] --tip [TARGET'S IP ADDRESS] --trpc_port [TARGET'S RPC PORT]
```

For example, we might run the fuzz suite related to the BGP OPEN message:

```bash
$ python fuzz_open.py --fbgp_id 192.168.56.107 --fasn 2 --tip 192.168.56.127 --trpc_port 1234 
```

NOTE: a target might not accept BGP messages from peers that are not configured,
therefore you might need to ensure that the fuzzer's IP address, BGP Identifier
and ASN are properly configured within the target.

## Getting results

You can monitor the test case execution via the [web interface of
BooFuzz](https://boofuzz.readthedocs.io/en/stable/user/quickstart.html). If you
are using our custom "crash" monitor (`myrpc.py`), you may see something like
this:

```bash

The target is dead!
Resetting the target...

Potential crash: [BgpOpenFuzzer_2 -> 138]
b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x1d\x01\x04\x00\x02\x00\xf0\xc0\xa88k\xff'

Attached to [14675] -> /usr/lib/frr/bgpd
```

As you can see, one of the test cases (`BgpOpenFuzzer_2`) killed the current
target's process. To reproduce, you may either copy the raw output from here,
or run a python script that the monitor will generate in the current working
directory:

```bash
$ ls

BgpOpenFuzzer_2_testcase_138.py

$ python BgpOpenFuzzer_2_testcase_138.py 192.168.56.127
```

# PoCs 

The purpose of the `PoC` folder is to collect proof-of-concept scripts for bugs
found either with the fuzzer, or manually. The PoCs scripts that come with the
tool by default can be used to directly test if a target device is vulnerable to
CVE-2022-40302 or CVE-2022-43681, which were discovered using the fuzzer.
