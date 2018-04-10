from structures import *

'''
so where does our data come from?
It's a point. It can decide the efficiency of fuzzing.
First of all, as normal, we choose some classic fuzzing data especially
the long strings which can cause buffer overflow.
'''
int_fuzz    = [0x00, 0x0000, 0xff, 0xffff, 0xffffffff,
			   0xff-1, 0xffff-1, 0xffffffff-1]
#focuing on this!
string_fuzz = ['a' * 0x100, 'a' * 0x1000, 'a' * 0x10000, 'a' * 0x100000]
delim_fuzz  = ['~!@#$%^&*()-_=+{}|\\;\',<.>/?`']
'''
For fsb(Format String Bug), normally the server won't crash, 
so in fact, this fuzzing data is useless unless you find some ways.
'''
fsb_fuzz    = ["%s%s%s", "%s%n%s", "%n%s%n%s"]
'''
Second, we can get some fuzzing data from the previous upnp loopholes.
And just pass now...
'''

def get_fuzz_data():
	fuzz_data = int_fuzz + string_fuzz + delim_fuzz + fsb_fuzz
	return fuzz_data

def add_fuzz_data(extra_fuzz_data):
	fuzz_data += extra_fuzz_data


