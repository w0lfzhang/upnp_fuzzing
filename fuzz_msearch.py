'''
Meant to fuzz the SSDP protocol

M-SEARCH * HTTP/1.1
HOST: 239.255.255.250:1900
ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1
MAN: "ssdp:discover"
MX: 2

'''
from defs import *
from testcases import *
from upnp import *
import sys

def build_ssdp(st):
	request = 'M-SEARCH * HTTP/1.1\r\n'\
			  'HOST: 239.255.255.250:1900\r\n'\
			  'ST: %s\r\n'\
			  'MAN "ssdp:discover"\r\n'\
			  'MX: 2' % (st)

	return request

def fuzz_msearch():
	server = hp.createNewListener('', False)
	if server == False:
		print 'Failed to bind port %d' % lport
		return
	fuzz_data = get_fuzz_data()
	fuzz_data.append('"ssdp:discover"')
	fuzz_data.append('upnp:rootdevice')
	#print fuzz_data
	try:
		while True:
			request = build_ssdp(get_random_str(fuzz_data))
			hp.send(request,server)
			print hp.recv(1024,server)
	except KeyboardInterrupt:
		print ''
		sys.exit(0)

if __name__ == '__main__':
	hp = upnp(False, False, None, None)
	fuzz_msearch()
