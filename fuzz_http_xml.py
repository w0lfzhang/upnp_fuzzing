'''
Personally, I think this won't work well~
Becase the protocols are not very complicated,
the changeable fields is few.
A simple request:

POST /control/url HTTP/1.1  
HOST: hostname:portNumber  
CONTENT-TYPE: text/xml;charset="utf-8"  
CONTENT-LENGTH: length ofbody  
USER-AGENT: OS/versionUPnP/1.1 product/version  
SOAPACTION:"urn:schemas-upnp-org:service:serviceType:v#actionName"  
   
<?xml version="1.0"?>  
<s:Envelope  
 xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"  
 s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">  
    <s:Body>  
        <u:actionNamexmlns:uu:actionNamexmlns:u="urn:schemas-upnp-org:service:serviceType:v">  
           <argumentName>in arg value</argumentName>  
        </u:actionName>  
    </s:Body>  
</s:Envelope>

We've already fuzzed the argumentName field which is the real user input.
And the rest to fuzz is:
CONTENT-TYPE
USER-AGENT
SOAPACTION
THE XML tags
'''
from upnp import *
from testcases import *
import sys
import re
from defs import *

def build_request(soapAction, user_agent, content_type, body_tag):
	#we just specify the request path
	soapRequest = None
	#XML tags to fuzz
	soapBody = 	'<?xml version="1.0"?>\n'\
				'%s\n'\
				'<SOAP-ENV:Body>\n'\
				'\t<m:DeletePortMapping xmlns:m="urn:schemas-upnp-org:service:WANIPConnection:1">'\
				'\t\t<NewProtocol>TCP</NewProtocol><NewExternalPort>8080</NewExternalPort><NewRemoteHost>192.168.50.1</NewRemoteHost>\n'\
				'\t</m:DeletePortMapping>\n'\
				'</SOAP-ENV:Body>\n'\
				'</SOAP-ENV:Envelope>' % body_tag
	#print soapBody

	'''
	Specify the headers to send with the request
	And the http headers to fuzz
	SOAPAction: "urn:schemas-upnp-org:service:WANIPConnection:1#DeletePortMapping"
	'''
	headers = 	'POST /ipc HTTP/1.1\r\n'\
				'SOAPAction: %s\r\n'\
				'Host: 192.168.1.1:1900\r\n'\
				'User-Agent: %s\r\n'\
				'Content-Type: %s\r\n'\
				'Content-Length: %d\r\n\r\n' %(soapAction, user_agent, content_type, len(soapBody))

	soapRequest = headers + soapBody
	#print soapRequest

	try:
		sock = socket(AF_INET, SOCK_STREAM)
		sock.connect(('192.168.1.1', 1900))
	
		#sys.exit(0)

		#print soapRequest
		sock.send(soapRequest)
		soapEnd = re.compile('<\/.*:envelope>')
		soapResponse = ''
		while True:
			data = sock.recv(1024)
			if not data:
				break
			else:
				soapResponse += data
				if soapEnd.search(soapResponse.lower()) != None:
					break
		sock.close()
	except Exception, e:
		print "Got exception in build_reqeust", e

	if len(soapResponse) == 0:
		return False
	else:
		print soapResponse
		return True

	#header, body = soapResponse.split('\r\n\r\n',1)

def fuzz_http_xml():
	fuzz_data = get_fuzz_data()
	fuzz_data.append('"urn:schemas-upnp-org:service:WANIPConnection:1#DeletePortMapping"')
	state = False
	print '[+] Stage 2 fuzzing start......'
	try:
		while True:
			state = build_request(get_random_str(fuzz_data), get_random_str(fuzz_data), 
								  get_random_str(fuzz_data), get_random_str(fuzz_data))
			if state == False:
				print '[+] Can not receive data, server crashed?'
				with open('crash/data_crash', 'a+') as f:
					f.write("crashed")
	except KeyboardInterrupt:
		print ''

if __name__ == "__main__":
	fuzz_http_xml()
	