#!/usr/bin python
from upnp import *
from actions import *
from testcases import *
from structures import *
import base64
import sys
import os
from monitor import *
from fuzz_http_xml import *
from defs import *

debug = 0

'''
@fuzz_case: a fuzz_case structure
@option: for other usage
@usage: just sending fuzzing data once
'''
def do_fuzz(hp, i, fuzz_case, option):
	hostInfo = hp.ENUM_HOSTS[i]
	service_fullName  = fuzz_case.service_fullName
	ctlurl   = fuzz_case.ctlurl
	action   = fuzz_case.action
	args     = fuzz_case.args
	state = hp.sendSOAP(hostInfo['name'], service_fullName, ctlurl, action, args)

	return state


#Get device
def get_devices(hp, index):
	devices = []
	try:
		command = ['host', 'info', index, 'deviceList']
		devices = host(len(command), command, hp)
	except Exception, e:
		print 'Caught exception in get_devices():', e
		return False

	if debug:
		print devices
		#print type(devices)

	return devices

#Get services and its control urls of the device
def get_services_and_control_urls(hp, index, device):
	services = []
	
	control_urls = []
	service_ctrurls = {}
	hostInfo = hp.ENUM_HOSTS[index]

	#Get device's services
	try:
		command = ['host', 'info', index, 'deviceList', device, 'services']
		services = host(len(command), command, hp)
	except Exception, e:
		print 'Caught exception in get_services_and_control_urls:', e
		return False

	#How to combine service with its control url? Dictionary or just list?
	for service in services:
		try:
			controlURL = hostInfo['proto'] + hostInfo['name']
			controlURL2 = hostInfo['deviceList'][device]['services'][service]['controlURL']
			#print controlURL, '\n', controlURL2
			if not controlURL.endswith('/') and controlURL2.startswith('/'):
				#controlURL += '/'
				controlURL += controlURL2
				#print controlURL
				control_urls.append(controlURL)
				service_ctrurls[service] = controlURL
		except Exception, e:
			print 'Caught exception in get_services_and_control_urls:', e
			print "Are you sure you've run 'host get %d' and specified the correct service name?" % index
			return False

	if debug:
		print service_ctrurls
		#print type(service_ctrurls)

	return services, service_ctrurls

#used for request, it's necessary!
def get_fullName_by_service(hp, index, device, service):
	service_fullName = None
	try:
		services = hp.ENUM_HOSTS[index]['deviceList'][device]['services']
	except Exception, e:
		print "Caught Exception in get_fullName_by_service:", e
		return False

	service_fullName = services[service]['fullName']
	return service_fullName


#getting service's actions
def get_actions(hp, index, device, service):
	actions = []
	#get service's all actions
	try:
		command = ['host', 'info', index, 'deviceList', device, 'services', service, 'actions']
		actions = host(len(command), command, hp)
	except Exception, e:
		print 'Caught exception in get_actions:', e
		return False

	if debug:
		print actions

	return actions

'''
The funciton is focusing to solve the problem that we must remove the arguments
in actionsArgs if the direction of the argument is out-direction in get_args.
'''
def get_keys(args):
	keys = []
	for key in args:
		if args[key]['direction'] == 'in':
			keys.append(key)

	return keys

#remove the out-direction arguments
#Actually, we don't need to do this operation
def remove_out_args(args):
	for arg in args:
		if args[arg]['direction'] == 'out':
			args.pop(arg)
	return args

'''
getting actions' arguments. Why we should do this?
Because if there is no argument of the action, we don't need to 
fuzzing the action.
Should we get the data type of the argument? Or even its allowed values?
And we have to configure that the argument is the input or output.
'''
def get_args(hp, index, device, service, action):
	#Just the arguments List, not including other properties
	argList = []
	hostInfo = hp.ENUM_HOSTS[index]
	try:
		actionArgs = hostInfo['deviceList'][device]['services'][service]['actions'][action]['arguments']
	except Exception, e:
		print 'Caught exception in get_args:', e
		print "Are you sure you've specified the correct action?"
		return False

	argList = get_keys(actionArgs)
	#Including properties
	#args = remove_out_args(actionArgs)
	if debug:
		print argList

	return argList, actionArgs


'''
Before fuzzing, we must get the deivce's services and
the services' actions and the actions' arguments.
The fuzzing job is mainly focusing on the actions' args.
And we also can try to fuzz the request header?
'''
def fuzz():
	init()
	hp = upnp(False, False, None, None)
	'''
	first we send a request to 239.255.255.250:1900
	to discover upnp servers.
	all information about the upnp server will be 
	saved in the structure of ENUM_HOSTS
	'''
	msearch(None, None, hp)
	'''
	fisrt, we get the description xml.
	then by the desc-xml, we get a service's SCPDURL location which
	describes the service of upnp server, including a service's actions
	and its arguments. And we must get a service's control-url which 
	we will send our actions to it. 
	'''
	#List UPnP servers
	command = ['host', 'list']
	host(len(command), command, hp)
	#Sending request to get the desc-xml
	scount = len(hp.ENUM_HOSTS)

	for i in range(0, scount):
		command = ['host', 'get', i]
		host(len(command), command, hp)

	if debug:
		for i in range(0, scount):
			command = ['host', 'summary', i]
			#host(len(command), command, hp)

	host_ip = None
	'''
	after getting the infomation we need, we constuct some packages sending
	to the control url.
	'''
	fuzz_times = 1
	state = False

	fuzz_data = get_fuzz_data()
	#A large loop
	print "\n\n[+] Fuzzing......"
	print '[+] Stage 1 fuzzing start.......'
	for i in range(0, scount):                      
		devices = get_devices(hp, i)
		#print devices
		for device in devices:	
			services, services_ctrurls = get_services_and_control_urls(hp, i, device)
			for service in services:
				actions = get_actions(hp, i, device, service)
				for action in actions:
					argList, args = get_args(hp, i, device, service, action)
					if len(args) == 0 or len(argList) == 0:
						continue
					#print args
					
					control_url = services_ctrurls[service]

					for data in fuzz_data:
						sendArgs = {}
						for argName, argVals in args.iteritems():
							#print '.....'
							#print argVals
							actionStateVar = argVals['relatedStateVariable']
							stateVar = hp.ENUM_HOSTS[i]['deviceList'][device]['services'][service]['serviceStateVariables'][actionStateVar]
						
							if argVals['direction'] == 'in':

								'''
								there is a problem that if the data type is bin.base64,
								before sending our requests, we must encode the data(or argument)
								''' 
								if stateVar['dataType'] == 'bin.base64':
									data = base64.encodestring(str(data))
								sendArgs[argName] = (data, stateVar['dataType'])
								#print sendArgs
						
						#print len(sendArgs)
						if len(sendArgs) > 0:
							service_fullName = get_fullName_by_service(hp, i, device, service)
							fuzz_case = Fuzz_case(service_fullName, control_url, action, sendArgs)

							fuzz_times += 1
							state = do_fuzz(hp, i, fuzz_case, False)
							'''
							#get host ip address
							host_ip = hp.ENUM_HOSTS[i]['name'].split(':')[0]
							host_port = hp.ENUM_HOSTS[i]['name'].split(':')[1]
							#print host_ip
							state = check_service(host_ip, int(host_port))
							'''
							if state == False:
								print "[-] Can't receive data. Server crashed?"
								#sys.exit()
								#We must save the data to analyse.
								with open('crash/data_crash', 'a+') as f:
									f.write('[+] ')
									f.write('host: ' + hp.ENUM_HOSTS[i]['name'])
									f.write('\tdevice: ' + device)
									f.write('\tservice: ' + service)
									f.write('\taction: ' + action)
									f.write('\targs: ' + str(sendArgs))
									f.write('\n')


	fuzz_http_xml()
	print '\n[+] Fuzzing finished! Just check the crash directory!'


if __name__ == "__main__":
	print '[+] Starting fuzzing......\n'
	fuzz()
	#os.system('rm *.pyc')


