from upnp import *

################## Action Functions ######################
#These functions handle user commands from the shell

#Actively search for UPNP devices
def msearch(argc,argv,hp):
	defaultST = "upnp:rootdevice"
	st = "schemas-upnp-org"
	myip = ''
	lport = hp.port

	if argc >= 3:
		if argc == 4:
			st = argv[1]
			searchType = argv[2]
			searchName = argv[3]
		else:
			searchType = argv[1]
			searchName = argv[2]
		st = "urn:%s:%s:%s:%s" % (st,searchType,searchName,hp.UPNP_VERSION.split('.')[0])
	else:
		st = defaultST

	#Build the request
	request = 	"M-SEARCH * HTTP/1.1\r\n"\
			"HOST:%s:%d\r\n"\
			"ST:%s\r\n" % (hp.ip,hp.port,st)
	for header,value in hp.msearchHeaders.iteritems():
			request += header + ':' + value + "\r\n"	
	request += "\r\n" 

	print '[+] Discoverying UPnP servers......'
	#print "Entering discovery mode for '%s', Ctl+C to stop..." % st
	print ''
		
	#Have to create a new socket since replies will be sent directly to our IP, not the multicast IP
	server = hp.createNewListener(myip,lport)
	if server == False:
		print 'Failed to bind port %d' % lport
		return

	hp.send(request,server)
	count = 0
	start = time.time()

	while True:
		try:
			if hp.MAX_HOSTS > 0 and count >= hp.MAX_HOSTS:
				break

			if hp.TIMEOUT > 0 and (time.time() - start) > hp.TIMEOUT:
				raise Exception("Timeout exceeded")

			if hp.parseSSDPInfo(hp.recv(1024,server),False,False):
				count += 1

		except Exception, e:
			print '\nDiscover mode halted...'
			break

#Passively listen for UPNP NOTIFY packets
def pcap(argc,argv,hp):
	print 'Entering passive mode, Ctl+C to stop...'
	print ''

	count = 0
	start = time.time()

	while True:
		try:
			if hp.MAX_HOSTS > 0 and count >= hp.MAX_HOSTS:
				break

			if hp.TIMEOUT > 0 and (time.time() - start) > hp.TIMEOUT:
				raise Exception ("Timeout exceeded")

			if hp.parseSSDPInfo(hp.recv(1024,False),False,False):
				count += 1

		except Exception, e:
			print "\nPassive mode halted..."
			break

#Manipulate M-SEARCH header values
def head(argc,argv,hp):
	if argc >= 2:
		action = argv[1]
		#Show current headers
		if action == 'show':
			for header,value in hp.msearchHeaders.iteritems():
				print header,':',value
			return
		#Delete the specified header
		elif action == 'del':
			if argc == 3:
				header = argv[2]
				if hp.msearchHeaders.has_key(header):
					del hp.msearchHeaders[header]
					print '%s removed from header list' % header
					return
				else:
					print '%s is not in the current header list' % header
					return
		#Create/set a headers
		elif action == 'set':
			if argc == 4:
				header = argv[2]
				value = argv[3]
				hp.msearchHeaders[header] = value
				print "Added header: '%s:%s" % (header,value)
				return

	showHelp(argv[0])

#Manipulate application settings
def set(argc,argv,hp):
	if argc >= 2:
		action = argv[1]
		if action == 'uniq':
			hp.UNIQ = toggleVal(hp.UNIQ)
			print "Show unique hosts set to: %s" % hp.UNIQ
			return
		elif action == 'debug':
			hp.DEBUG = toggleVal(hp.DEBUG)
			print "Debug mode set to: %s" % hp.DEBUG
			return
		elif action == 'verbose':
			hp.VERBOSE = toggleVal(hp.VERBOSE)
			print "Verbose mode set to: %s" % hp.VERBOSE
			return
		elif action == 'version':
			if argc == 3:
				hp.UPNP_VERSION = argv[2]
				print 'UPNP version set to: %s' % hp.UPNP_VERSION
			else:
				showHelp(argv[0])
			return
		elif action == 'iface':
			if argc == 3:
				hp.IFACE = argv[2]
				print 'Interface set to %s, re-binding sockets...' % hp.IFACE
				if hp.initSockets(hp.ip,hp.port,hp.IFACE):
					print 'Interface change successful!'
				else:
					print 'Failed to bind new interface - are you sure you have root privilages??'
					hp.IFACE = None
				return
		elif action == 'socket':
			if argc == 3:
				try:
					(ip,port) = argv[2].split(':')
					port = int(port)
					hp.ip = ip
					hp.port = port
					hp.cleanup()
					if hp.initSockets(ip,port,hp.IFACE) == False:
						print "Setting new socket %s:%d failed!" % (ip,port)
					else:
						print "Using new socket: %s:%d" % (ip,port)
				except Exception, e:
					print 'Caught exception setting new socket:',e	
				return
		elif action == 'timeout':
			if argc == 3:
				try:
					hp.TIMEOUT = int(argv[2])
				except Exception, e:
					print 'Caught exception setting new timeout value:',e
				return
		elif action == 'max':
			if argc == 3:
				try:
					hp.MAX_HOSTS = int(argv[2])
				except Exception, e:
					print 'Caught exception setting new max host value:', e
				return
		elif action == 'show':
			print 'Multicast IP:          ',hp.ip
			print 'Multicast port:        ',hp.port
			print 'Network interface:     ',hp.IFACE
			print 'Receive timeout:       ',hp.TIMEOUT
			print 'Host discovery limit:  ',hp.MAX_HOSTS
			print 'Number of known hosts: ',len(hp.ENUM_HOSTS)
			print 'UPNP version:          ',hp.UPNP_VERSION
			print 'Debug mode:            ',hp.DEBUG
			print 'Verbose mode:          ',hp.VERBOSE
			print 'Show only unique hosts:',hp.UNIQ
			print 'Using log file:        ',hp.LOG_FILE
			return

	showHelp(argv[0])
	return

#Host command. It's kind of big.
def host(argc,argv,hp):

	hostInfo = None
	indexList = []
	indexError = "Host index out of range. Try the 'host list' command to get a list of known hosts"

	if argc >= 2:
		action = argv[1]
		if action == 'list':
			if len(hp.ENUM_HOSTS) == 0:
				print "No known hosts - try running the 'msearch' or 'pcap' commands"
				return
			print '[+] Found %d UPnP servers' % len(hp.ENUM_HOSTS)
			for index,hostInfo in hp.ENUM_HOSTS.iteritems():
				print "[%d] %s" % (index,hostInfo['name'])
			return
		elif action == 'details':
			if argc == 3:
				try:
					index = int(argv[2])
					hostInfo = hp.ENUM_HOSTS[index]
				except Exception, e:
					print indexError
					return

				try:
					#If this host data is already complete, just display it
					if hostInfo['dataComplete'] == True:
						hp.showCompleteHostInfo(index,False)
					else:
						print "Can't show host info because I don't have it. Please run 'host get %d'" % index
				except KeyboardInterrupt, e:
					print ""
					pass
				return

		elif action == 'summary':
			if argc == 3:
			
				try:
					index = int(argv[2])
					hostInfo = hp.ENUM_HOSTS[index]
				except:
					print indexError
					return

				print 'Host:',hostInfo['name']
				print 'XML File:',hostInfo['xmlFile']
				for deviceName,deviceData in hostInfo['deviceList'].iteritems():
					print deviceName
					for k,v in deviceData.iteritems():
						try:
							v.has_key(False)
						except:
							print "\t%s: %s" % (k,v)
				print ''
				return

		elif action == 'info':
			output = hp.ENUM_HOSTS
			dataStructs = []
			for arg in argv[2:]:
				try:
					arg = int(arg)
				except:
					pass
				output = output[arg]
			try:
				for k,v in output.iteritems():
					try:
						v.has_key(False)
						dataStructs.append(k)
					except:
						print k,':',v
						continue
			except:
				print output

			for struct in dataStructs:
				pass
				#print struct,': {}'
			return dataStructs

		elif action == 'get':
			if argc == 3:
				try:
					index = int(argv[2])
					hostInfo = hp.ENUM_HOSTS[index]
				except:
					print indexError
					return
			
				if hostInfo is not None:
					#If this host data is already complete, just display it
					if hostInfo['dataComplete'] == True:
						print 'Data for this host has already been enumerated!'
						return

					try:
						#Get extended device and service information
						if hostInfo != False:
							print "\nRequesting device and service info for %s (this could take a few seconds)..." % hostInfo['name']
							#print ''
							if hostInfo['dataComplete'] == False:
								(xmlHeaders,xmlData) = hp.getXML(hostInfo['xmlFile'])
								if xmlData == False:
									print 'Failed to request host XML file:',hostInfo['xmlFile']
									return
								if hp.getHostInfo(xmlData,xmlHeaders,index) == False:
									print "Failed to get device/service info for %s..." % hostInfo['name']
									return
							print 'Host data enumeration complete!\n'
							#hp.updateCmdCompleter(hp.ENUM_HOSTS)
							return
					except KeyboardInterrupt, e:
						print ""
						return

		elif action == 'send':
			#Send SOAP requests
			index = False
			inArgCounter = 0

			if argc != 6:
				showHelp(argv[0])
				return
			else:
				try:
					index = int(argv[2])
					hostInfo = hp.ENUM_HOSTS[index]
				except:
					print indexError
					return
				deviceName = argv[3]
				serviceName = argv[4]
				actionName = argv[5]
				actionArgs = False
				sendArgs = {}
				retTags = []
				controlURL = False
				fullServiceName = False

				#Get the service control URL and full service name
				try:
					controlURL = hostInfo['proto'] + hostInfo['name']
					controlURL2 = hostInfo['deviceList'][deviceName]['services'][serviceName]['controlURL']
					if not controlURL.endswith('/') and not controlURL2.startswith('/'):
						controlURL += '/'
					controlURL += controlURL2
				except Exception,e:
					print 'Caught exception:',e
					print "Are you sure you've run 'host get %d' and specified the correct service name?" % index
					return False

				#Get action info
				try:
					actionArgs = hostInfo['deviceList'][deviceName]['services'][serviceName]['actions'][actionName]['arguments']
					fullServiceName = hostInfo['deviceList'][deviceName]['services'][serviceName]['fullName']
				except Exception,e:
					print 'Caught exception:',e
					print "Are you sure you've specified the correct action?"
					return False

				for argName,argVals in actionArgs.iteritems():
					actionStateVar = argVals['relatedStateVariable']
					stateVar = hostInfo['deviceList'][deviceName]['services'][serviceName]['serviceStateVariables'][actionStateVar]

					if argVals['direction'].lower() == 'in':
						print "Required argument:" 
						print "\tArgument Name: ",argName
						print "\tData Type:     ",stateVar['dataType']
						if stateVar.has_key('allowedValueList'):
							print "\tAllowed Values:",stateVar['allowedValueList']
						if stateVar.has_key('allowedValueRange'):
							print "\tValue Min:     ",stateVar['allowedValueRange'][0]
							print "\tValue Max:     ",stateVar['allowedValueRange'][1]
						if stateVar.has_key('defaultValue'):
							print "\tDefault Value: ",stateVar['defaultValue']
						prompt = "\tSet %s value to: " % argName
						try:
							#Get user input for the argument value
							(argc,argv) = getUserInput(hp,prompt)
							if argv == None:
								print 'Stopping send request...'
								return
							uInput = ''
							
							if argc > 0:
								inArgCounter += 1

							for val in argv:
								uInput += val + ' '
							
							uInput = uInput.strip()
							if stateVar['dataType'] == 'bin.base64' and uInput:
								uInput = base64.encodestring(uInput)
	
							sendArgs[argName] = (uInput.strip(),stateVar['dataType'])
						except KeyboardInterrupt:
							print ""
							return
						print ''
					else:
						retTags.append((argName,stateVar['dataType']))

				#Remove the above inputs from the command history				
				while inArgCounter:
					try:
						readline.remove_history_item(readline.get_current_history_length()-1)
					except:
						pass

					inArgCounter -= 1

				#print 'Requesting',controlURL
				soapResponse = hp.sendSOAP(hostInfo['name'],fullServiceName,controlURL,actionName,sendArgs)
				if soapResponse != False:
					#It's easier to just parse this ourselves...
					for (tag,dataType) in retTags:
						tagValue = hp.extractSingleTag(soapResponse,tag)
						if dataType == 'bin.base64' and tagValue != None:
							tagValue = base64.decodestring(tagValue)
						print tag,':',tagValue
			return


	showHelp(argv[0])
	return

#Save data
def save(argc,argv,hp):
	suffix = '%s_%s.mir'
	uniqName = ''
	saveType = ''
	fnameIndex = 3

	if argc >= 2:
		if argv[1] == 'help':
			showHelp(argv[0])
			return
		elif argv[1] == 'data':
			saveType = 'struct'
			if argc == 3:
				index = argv[2]
			else:
				index = 'data'
		elif argv[1] == 'info':
			saveType = 'info'
			fnameIndex = 4
			if argc >= 3:
				try:
					index = int(argv[2])
				except Exception, e:
					print 'Host index is not a number!'
					showHelp(argv[0])
					return
			else:
				showHelp(argv[0])
				return

		if argc == fnameIndex:
			uniqName = argv[fnameIndex-1]
		else:
			uniqName = index
	else:
		showHelp(argv[0])
		return

	fileName = suffix % (saveType,uniqName)
	if os.path.exists(fileName):
		print "File '%s' already exists! Please try again..." % fileName
		return
	if saveType == 'struct':
		try:
			fp = open(fileName,'w')
			pickle.dump(hp.ENUM_HOSTS,fp)
			fp.close()
			print "Host data saved to '%s'" % fileName
		except Exception, e:
			print 'Caught exception saving host data:',e
	elif saveType == 'info':
		try:
			fp = open(fileName,'w')
			hp.showCompleteHostInfo(index,fp)
			fp.close()
			print "Host info for '%s' saved to '%s'" % (hp.ENUM_HOSTS[index]['name'],fileName)
		except Exception, e:
			print 'Failed to save host info:',e
			return
	else:
		showHelp(argv[0])
	
	return		

#Load data
def load(argc,argv,hp):
	if argc == 2 and argv[1] != 'help':
		loadFile = argv[1]
	
		try:
			fp = open(loadFile,'r')
			hp.ENUM_HOSTS = {}
			hp.ENUM_HOSTS = pickle.load(fp)
			fp.close()
			hp.updateCmdCompleter(hp.ENUM_HOSTS)
			print 'Host data restored:'
			print ''
			host(2,['host','list'],hp)
			return
		except Exception, e:
			print 'Caught exception while restoring host data:',e

	showHelp(argv[0])

#Open log file
def log(argc,argv,hp):
	if argc == 2:
		logFile = argv[1]
		try:
			fp = open(logFile,'a')
		except Exception, e:
			print 'Failed to open %s for logging: %s' % (logFile,e)
			return
		try:
			hp.LOG_FILE = fp
			ts = []
			for x in time.localtime():
				ts.append(x)
			theTime = "%d-%d-%d, %d:%d:%d" % (ts[0],ts[1],ts[2],ts[3],ts[4],ts[5])
			hp.LOG_FILE.write("\n### Logging started at: %s ###\n" % theTime)
		except Exception, e:
			print "Cannot write to file '%s': %s" % (logFile,e)
			hp.LOG_FILE = False
			return
		print "Commands will be logged to: '%s'" % logFile
		return
	showHelp(argv[0])

#Show help
def help(argc,argv,hp):
	showHelp(False)

#Debug, disabled by default
def debug(argc,argv,hp):
	command = ''
	if hp.DEBUG == False:
		print 'Debug is disabled! To enable, try the set command...'
		return
	if argc == 1:
		showHelp(argv[0])
	else:
		for cmd in argv[1:]:
			command += cmd + ' '
		command = command.strip()
		print eval(command)
	return
#Quit!
def exit(argc,argv,hp):
	quit(argc,argv,hp)

#Quit!
def quit(argc,argv,hp):
	if argc == 2 and argv[1] == 'help':
		showHelp(argv[0])
		return
	print 'Bye!'
	print ''
	hp.cleanup()
	sys.exit(0)

################ End Action Functions ######################

#Show command help
def showHelp(command):
	#Detailed help info for each command
	helpInfo = {
			'help' : {
					'longListing':
						'Description:\n'\
							'\tLists available commands and command descriptions\n\n'\
						'Usage:\n'\
							'\t%s\n'\
							'\t<command> help',
					'quickView':
						'Show program help'
				},
			'quit' : {
					'longListing' :
						'Description:\n'\
							'\tQuits the interactive shell\n\n'\
						'Usage:\n'\
							'\t%s',
					'quickView' :
						'Exit this shell'
				},
			'exit' : {

					'longListing' :
						'Description:\n'\
							'\tExits the interactive shell\n\n'\
						'Usage:\n'\
							'\t%s',
					'quickView' : 
						'Exit this shell'
				},
			'save' : {
					'longListing' :
						'Description:\n'\
							'\tSaves current host information to disk.\n\n'\
						'Usage:\n'\
							'\t%s <data | info <host#>> [file prefix]\n'\
							"\tSpecifying 'data' will save the raw host data to a file suitable for importing later via 'load'\n"\
							"\tSpecifying 'info' will save data for the specified host in a human-readable format\n"\
							"\tSpecifying a file prefix will save files in for format of 'struct_[prefix].mir' and info_[prefix].mir\n\n"\
						'Example:\n'\
							'\t> save data wrt54g\n'\
							'\t> save info 0 wrt54g\n\n'\
						'Notes:\n'\
							"\to Data files are saved as 'struct_[prefix].mir'; info files are saved as 'info_[prefix].mir.'\n"\
							"\to If no prefix is specified, the host index number will be used for the prefix.\n"\
							"\to The data saved by the 'save info' command is the same as the output of the 'host details' command.",
					'quickView' :
						'Save current host data to file'
				},
			'set' : {
					'longListing' :
						'Description:\n'\
							'\tAllows you  to view and edit application settings.\n\n'\
						'Usage:\n'\
							'\t%s <show | uniq | debug | verbose | version <version #> | iface <interface> | socket <ip:port> | timeout <seconds> | max <count> >\n'\
							"\t'show' displays the current program settings\n"\
							"\t'uniq' toggles the show-only-uniq-hosts setting when discovering UPNP devices\n"\
							"\t'debug' toggles debug mode\n"\
							"\t'verbose' toggles verbose mode\n"\
							"\t'version' changes the UPNP version used\n"\
							"\t'iface' changes the network interface in use\n"\
							"\t'socket' re-sets the multicast IP address and port number used for UPNP discovery\n"\
							"\t'timeout' sets the receive timeout period for the msearch and pcap commands (default: infinite)\n"\
							"\t'max' sets the maximum number of hosts to locate during msearch and pcap discovery modes\n\n"\
						'Example:\n'\
							'\t> set socket 239.255.255.250:1900\n'\
							'\t> set uniq\n\n'\
						'Notes:\n'\
							"\tIf given no options, 'set' will display help options",
					'quickView' :
						'Show/define application settings'
				},
			'head' : {
					'longListing' :
						'Description:\n'\
							'\tAllows you to view, set, add and delete the SSDP header values used in SSDP transactions\n\n'\
						'Usage:\n'\
							'\t%s <show | del <header> | set <header>  <value>>\n'\
							"\t'set' allows you to set SSDP headers used when sending M-SEARCH queries with the 'msearch' command\n"\
							"\t'del' deletes a current header from the list\n"\
							"\t'show' displays all current header info\n\n"\
						'Example:\n'\
							'\t> head show\n'\
							'\t> head set MX 3',
					'quickView' :
						'Show/define SSDP headers'
				},
			'host' : {
					'longListing' :
						'Description:\n'\
							"\tAllows you to query host information and iteract with a host's actions/services.\n\n"\
						'Usage:\n'\
							'\t%s <list | get | info | summary | details | send> [host index #]\n'\
							"\t'list' displays an index of all known UPNP hosts along with their respective index numbers\n"\
							"\t'get' gets detailed information about the specified host\n"\
							"\t'details' gets and displays detailed information about the specified host\n"\
							"\t'summary' displays a short summary describing the specified host\n"\
							"\t'info' allows you to enumerate all elements of the hosts object\n"\
							"\t'send' allows you to send SOAP requests to devices and services *\n\n"\
						'Example:\n'\
							'\t> host list\n'\
							'\t> host get 0\n'\
							'\t> host summary 0\n'\
							'\t> host info 0 deviceList\n'\
							'\t> host send 0 <device name> <service name> <action name>\n\n'\
						'Notes:\n'\
							"\to All host commands support full tab completion of enumerated arguments\n"\
							"\to All host commands EXCEPT for the 'host send', 'host info' and 'host list' commands take only one argument: the host index number.\n"\
							"\to The host index number can be obtained by running 'host list', which takes no futher arguments.\n"\
							"\to The 'host send' command requires that you also specify the host's device name, service name, and action name that you wish to send,\n\t  in that order (see the last example in the Example section of this output). This information can be obtained by viewing the\n\t  'host details' listing, or by querying the host information via the 'host info' command.\n"\
							"\to The 'host info' command allows you to selectively enumerate the host information data structure. All data elements and their\n\t  corresponding values are displayed; a value of '{}' indicates that the element is a sub-structure that can be further enumerated\n\t  (see the 'host info' example in the Example section of this output).",
					'quickView' :
						'View and send host list and host information'
				},
			'pcap' : {
					'longListing' :
						'Description:\n'\
							'\tPassively listens for SSDP NOTIFY messages from UPNP devices\n\n'\
						'Usage:\n'\
							'\t%s',
					'quickView' :
						'Passively listen for UPNP hosts'
				},
			'msearch' : {
					'longListing' :
						'Description:\n'\
							'\tActively searches for UPNP hosts using M-SEARCH queries\n\n'\
						'Usage:\n'\
							"\t%s [device | service] [<device name> | <service name>]\n"\
							"\tIf no arguments are specified, 'msearch' searches for upnp:rootdevices\n"\
							"\tSpecific device/services types can be searched for using the 'device' or 'service' arguments\n\n"\
						'Example:\n'\
							'\t> msearch\n'\
							'\t> msearch service WANIPConnection\n'\
							'\t> msearch device InternetGatewayDevice',
					'quickView' :
						'Actively locate UPNP hosts'
				},
			'load' : {
					'longListing' :
						'Description:\n'\
							"\tLoads host data from a struct file previously saved with the 'save data' command\n\n"\
						'Usage:\n'\
							'\t%s <file name>',
					'quickView' :
						'Restore previous host data from file'
				},
			'log'  : {
					'longListing' : 
						'Description:\n'\
							'\tLogs user-supplied commands to a log file\n\n'\
						'Usage:\n'\
							'\t%s <log file name>',
					'quickView' :
						'Logs user-supplied commands to a log file'
				}
	}

	
	try:
		print helpInfo[command]['longListing'] % command
	except:
		for command,cmdHelp in helpInfo.iteritems():
			print "%s\t\t%s" % (command,cmdHelp['quickView'])

#Display usage
def usage():
	print '''
Command line usage: %s [OPTIONS]
	
	-s <struct file>	Load previous host data from struct file
	-l <log file>		Log user-supplied commands to log file
	-i <interface>		Specify the name of the interface to use (Linux only, requires root)
        -b <batch file>         Process commands from a file
	-u			Disable show-uniq-hosts-only option
	-d			Enable debug mode
	-v			Enable verbose mode
	-h 			Show help
''' % sys.argv[0]
	sys.exit(1)

#Check command line options
def parseCliOpts(argc,argv,hp):
	try:
		opts,args = getopt.getopt(argv[1:],'s:l:i:b:udvh')
	except getopt.GetoptError, e:
		print 'Usage Error:',e
		usage()
	else:
		for (opt,arg) in opts:
			if opt == '-s':
				print ''
				load(2,['load',arg],hp)
				print ''
			elif opt == '-l':
				print ''
				log(2,['log',arg],hp)
				print ''
			elif opt == '-u':
				hp.UNIQ = toggleVal(hp.UNIQ)
			elif opt == '-d':
				hp.DEBUG = toggleVal(hp.DEBUG)
				print 'Debug mode enabled!'
			elif opt == '-v':
				hp.VERBOSE = toggleVal(hp.VERBOSE)
				print 'Verbose mode enabled!'
			elif opt == '-b':
				hp.BATCH_FILE = open(arg, 'r')
				print "Processing commands from '%s'..." % arg
			elif opt == '-h':
				usage()
			elif opt == '-i':
				networkInterfaces = []
				requestedInterface = arg
				interfaceName = None
				found = False

				#Get a list of network interfaces. This only works on unix boxes.
				try:
					if platform.system() != 'Windows':
						fp = open('/proc/net/dev','r')
						for line in fp.readlines():
							if ':' in line:
								interfaceName = line.split(':')[0].strip()
								if interfaceName == requestedInterface:
									found = True
									break
								else:
									networkInterfaces.append(line.split(':')[0].strip())
						fp.close()
					else:
						networkInterfaces.append('Run ipconfig to get a list of available network interfaces!')
				except Exception,e:
					print 'Error opening file:',e
					print "If you aren't running Linux, this file may not exist!"
					
				if not found and len(networkInterfaces) > 0:
					print "Failed to find interface '%s'; try one of these:\n" % requestedInterface
					for iface in networkInterfaces:
						print iface
					print ''
					sys.exit(1)
				else:
					if not hp.initSockets(False,False,interfaceName):
						print 'Binding to interface %s failed; are you sure you have root privilages??' % interfaceName

#Toggle boolean values
def toggleVal(val):
	if val:
		return False
	else:
		return True

#Prompt for user input
def getUserInput(hp,shellPrompt):
	defaultShellPrompt = 'upnp> '

	if hp.BATCH_FILE is not None:
		return getFileInput(hp)

	if shellPrompt == False:
		shellPrompt = defaultShellPrompt

	try:
		uInput = raw_input(shellPrompt).strip()
		argv = uInput.split()
		argc = len(argv)
	except KeyboardInterrupt, e:
		print '\n'
		if shellPrompt == defaultShellPrompt:
			quit(0,[],hp)
		return (0,None)
	if hp.LOG_FILE != False:
		try:
			hp.LOG_FILE.write("%s\n" % uInput)
		except:
			print 'Failed to log data to log file!'

	return (argc,argv)

#Reads scripted commands from a file
def getFileInput(hp):
	data = False
	line = hp.BATCH_FILE.readline()
	if line:
		data = True
		line = line.strip()

	argv = line.split()
	argc = len(argv)

	if not data:
		hp.BATCH_FILE.close()
		hp.BATCH_FILE = None

	return (argc,argv)