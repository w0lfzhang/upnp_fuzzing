'''
Simple monitor 
'''
import subprocess
import re
import sys

'''
Using ping command to check if the remote
host is alive
'''
def check_alive(ip):
	args = ['ping', '-c', '3', ip]
	recv_count = -1

	try:
		p = subprocess.Popen(args, stdin = subprocess.PIPE, 
			stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = False)
		out = p.stdout.read()
		#print out
	
		#results = out.split('\n')
		reg_recv = re.compile(r"\d received")
		match_recv = re.search(reg_recv, out).group()
		recv_count = int(match_recv[0])
		if recv_count > 0:
			return True
		else:
			return False

	except Exception, e:
		print "[-] Got exception in check_alive"
		sys.exit(0)

'''
checking the remtoe service available.
using connect() to check the service.
'''
def check_service(ip, port):
	pass
	
if __name__ == "__main__":
	if check_alive('192.168.50.2'):
		print "[+] Remote host is alive"
	else:
		print "[-] Remote host is down"