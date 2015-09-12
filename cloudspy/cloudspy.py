# Author : proneer
# Email : proneer(47)gmail.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

import sys
import socket
import getopt
import _winreg
import dnslib

CLOUD_DOMAIN = {
	'Apple iCloud (ambiguous)':'www.icloud.com',
	'Daum Cloud (almost certain)':'cloud.daum.net',
	'Dropbox (ambiguous)':'www.dropbox.com',
	'Evernote (ambiguous)':'www.evernote.com',
	'Google Drive (almost certain)':'drive.google.com',
	'KT uCloud (almost certain)':'my.ucloud.olleh.com',
	'LG CNS Cloud (ambiguous)':'cloud.lgcns.com',
	'LG U+ Box (ambiguous)':'www.uplusbox.co.kr',
	'LG U+ Cloud N (ambiguous)':'www.cloudn.co.kr',
	'Naver NDrive (almost certain)':'ndrive.naver.com',
	'SKT T Cloud':'www.tcloud.co.kr'
}

def get_nameserver_from_registry():
	nameservers = []
	try:
		key_interfaces = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces')
		i = 0
		while True:
			try:
				key_guid = _winreg.EnumKey(key_interfaces, i)
				i += 1
				key_nic_guid = _winreg.OpenKey(key_interfaces, key_guid)
				try:
					servers, rtype = _winreg.QueryValueEx(key_nic_guid, 'NameServer')
					if servers:
						# split primary and secondary
						if servers.find(',') > 0:
							servers = servers.split(',')
							for server in servers:
								nameservers.append(str(server))
					else:
						try:
							servers, rtype = _winreg.QueryValueEx(key_nic_guid, 'DhcpNameServer')
							if servers:
								# split primary and secondary
								if servers.find(' ') > 0:
									servers = servers.split(' ')
									for server in servers:
										nameservers.append(str(server))
						except WindowsError:
							pass
				except WindowsError:
					pass
			except EnvironmentError:
				break
			except WindowsError:
				pass
			finally:
				key_nic_guid.Close()
	finally:
		key_interfaces.Close()	
	
	if len(nameservers) > 0:
		return nameservers
	else:
		print '[!] ERROR: Can\'t find nameserver. You have to use \'-n\' option.'
		sys.exit()
			
def query_domain(query, nameserver):
	udpsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)	# DNS UDP
	udpsock.sendto(query, (nameserver, 53))					
	data, addr = udpsock.recvfrom(65535)
	udpsock.close()
	return data
		
def parse_rr(service, domain, response):
	pos = response.find('<DNS RR:')
	if pos < 0:
		print '[-] ', service, '-', domain, ' : Not Found'
	else:
		print '[+] ', service, '-', domain
		
		# parse RR(Resource Record)
		records = response[pos:].split('\n')
		for record in records:
			pos = record.find('DNS RR:')
			record = record[pos+8:].rstrip('>')
  			items = record.split()
			for item in items:
				item = item.replace('\'', '')
				print '    ', item
			print ''

def cloud_spy(nameserver=None):
	# get a local DNS server list
	if nameserver == None:
		nameservers = get_nameserver_from_registry()
		if len(nameservers) > 0:
			print '# Your DNS Server List'
			i = 0
			# print ALL DNS servers
			for nameserver in nameservers:
				i += 1
				print '[%d] '%i, nameserver
			# User can choose a DNS server
			idx = raw_input('\nWhat do you choose? ')
			nameserver = nameservers[int(idx)-1]
			print '\n# A DNS Server of your choice : ', nameserver
	
	for key, value in CLOUD_DOMAIN.items():
		# create a DNS request packet (wire format)
		wire_query = dnslib.DNSRecord(dnslib.DNSHeader(rd=0), # RD(Recursion Desired) don't set up.
	                                  q=dnslib.DNSQuestion(value))
		wire_query = wire_query.pack()
			
		# query to dns server
		response = query_domain(wire_query, nameserver)
		parse_rr(key, value, str(dnslib.DNSRecord.parse(response)))

def usage():
	print 'It simply request to default(primary) DNS server. If you have to use other server, use \'-n\' option.\n'
	print 'usage: cloudspy.py [-n nameserver]'
	print '   -n : use a custom DNS server'
	print '   -h : help message'
	sys.exit()
	
def main():
	try:
		if len(sys.argv) > 3:
			usage()
			sys.exit()
	except IndexError:
		usage()
		sys.exit()
	
	if len(sys.argv) == 1:
		cloud_spy()
		
	try:
		options, args = getopt.getopt(sys.argv[1:], 'nh:')
		for op, p in options:
			if op == '-n':
				cloud_spy(sys.argv[2])
			elif op == '-h':
				usage()
				sys.exit()
			else:
				print '[!] ERROR: unknown option', op
	except getopt.GetoptError, err:
		usage()
		sys.exit()

if __name__ == "__main__":
	print '# This script is to find cloud traces from DNS Server cache.'
	main()