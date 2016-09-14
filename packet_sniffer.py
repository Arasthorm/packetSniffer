import socket
import struct
import os
import binascii
import time
import GeoIP

def main():

	print "Welcome to the sniffing!!"
	geo = GeoIP.open("/usr/local/share/GeoIP/GeoLiteCity.dat", GeoIP.GEOIP_STANDARD)
	sock = socket.socket(socket.PF_PACKET,socket.SOCK_RAW,		socket.htons(0x0003))

	while(True):

		data = sock.recv(2048)
		proto,data = analyze_ether_header(data)

		if proto == hex(0x800):

			#print "Protocol : IPV4"
			protocol,data,TTL = analyze_ip_header(data,geo)

			if protocol == 6:
				#print "Transport Protocol: TCP"
				data = analyze_tcp_header(data)

			if protocol == 17:
				#print "Transport Protocol: UDP"
				analyze_udp_header(data)


def analyze_ether_header(data):

	data_ether = struct.unpack("!6s6sH",data[:14])
	mac_dest = binascii.hexlify(data_ether[0])
	mac_orig = binascii.hexlify(data_ether[1])
	protocol_type = hex(data_ether[2])
	'''
	print "!-------Ethernet Header-------!"
	print "mac destination: " + mac_dest[0:2] +"-"+ mac_dest[2:4] + "-" + mac_dest[4:6] + "-" + mac_dest[6:8] + "-" + mac_dest[8:10] + "-" + mac_dest[10:12]

	print "mac origin: " + mac_orig[0:2] +"-"+ mac_orig[2:4] + "-" + mac_orig[4:6] + "-" + mac_orig[6:8] + "-" + mac_orig[8:10] + "-" + mac_orig[10:12]
	'''
	return protocol_type,data[14:]


def analyze_ip_header(data,geo):

	ip_header = struct.unpack("!6H4s4s",data[:20])

	version = ip_header[0] >> 12
	IHL = (ip_header[0] >> 8) & 0x0f
	ToS = ip_header[0] & 0x00ff
	total_length = ip_header[1]
	ID = ip_header[2]
	flags = ip_header[3] >> 13
	fragment_offset = ip_header[3] & 0x1fff
	TTL = ip_header[4] >> 8
	protocol = ip_header[4] & 0x00ff
	check = ip_header[5]
	source_add = socket.inet_ntoa(ip_header[6])
	dest_add = socket.inet_ntoa(ip_header[7])
	'''
	print "!-------IP header-------!"
	print "source add: "+ source_add
	print "dest add: "+dest_add
	print "Time to live: "+str(time_to_live)
	print "protocol: "+ str(protocol)
	'''

	if not source_add == '127.0.0.1':
		getCityCountry(source_add,dest_add,geo)

	return protocol,data[20:],TTL

def analyze_tcp_header(data):

	tcp_header = struct.unpack("!2HII4H",data[:20])
	source_port = tcp_header[0]
	dest_port = tcp_header[1]
	sequence_num = tcp_header[2]
	ack_num = tcp_header[3]
	data_offset = tcp_header[4] >> 12
	reserved = (tcp_header[4] >> 6) & 0x03f
	URG = (tcp_header[4] >> 5) & 0x001
	ACK = (tcp_header[4] >> 4) & 0x001
	PSH = (tcp_header[4] >> 3) & 0x0001
	RST = (tcp_header[4] >> 2) & 0x0001
	SYN = (tcp_header[4] >> 1) & 0x0001
	FIN = tcp_header[4] & 0x0001
	window = tcp_header[5]
	checksum = tcp_header[6]
	urgent_pointer = tcp_header[7]
	'''
	print "!-------TCP Header-------!"
	print "source port: " + str(source_port)
	print "destination port: " + str(dest_port)
	print "sequence number: " + str(sequence_num)
	print "ack number: "+ str(ack_num)
	print "URG: "+ str(URG)
	print "ACK: "+ str(ACK)
	print "PSH: "+ str(PSH)
	print "SYN: "+ str(SYN)
	print "FIN: "+ str(FIN)
	print "window: "+ str(window)
	print "urgent pointer: "+str(urgent_pointer)
	'''
	return data[20:]

def analyze_udp_header(data):

	udp_header = struct.unpack("!4s4s2H",data[:12])
	source_add = socket.inet_ntoa(udp_header[0])
	destination_add = socket.inet_ntoa(udp_header[1])
	zero = udp_header[2] >> 8
	protocol = udp_header[2] & 0x00ff
	UDP_length = udp_header[3]

	'''
	print "!-------UDP Header-------!"
	print "Source Address: "+ source_add
	print "Destination Address: "+ destination_add
	print "Zero: "+str(zero)
	print "Protocol: "+str(protocol)
	print "UDP_length: "+str(UDP_length)
	'''
	return


def getCityCountry(source_add,dest_add,geo):

	geoD = geo.record_by_name(dest_add)
	geoS = geo.record_by_name(source_add)

	print "-----------------------------------"
	print "Source IP Address: " + source_add

	if geoS:
		if geoS['city']:
			print "source City: "+ geoS['city']
		if geoS['country_name']:
			print "source Country: "+ geoS['country_name']

	print "Destination IP Address: " + dest_add
	if geoD:
		if geoD['city']:
			print "destination City: "+geoD['city']
		if geoD['country_name']:
			print "destination Country: "+ geoD['country_name']


main()
