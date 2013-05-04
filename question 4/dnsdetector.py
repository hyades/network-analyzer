from scapy.all import *
import sys

DNSPORT = [
				53,		
		]

def DNSMalformedPacketDectector(x):

	#Restricting DNS Packets by size. Max size we can assume for a DNS packet is around 512 bytes. Anything greater than this is considered as anomaly
	global DNSPORT
	MAXSIZE = 512 			#considering dnssec also
	try:
		dport = x[IP].dport
		sport = x[IP].sport
		size = len(x)
		#print size
		if (dport in DNSPORT) or (sport in DNSPORT):
			if size > MAXSIZE:
				print >> sys.stderr, "ANOMALY DETECTED: MAX SIZE OF PACKET EXCEEDED"
				print x.show()
				return True


		if x.haslayer(DNS):
			l = x[DNS].qd.qname.split('.')
			for i in l:
				if len(i) > 64:
					print >> sys.stderr,"ANOMALY DETECTED: MAX SIZE OF NAME FIELD (INTERNAL) EXCEEDED"
					return True
			if len(x[DNS].qd.qname) > 254:
				print >> sys.stderr,"ANOMALY DETECTED: MAX SIZE OF NAME FIELD EXCEEDED"
				return True
	except:
		return False

	#Other detection modules can be added here
	return False



