from scapy.all import *
import sys
from dnsdetector import *


class DNSAnalyzer():
	def __init__(self,packets,outputFile):
		self.packets = packets
		self.packet_list = []
		self.outputFile = outputFile
	
	def DNSParser(self):
		self.packet_list = []
		
		for i in self.packets:
			if i.haslayer(DNS):
				self.packet_list.append(i)		
		wrpcap(self.outputFile, self.packet_list)

	def DNSAnomalyDetector(self):

		self.anomalyFile = "dnsanomaly.pcap"
		#self.anomalyLogFile = "dnsAnomaly.log"
		self.anomaly_list = []


		for x in self.packets:
			response = DNSMalformedPacketDectector(x)
			if response == True:
				self.anomaly_list.append(x)

		if self.anomaly_list:
			wrpcap(self.anomalyFile, self.anomaly_list)
		



packets = rdpcap("dns-remoteshell.pcap")
outputFile = "dnspackets.pcap"
a = DNSAnalyzer(packets,outputFile)
a.DNSParser()
a.DNSAnomalyDetector()
