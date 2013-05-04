from scapy.all import *
from q3 import IRC



class IRCAnalyzer():
	def __init__(self,packets,outputFile):
		self.packets = packets
		self.packet_list = None
		self.outputFile = outputFile
	
	def IRCParser(self):
		self.packet_list = []
		

		for i in self.packets:
			if i.haslayer(IRC):
				self.packet_list.append(i)
				
		wrpcap(self.outputFile, self.packet_list)

packets = rdpcap('SkypeIRC.cap')
outputFile = "ircpackets.cap"
a  = IRCAnalyzer(packets,outputFile)
a.IRCParser()

