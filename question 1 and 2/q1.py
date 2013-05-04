from scapy.all import *


a = rdpcap("http.cap")
f = open("out.csv","w")
f.write("source,target,value\n")
dict = {}

for i in range(len(a)):
	#print i,":",dict
	src = a[i][1].src
	dst = a[i][1].dst
	try:
		dict[src][dst]+=1
	except KeyError:
		#print i
		try:
			dict1 = dict[src]
			dict1[dst] = 1
			dict[src]=dict1
		except:
			dict1 = {}
			dict1[dst] = 1
			dict[src] = dict1

print dict

for x in dict:
	for y in dict[x]:
		f.write(str(x) + "," + str(y) + "," + str(dict[x][y])+ "\n")

