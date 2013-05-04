#!/usr/bin/env python
 
#http://tools.ietf.org/html/rfc1459.html#section-2.3.1


from scapy.all import *
import re

#@TODO
#Function has bugs no not in use. This function should be used. For now, a brute force approach is used below. Probably yacc parser can be used
def check_header(s):
	ip = "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])" #IP addresses
	host = "(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])" #hostnames
	servername = "%s|%s"%(ip,host)
	channel = "[\#|\&][a-zA-Z0-9]*"
	special = "[\-\[\]\{\}\`\\]"
	nick = "[a-zA-Z][a-z|A-Z|0-9|%s]*"%special
	mask = "[\#|\$][a-zA-Z0-9]"
	user = "[.]*"
	to = "%s|%s\@%s|%s|%s"%(channel,user,servername,nick,mask)
	target = "%s[,%s]*"%(to,to)
	crlf = "\r\n"
	trailing = "[\S]*"
	middle = "[\S]+"
	space = "[ ]+"
	params = "%s[:%s|%s[%s:%s]*[%s:%s]]"%(space,trailing,middle,space,middle,space,trailing)
	command = "[a-zA-Z]+|[0-9][0-9][0-9]"
	prefix = "%s|%s[\!%s]?[\@%s]"%(servername,nick,user,host)
	message = "[:%s%s]?%s%s%s"%(prefix,space,command,params,crlf)

	p = re.compile(message)
	res = re.match(str(s))
	if res:
		return True
	else:
		return False

#@TODO
# def check_header_yacc(s):
# 	tokens = (
# 				message,prefix,command,SPACE,
# 				params,
# 				target,to,channel,servername,
# 				host,nick,mask,user,

# 		)
# 	t_space = r' '
# 	t_middle = r'[\S]+'
# 	t_trailing = r'[\S]*'
# 	t_crlf = r'[\r\n]'
# 	t_comma = r'\,'
# 	t_colon = r'\:'
# 	t_ex = r'\!'
# 	t_at = r'\@'
# 	t_hash = r'\#'
# 	t_nonwhite = r'\S'
# 	t_letter = r'[a-zA-Z_]'
# 	t_number = r'[0-9_]'
# 	t_symbol = r'\-\[\]\{\}\`\^'
	





class IRC(Packet):
	name="IRC PROTOCOL [RFC 1459]"
	fields_desc=[
					StrField("prefix", None, fmt="H"),
					StrField("command", None, fmt="H"),
					StrField("params", None, fmt="H"),
	]

	def do_dissect(self, s):
		flist = self.fields_desc
		cr = chr(0x0D)
		lf = chr(0x0A)
		crlf = str(cr+lf)   				#"carriage return" "linefeed"
		SPACE = chr(0x20)
		data = s.split(crlf)[0]
		#if check_header(i2m(s)) == False : return
		if data:
			p1 = 1
			if data[0] == ':':
				p1 = data.find(SPACE)
				prefix = data[1:p1]
			p2 = p1 + data[p1+1:].find(SPACE)
			command = data[p1+1:p2]
			params = data[p2:]

			self.setfieldval(flist[0].name,prefix)
			self.setfieldval(flist[1].name,command)
			self.setfieldval(flist[2].name,params)
			

bind_layers(TCP,IRC)





