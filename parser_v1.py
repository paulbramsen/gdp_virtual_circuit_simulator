import site; site.addsitedir("/usr/local/lib/python2.7/site-packages")
from scapy.all import *

gdp_02 = rdpcap('gdp-02.pcap')

counts = defaultdict(int)
empty = 0

for pkt in gdp_02:
	if Raw in pkt:
		counts[ord(pkt[Raw].load[0])] += 1
	else:
		empty += 1




def pkt_raw_data(pkt):
	return str(pkt[TCP].payload)


streams = dict()
complete_pdus = defaultdict(list)
ignore_count = 0

bad = []

# process streams
for i in range(len(gdp_02)):
	pkt = gdp_02[i]
	key = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)
	raw_data = pkt_raw_data(pkt)
	if key not in streams:
		if GDPPDU.valid_pdu_header(raw_data):
			streams[key] = GDPPDU(raw_data)
		else:
			ignore_count += 1
			continue
	else:
		# key is in streams so we must be building a pdu
		try:
			streams[key].add_raw_data(raw_data)
		except:
			bad.append((key, i))
			del streams[key]
			continue

	pdu = streams[key]
	if pdu.complete:
		del streams[key]
		complete_pdus[key].append(pdu)






import socket
addrs = set(zip(*complete_pdus.keys())[0] + zip(*complete_pdus.keys())[1])
for addr in addrs:
	print socket.gethostbyaddr(addr)



# extract srcs/dsts
non_inter_router_comm_count = 0
inter_router_comm_count = 0
dsts = defaultdict(int)
srcs = defaultdict(int)
for i in range(len(gdp_02)):
	pk = gdp_02[i]
	if Raw in pk:
		try:
			pdu = GDPPDU(pk)
		except:
			continue
		srcs[pdu.src] += 1
		dsts[pdu.dst] += 1
		if pdu.src != router or pdu.dst != router:
		    non_inter_router_comm_count += 1
		else:
			inter_router_comm_count += 1

# find a pdu with a specific src/dst
def find_pdus(pdus, val):
	result = []
	for i in range(len(pdus)):
		pk = gdp_02[i]
		if Raw not in pk:
			continue
		pdu = GDPPDU(pk)
		if (pdu.ver != 2 and pdu.ver != 3) or pdu.reserved != 0:
			continue
		if pdu.src == val or pdu.dst == val:
			result.append(i)
	return result
find_pdus(gdp_02, 'st_room_label": "FT223", "est_co')


def find_pdus(pdus, test):
	result = []
	for i in range(len(pdus)):
		pk = gdp_02[i]
		if Raw not in pk:
			continue
		try:
			pdu = GDPPDU(pk)
		except:
			continue
		if test(pdu):
			result.append(i)
	return result
res = find_pdus(gdp_02, lambda pdu: pdu.flags != 0)

class GDP(Packet):
	name = 'GDP'
	fields_desc = [
		ByteField('version', 0x03),
		ByteField('ttl', 0),
		ByteField('reserved', 0),
		ByteField('cmd', 0)
	]
bind_layers(TCP, GDP)



sigs = []
for pkt in gdp_02:
	try:
		pdu = GDPPDU(pkt)
		if(pdu.sig_info != 0):
			sigs.append(pdu)
	except:
		pass
