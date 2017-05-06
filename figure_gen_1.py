#import PDUVersion2 from pdu
#import PDUVersion3 from pdu
#import site; site.addsitedir("/usr/local/lib/python2.7/site-packages")
from matplotlib import pyplot as plt
from scapy.all import *

#print '1'
#gdp_01 = rdpcap('gdp-01.pcap')
print '2'
gdp_02 = rdpcap('gdp-02.pcap')
print '3'
gdp_03 = rdpcap('gdp-03.pcap')
print '4'
gdp_04 = rdpcap('gdp-04.pcap')

GDP_ROUTER_ADDRESS = '\xff\x00' * 16

def binary_to_integer(bytes):
	res = 0
	for b in bytes:
		res = (res << 8) | ord(b)
	return res

def counts(a):
	counts = defaultdict(int)
	for v in a:
		counts[v] += 1
	return counts

def pkt_raw_data(pkt):
	return str(pkt[TCP].payload)

def packet_byte_total(packets):
	return sum(map(len, packets))

def pdu_byte_total(pdus):
	for pdu in pdus:
		assert pdu.opt_len + pdu.data_len + pdu.sig_len + 80 == len(pdu.buffer)
	return sum(map(lambda pdu: len(pdu.buffer), pdus))

def client_client_pdus(pdus):
	return filter(lambda pdu: pdu.source_address != GDP_ROUTER_ADDRESS and pdu.destination_address != GDP_ROUTER_ADDRESS, pdus)

def router_client_pdus(pdus):
	return filter(lambda pdu: (pdu.source_address != GDP_ROUTER_ADDRESS) != (pdu.destination_address != GDP_ROUTER_ADDRESS), pdus)

def router_router_pdus(pdus):
	return filter(lambda pdu: pdu.source_address == GDP_ROUTER_ADDRESS and pdu.destination_address == GDP_ROUTER_ADDRESS, pdus)


def process(packets, name):
	print('Processing %s' % name)
	streams = defaultdict(str)
	dropped_packets = []
	pdus = []

	for i in range(len(packets)):
		pkt = packets[i]

		key = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)
		old_data = streams[key]
		new_data = pkt_raw_data(pkt)
		data = old_data + new_data

		while True:
			if len(data) == 0:
				break	   # can't figure out the version

			# check the version number
			version = ord(data[0])
			if version == 2:
				PDU = PDUVersion2
			elif version == 3:
				PDU = PDUVersion3
			else:   # bogus version number
				dropped_packets.append(pkt)
				del streams[key]
				break

			pdu = PDU(buffer(data))

			if pdu is not None:
				pdu.time = pkt.time
				pdus.append(pdu)
				data = data[len(pdu):]
			
			streams[key] = data
			
			if pdu is None:
				# Incomplete pdu [TODO: maybe unparsable. deal with it.]
				break
			#esc; import ipdb; ipdb.set_trace()


	total_bytes = packet_byte_total(packets)
	print('total_bytes:                   %s' % total_bytes)
	dropped_bytes = packet_byte_total(dropped_packets)
	print('dropped_bytes:                 %s' % dropped_bytes)

	cc_pdus = client_client_pdus(pdus)
	rc_pdus = router_client_pdus(pdus)
	rr_pdus = router_router_pdus(pdus)

	remaining_bytes = packet_byte_total(streams.values())
	good_bytes = total_bytes - dropped_bytes - remaining_bytes
	print(float(good_bytes) / total_bytes)

	total_gdp_bytes = sum(map(lambda pdu: len(pdu.buffer), pdus))
	print('total_gdp_bytes                %s' % total_gdp_bytes)
	total_client_client_pdu_bytes = pdu_byte_total(cc_pdus)
	print('total_client_client_pdu_bytes: %s' % total_client_client_pdu_bytes)
	total_router_client_pdu_bytes = pdu_byte_total(rc_pdus)
	print('total_router_client_pdu_bytes: %s' % total_router_client_pdu_bytes)
	total_router_router_pdu_bytes = pdu_byte_total(rr_pdus)
	print('total_router_router_pdu_bytes: %s' % total_router_router_pdu_bytes)

	total_gdp_client_data_bytes = sum(map(lambda pdu: pdu.data_len, cc_pdus))
	print('total_gdp_client_data_bytes:   %s' % total_gdp_client_data_bytes)

	rws = filter(lambda pdu: ord(pdu.cmd) == 133 or ord(pdu.cmd) == 71, pdus)
	rw_counts = counts(map(lambda pdu: ord(pdu.cmd), rws))
	total_reads = rw_counts[133]
	total_writes = rw_counts[71]
	rws_sigs = filter(lambda pdu: pdu.sig_len != 0, rws)
	rw_sig_counts = counts(map(lambda pdu: ord(pdu.cmd), rws_sigs))
	total_sig_reads = rw_sig_counts[133]
	total_sig_writes = rw_sig_counts[71]

	print('total reads:                   %f' % total_reads)
	print('Portion of reads signed:       %f' % (total_sig_reads / float(total_reads)))
	print('total writes:                  %f' % total_writes)
	print('Portion of writes signed:      %f' % (total_sig_writes / float(total_writes)))
	return pdus

gdp_01_pdus = process(gdp_01, 'gdp_01')
gdp_02_pdus = process(gdp_02, 'gdp_02')
gdp_03_pdus = process(gdp_03, 'gdp_03')
gdp_04_pdus = process(gdp_04, 'gdp_04')
pdus = gdp_01_pdus + gdp_02_pdus + gdp_03_pdus + gdp_04_pdus

cc_pdus = client_client_pdus(pdus)

def determine_log_server_addr(pdus):
	ACKED_CMDS = 0
	ACKS = 1
	addr_1 = pdus[0].source_address
	addr_2 = pdus[0].destination_address
	counts = {
		addr_1: [0, 0],
		addr_2: [0, 0]
	}
	for pdu in pdus:
		src = pdu.source_address
		if 64 <= ord(pdu.cmd) <=127:
			counts[src][ACKED_CMDS] += 1
		elif ord(pdu.cmd) > 127:
			counts[src][ACKS] += 1
	diff = ((counts[addr_1][ACKED_CMDS] - counts[addr_1][ACKS])
		  - (counts[addr_2][ACKED_CMDS] - counts[addr_2][ACKS])) #/ float(len(pdus))
	return addr_1 if diff < 0 else addr_2

# timeout in seconds
def bytes_using_proto_4(pdus, sig_rate, timeout):
	SRCDST_SIZE        = 64
	ESTABLISHMENT_SIZE = 158
	FLOW_ID_SIZE       = 4

	PACKET_LATENCY = .001

	v4_bytes = 0
	circuit_setup_p1_time     = 0
	new_circuit_setup_p1_time = 0
	circuit_last_use_time     = 0
	new_circuit_last_use_time = 0
	addrs = set((pdus[0].source_address, pdus[0].destination_address))
	log_server_addr = determine_log_server_addr(pdus)
	assert log_server_addr in addrs

	for i in range(len(pdus)):
		pdu = pdus[i]
		pdu_bytes = len(pdu.buffer)
		src = pdu.source_address
		dst = pdu.destination_address
		assert src in addrs and dst in addrs
		
		if new_circuit_last_use_time + PACKET_LATENCY < pdu.time:
			circuit_last_use_time = new_circuit_last_use_time
		if new_circuit_setup_p1_time + PACKET_LATENCY < pdu.time:
			circuit_setup_p1_time = new_circuit_setup_p1_time

		pdu_bytes += (-80 + 16)
		pdu_bytes += (1 / float(sig_rate)) * pdu.sig_len - pdu.sig_len
		if pdu.time - circuit_last_use_time < timeout:
			# there is a channel
			pdu_bytes += FLOW_ID_SIZE
			circuit_last_use_time = pdu.time
		elif src == log_server_addr and pdu.time - circuit_setup_p1_time < timeout:
			# finish second half of flow establishment
			pdu_bytes += FLOW_ID_SIZE + ESTABLISHMENT_SIZE
			new_circuit_last_use_time = pdu.time
		elif src != log_server_addr and pdu.time - circuit_setup_p1_time > timeout:
			# begin flow establishment
			pdu_bytes += SRCDST_SIZE + FLOW_ID_SIZE + ESTABLISHMENT_SIZE
			new_circuit_setup_p1_time = pdu.time
		else:
			# no channel
			pdu_bytes += SRCDST_SIZE
		v4_bytes += pdu_bytes
	return v4_bytes

client_client_pdu_flows = defaultdict(list)
for pdu in cc_pdus:
	key = [pdu.source_address, pdu.destination_address]
	key.sort()
	key = tuple(key)
	client_client_pdu_flows[key].append(pdu)
client_client_pdu_flows = client_client_pdu_flows.values()

top_flow_xvals = xrange(0, 61, 3)
top_flow_savings = []
NUM_FLOWS_TO_INCLUDE_PCT_SIG_FREQ = [(1, 1), (1, 100), (5, 100), (10, 1), (10, 100), (25, 100)]
for pct, sig_rate in NUM_FLOWS_TO_INCLUDE_PCT_SIG_FREQ:
	num_flows = (int)((pct / 100.0) * len(client_client_pdu_flows))
	if num_flows == 0:
		num_flows = 1
	print((num_flows, sig_rate))
	top_n_flow_savings = []
	for timeout in top_flow_xvals:
		vals = [float(bytes_using_proto_4(client_client_pdu_flows[i], sig_rate=sig_rate, timeout=timeout)) /
				pdu_byte_total(client_client_pdu_flows[i])
				for i in range(len(client_client_pdu_flows))]
		vals.sort()
		top_n_flow_savings.append(sum(vals[:num_flows]) / float(num_flows))
	top_flow_savings.append(top_n_flow_savings)

for i in range(len(top_flow_savings)):
	savings = top_flow_savings[i]
	label = 'Top %s%% flows; %ipkts/sig' % NUM_FLOWS_TO_INCLUDE_PCT_SIG_FREQ[i]
	plt.plot(top_flow_xvals, savings, lw=3.0, label=label)
plt.plot((0, top_flow_xvals[-1]), (1, 1), 'k-', lw=3.0, label='Old protocol')
plt.legend(loc='upper right')
plt.xlabel('timeout (s)')
plt.ylabel('[v4 bytes] / [v3 bytes]')
plt.title('Proportion of bytes sent relative to old protocol VS Timeout')
plt.ylim(.3, 1.3)
plt.show()


