def flatten(lst):
	return list(itertools.chain(*lst))


class GDPPDU(object):

	BASE_HEADER_LENGTH = 80

	class GDPException(Exception):
		pass

	def __init__(self, pkt):
		self.pkts = [pkt]
		self.raw_data = raw_data_from_pkt(pkt)
		if self.ver != 2 and self.ver != 3:
			raise GDPPDU.GDPException("unknown protocol version")
		if self.reserved != 0:
			raise GDPPDU.GDPException("reserved non-zero")

		if len(self.raw_data) > self.expected_total_pdu_bytes:
			print 'bad'
			raise GDPPDU.GDPException("too much raw_data")

		if len(self.raw_data) < GDPPDU.BASE_HEADER_LENGTH:
			print 'too short'
			raise GDPPDU.GDPException("header too short")

	@property
	def ver(self):
		return ord(self.raw_data[0])

	@property
	def ttl(self):
		return ord(self.raw_data[1])

	@property
	def reserved(self):
		return ord(self.raw_data[2])

	@property
	def cmd(self):
		return ord(self.raw_data[3])

	@property
	def dst(self):
		return self.raw_data[4:36]

	@property
	def src(self):
		return self.raw_data[36:68]

	@property
	def rid(self):
		return self.raw_data[68:72]

	@property
	def sig_info(self):
		return struct.unpack(">H", self.raw_data[72:74])[0]

	@property
	def sig_digest(self):
		return (self.sig_info & 0xF000) >> 12

	@property
	def sig_len(self):
		return self.sig_info & 0x0FFF

	@property
	def opt_len(self):
		return ord(self.raw_data[74]) * 4

	@property
	def flags(self):
		return ord(self.raw_data[75])

	@property
	def data_len(self):
		return struct.unpack(">L", self.raw_data[76:80])[0]

	@property
	def data(self):
		data_start = GDPPDU.BASE_HEADER_LENGTH + self.opt_len
		return self.raw_data[data_start:data_start + self.data_len]

	@property
	def sig(self):
		sig_start = GDPPDU.BASE_HEADER_LENGTH + self.opt_len + self.data_len
		return self.raw_data[sig_start:sig_start + sig_len]

	@property
	def complete(self):
		return len(self.raw_data) == self.expected_total_pdu_bytes

	@property
	def total_network_bytes(self):
		return sum(map(len, self.pkts))

	@property
	def expected_total_pdu_bytes(self):
		return GDPPDU.BASE_HEADER_LENGTH + self.opt_len + self.data_len + self.sig_len

	def add_data(self, pkt):
		new_raw_data = raw_data_from_pkt(pkt)
		if len(self.raw_data) + len(new_raw_data) > self.expected_total_pdu_bytes:
			raise GDPPDU.GDPException("Too much data! Bad header.")
		self.pkts.append(pkt)
		self.raw_data += new_raw_data

	@staticmethod
	def valid_pdu_header(pkt):
		if len(raw_data_from_pkt(pkt)) < GDPPDU.BASE_HEADER_LENGTH:
			return False
		try:
			GDPPDU(pkt)
			return True
		except GDPPDU.GDPException:
			return False


def raw_data_from_pkt(pkt):
	return str(pkt[TCP].payload)

def key_from_pkt(pkt):
	return (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)

streams = dict()
complete_pdus = defaultdict(list)
ignore_count = 0

ignores = []
seen = set()
bad = []

# process streams
for i in range(len(gdp_02)):
	#print i
	pkt = gdp_02[i]
	key = key_from_pkt(pkt)
	raw_data = raw_data_from_pkt(pkt)
	if key not in streams:
		# not currently building pdu for key
		if GDPPDU.valid_pdu_header(pkt):
			# packet has balid pdu header, start new pdu
			streams[key] = GDPPDU(pkt)
		else:
			# no valid pdu header
			if len(raw_data) == 0 and key in seen:
				# probably just an ack. skip over it
				continue
			else:
				if key in seen:
					# whats going on? we don't have an in progress pdu for the
					# key and it's not a header but we have seen previous pdus
					# for this key. probably a TCP retransmission
					print 'oops'
				ignores.append(pkt)
				continue
	else:
		# currently building pdu for key
		try:
			streams[key].add_data(pkt)
		except:
			# packet causes PDU to become too long
			# delete currently built up pdu. this shouldnt happen!
			#import ipdb; ipdb.set_trace()
			#raise Exception("pdu too long. corrupt data")
			streams[key].pkts.append(pkt)
			bad += streams[key].pkts
			del streams[key]
			print
			continue

	pdu = streams[key]
	if pdu.complete:
		del streams[key]
		seen.add(key)
		complete_pdus[key].append(pdu)

pdus = flatten(complete_pdus.values())
sigs = filter(lambda pdu: pdu.sig_info != 0, pdus)
bad_pkts = flatten(bad)

total_bytes = sum(map(len, gdp_02))
meaningless_bytes = sum(map(len, ignores)) + sum(map(lambda pdu: pdu.total_network_bytes, streams.values())) + sum(map(len, bad_pkts))
meaningful_bytes = total_bytes - meaningless_bytes

total_gdp_bytes = sum(map(lambda pdu: len(pdu.raw_data), pdus))
total_gdp_data_bytes = sum(map(lambda pdu: len(pdu.data), pdus))
