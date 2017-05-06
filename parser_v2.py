import site; site.addsitedir("/usr/local/lib/python2.7/site-packages")
from scapy.all import *

CMDS_ACKS = {
	# blind commands
	0: 'CMD_KEEPALIVE',
	1: 'CMD_ADVERTISE',
	2: 'CMD_WITHDRAW',
	3: 'GDP_CMD_ROUTER_META',
	# acked commands
	64: 'CMD_PING',
	65: 'CMD_HELLO',
	66: 'CMD_CREATE [Note: This will change in the future!',
	67: 'CMD_OPEN_AO',
	68: 'CMD_OPEN_RO',
	69: 'CMD_CLOSE',
	70: 'CMD_READ',
	71: 'CMD_APPEND',
	74: 'CMD_GETMETADATA',
	# acks,
	128: 'ACK_SUCCESS',
	129: 'ACK_CREATED',
	130: 'ACK_DELETED',
	131: 'ACK_VALID',
	132: 'ACK_CHANGED',
	133: 'ACK_CONTENT',
	192: 'NAK_C_BADREQ',
	193: 'NAK_C_UNAUTH',
	194: 'NAK_C_BADOPT',
	195: 'NAK_C_FORBIDDEN',
	196: 'NAK_C_NOTFOUND',
	197: 'NAK_C_METHNOTALLOWED',
	198: 'NAK_C_NOTACCEPTABLE',
	201: 'NAK_C_CONFLICT',
	204: 'NAK_C_PRECONFAILED',
	205: 'NAK_C_TOOLARGE',
	207: 'NAK_C_UNSUPMEDIA',
	224: 'NAK_S_INTERNAL',
	225: 'NAK_S_NOTIMPL',
	226: 'NAK_S_BADGATEWAY',
	227: 'NAK_S_SVCUNAVAIL',
	228: 'NAK_S_GWTIMEOUT',
	229: 'NAK_S_PROXYNOTSUP',
	238: 'NAK_S_REPLICATE_FAIL',
	239: 'NAK_S_EXITING',
	240: 'NAK_R_NOROUTE',
}

FLAGS = ['UNASSIGNED',
		 'GDP_PDU_HAS_RECNO',
		 'GDP_PDU_HAS_SEQNO',
		 'GDP_PDU_HAS_TS',
		 'UNASSIGNED',
		 'UNASSIGNED',
		 'UNASSIGNED',
		 'UNASSIGNED']

class GDP(Packet):
	name = 'GDP'
	fields_desc = [
		# bytes [0, 4)
		XByteField('version', 0x03),
		ByteField('ttl', 0),
		ByteField('reserved', 0),
		ByteEnumField('cmd', None, CMDS_ACKS),
		# bytes [4, 68)
		StrFixedLenField('dst', None, 32),
		StrFixedLenField('src', None, 32),
		# bytes [68, 72)
		IntField('rid', 0),
		# bytes [72, 76)
		XShortField('sig_info', None),
		ByteField('opt_len', 0),
		FlagsField('flags', 0, 8, FLAGS),
		# bytes [76, 80)
		IntField('data_len', 0)
	]
# for now, bind to all TCP ports
bind_layers(TCP, GDP)

if __name__ == '__main__':
	gdp_02 = rdpcap('gdp-02.pcap')