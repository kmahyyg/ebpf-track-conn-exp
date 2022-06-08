package utils

import (
	"fmt"
)

var sockDataList = map[uint32]string{
	uint32(1):  "SOCK_STREAM",
	uint32(2):  "SOCK_DGRAM",
	uint32(3):  "SOCK_RAW",
	uint32(4):  "SOCK_RDM",
	uint32(5):  "SOCK_SEQPACKET",
	uint32(6):  "SOCK_DCCP",
	uint32(10): "SOCK_PACKET",
}

var familyDataList = map[uint16]string{
	uint16(0):  "AF_UNSPEC",
	uint16(1):  "AF_UNIX|AF_LOCAL",
	uint16(2):  "AF_INET",
	uint16(3):  "AF_AX25",
	uint16(4):  "AF_IPX",
	uint16(5):  "AF_APPLETALK",
	uint16(6):  "AF_NETROM",
	uint16(7):  "AF_BRIDGE",
	uint16(8):  "AF_ATMPVC",
	uint16(9):  "AF_X25",
	uint16(10): "AF_INET6",
	uint16(11): "AF_ROSE",
	uint16(12): "AF_DECnet",
	uint16(13): "AF_NETBEUI",
	uint16(14): "AF_SECURITY",
	uint16(15): "AF_KEY",
	uint16(16): "AF_NETLINK|AF_ROUTE",
	uint16(17): "AF_PACKET",
	uint16(18): "AF_ASH",
	uint16(19): "AF_ECONET",
	uint16(20): "AF_ATMSVC",
	uint16(21): "AF_RDS",
	uint16(22): "AF_SNA",
	uint16(23): "AF_IRDA",
	uint16(24): "AF_PPPOX",
	uint16(25): "AF_WANPIPE",
	uint16(26): "AF_LLC",
	uint16(27): "AF_IB",
	uint16(28): "AF_MPLS",
	uint16(29): "AF_CAN",
	uint16(30): "AF_TIPC",
	uint16(31): "AF_BLUETOOTH",
	uint16(32): "AF_IUCV",
	uint16(33): "AF_RXRPC",
	uint16(34): "AF_ISDN",
	uint16(35): "AF_PHONET",
	uint16(36): "AF_IEEE802154",
	uint16(37): "AF_CAIF",
	uint16(38): "AF_ALG",
	uint16(39): "AF_NFC",
	uint16(40): "AF_VSOCK",
	uint16(41): "AF_KCM",
	uint16(42): "AF_QIPCRTR",
	uint16(43): "AF_SMC",
	uint16(44): "AF_XDP",
	uint16(45): "AF_MCTP",
	uint16(46): "AF_MAX",
}

var protocolDataList = map[uint32]string{
	uint32(0):   "IPPROTO_IP",
	uint32(1):   "IPPROTO_ICMP",
	uint32(2):   "IPPROTO_IGMP",
	uint32(4):   "IPPROTO_IPIP",
	uint32(6):   "IPPROTO_TCP",
	uint32(8):   "IPPROTO_EGP",
	uint32(12):  "IPPROTO_PUP",
	uint32(17):  "IPPROTO_UDP",
	uint32(22):  "IPPROTO_IDP",
	uint32(29):  "IPPROTO_TP",
	uint32(33):  "IPPROTO_DCCP",
	uint32(41):  "IPPROTO_IPV6",
	uint32(46):  "IPPROTO_RSVP",
	uint32(47):  "IPPROTO_GRE",
	uint32(50):  "IPPROTO_ESP",
	uint32(51):  "IPPROTO_AH",
	uint32(92):  "IPPROTO_MTP",
	uint32(94):  "IPPROTO_BEETPH",
	uint32(98):  "IPPROTO_ENCAP",
	uint32(103): "IPPROTO_PIM",
	uint32(108): "IPPROTO_COMP",
	uint32(132): "IPPROTO_SCTP",
	uint32(136): "IPPROTO_UDPLITE",
	uint32(137): "IPPROTO_MPLS",
	uint32(143): "IPPROTO_ETHERNET",
	uint32(255): "IPPROTO_RAW",
	uint32(262): "IPPROTO_MPTCP",
	uint32(263): "IPPROTO_MAX",
}

func ParseSocketFamily(fam uint16) string {
	// thanks to GitHub CoPilot
	defer func() {
		if err := recover(); err != nil {
			fmt.Println("ParseSocketFamily error: undefined protocol")
		}
	}()
	return familyDataList[fam]
}

func ParseSocketType(typ uint32) string {
	if typ > 10 || typ < 0 {
		return "--"
	}
	defer func() {
		if err := recover(); err != nil {
			fmt.Println("ParseSocketType error: undefined socket type")
		}
	}()
	return sockDataList[typ]
}

func ParseSocketProtocol(prot uint32) string {
	defer func() {
		if err := recover(); err != nil {
			fmt.Println("ParseSocketProtocol error: undefined socket protocol")
		}
	}()
	return protocolDataList[prot]
}

func ParseConnectIPAddr(addr uint32) string {
	// from sin.in_addr as uint32 to decimal IPv4 addr
	return fmt.Sprintf("%d.%d.%d.%d", byte(addr>>24), byte(addr>>16), byte(addr>>8), byte(addr))
}
