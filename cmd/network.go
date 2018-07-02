package main

import (
	"gopp"
	"log"
	"net"
)

const (
	NET_PACKET_PING_REQUEST    = 0x00 /* Ping request packet ID. */
	NET_PACKET_PING_RESPONSE   = 0x01 /* Ping response packet ID. */
	NET_PACKET_GET_NODES       = 0x02 /* Get nodes request packet ID. */
	NET_PACKET_SEND_NODES_IPV6 = 0x04 /* Send nodes response packet ID for other addresses. */
	NET_PACKET_COOKIE_REQUEST  = 0x18 /* Cookie request packet */
	NET_PACKET_COOKIE_RESPONSE = 0x19 /* Cookie response packet */
	NET_PACKET_CRYPTO_HS       = 0x1a /* Crypto handshake packet */
	NET_PACKET_CRYPTO_DATA     = 0x1b /* Crypto data packet */
	NET_PACKET_CRYPTO          = 0x20 /* Encrypted data packet ID. */
	NET_PACKET_LAN_DISCOVERY   = 0x21 /* LAN discovery packet ID. */

	/* See: docs/Prevent_Tracking.txt and onion.{ch} */
	NET_PACKET_ONION_SEND_INITIAL = 0x80
	NET_PACKET_ONION_SEND_1       = 0x81
	NET_PACKET_ONION_SEND_2       = 0x82

	NET_PACKET_ANNOUNCE_REQUEST    = 0x83
	NET_PACKET_ANNOUNCE_RESPONSE   = 0x84
	NET_PACKET_ONION_DATA_REQUEST  = 0x85
	NET_PACKET_ONION_DATA_RESPONSE = 0x86

	NET_PACKET_ONION_RECV_3 = 0x8c
	NET_PACKET_ONION_RECV_2 = 0x8d
	NET_PACKET_ONION_RECV_1 = 0x8e

	BOOTSTRAP_INFO_PACKET_ID = 0xf0 /* Only used for bootstrap nodes */

	NET_PACKET_MAX = 0xff /* This type must remain within a single uint8. */
)

var netpktnames = map[uint8]string{
	NET_PACKET_PING_REQUEST:    "PING_REQUEST",
	NET_PACKET_PING_RESPONSE:   "PING_RESPONSE",
	NET_PACKET_GET_NODES:       "GET_NODES",
	NET_PACKET_SEND_NODES_IPV6: "SEND_NODES_IPV6",
	NET_PACKET_COOKIE_REQUEST:  "COOKIE_REQUEST",
	NET_PACKET_COOKIE_RESPONSE: "COOKIE_RESPONSE",
	NET_PACKET_CRYPTO_HS:       "CRYPTO_HS",
	NET_PACKET_CRYPTO_DATA:     "CRYPTO_DATA",
	NET_PACKET_CRYPTO:          "CRYPTO",
	NET_PACKET_LAN_DISCOVERY:   "LAN_DISCOVERY",

	/* See: docs/Prevent_Tracking.txt and onion.{ch} */
	NET_PACKET_ONION_SEND_INITIAL: "ONION_SEND_INITIAL",
	NET_PACKET_ONION_SEND_1:       "ONION_SEND_1",
	NET_PACKET_ONION_SEND_2:       "ONION_SEND_2",

	NET_PACKET_ANNOUNCE_REQUEST:    "ANNOUNCE_REQUEST",
	NET_PACKET_ANNOUNCE_RESPONSE:   "ANNOUNCE_RESPONSE",
	NET_PACKET_ONION_DATA_REQUEST:  "ONION_DATA_REQUEST",
	NET_PACKET_ONION_DATA_RESPONSE: "ONION_DATA_RESPONSE",

	NET_PACKET_ONION_RECV_3: "ONION_RECV_3",
	NET_PACKET_ONION_RECV_2: "ONION_RECV_2",
	NET_PACKET_ONION_RECV_1: "ONION_RECV_1",

	BOOTSTRAP_INFO_PACKET_ID: "BOOTSTRAP_INFO_PACKET_ID",

	NET_PACKET_MAX: "NET_PACKET_MAX",
}

func netpktname(ptype uint8) string {
	if name, ok := netpktnames[ptype]; ok {
		return name
	}
	return netpktnames[NET_PACKET_MAX]
}

///// for familar the packet format
type _DHTPacket struct {
	// plain
	Ptype  uint8
	Pubkey [PUBLIC_KEY_SIZE]byte
	Nonce  [NONCE_SIZE]byte
	// encrypted
	// Bytes []byte	// some subpacket here
	RequestId uint64 // tail of any subpacket
}
type _DHTPacketGetNodes struct {
	_DHTPacket
	// encrypted
	Pubkey [PUBLIC_KEY_SIZE]byte
}
type _DHTPacketNodesResponse struct {
	_DHTPacket
	// encrypted
	NumOfNodes uint8
	Nodes      [4]NodeFormat
}
type _DHTPacketPing struct { //???
	_DHTPacket
	// encrypted
	ResponseFlag uint8
}

/////
type PacketHandleFunc func(object interface{}, addr net.Addr, data []byte, cbdata interface{}) (int, error)
type PacketHandle struct {
	Func   func(object interface{}, addr net.Addr, data []byte, cbdata interface{}) (int, error)
	Object interface{}
}

type NetworkCore struct {
	srv *net.UDPConn

	PacketHandlers map[uint8]PacketHandle
}

func NewNetworkCore() *NetworkCore {
	this := &NetworkCore{}
	this.PacketHandlers = make(map[uint8]PacketHandle, 256)

	laddr := &net.UDPAddr{}
	laddr.IP = net.ParseIP("0.0.0.0")
	var srv *net.UDPConn
	var err error
	for i := 0; i < 100; i++ {
		laddr.Port = 33445 - 100 + i
		srv, err = net.ListenUDP("udp", laddr)
		gopp.ErrPrint(err)
		if err == nil {
			break
		}
	}
	log.Println("Listen on UDP:", srv.LocalAddr().String())
	this.srv = srv

	this.start()
	return this
}
func (this *NetworkCore) RegisterHandle(ptype uint8, cbfn PacketHandleFunc, object interface{}) {
	this.PacketHandlers[ptype] = PacketHandle{cbfn, object}
}

/// for read here
func (this *NetworkCore) start() { go this.doPoll(nil) }
func (this *NetworkCore) doPoll(cbdata interface{}) {
	for {
		rdbuf := make([]byte, 2000)
		rn, raddr, err := this.srv.ReadFrom(rdbuf)
		gopp.ErrPrint(err, rn, raddr)
		if err != nil {
			break
		}
		if rn < 1 {
			continue
		}
		// dispatch
		rdbuf = rdbuf[:rn]
		pktname := netpktname(rdbuf[0])
		log.Println("recv UDP pkt:", rn, raddr.String(), pktname)
		h, ok := this.PacketHandlers[rdbuf[0]]
		if !ok || h.Func == nil {
			log.Println("Packet has no handler:", pktname)
			continue
		}

		iret, err := h.Func(h.Object, raddr, rdbuf, cbdata)
		gopp.ErrPrint(err, iret, pktname)
	}
	log.Println("DHT read routine done.")
}

func (this *NetworkCore) Write(data []byte) (int, error) { return this.srv.Write(data) }
func (this *NetworkCore) WriteTo(data []byte, addr net.Addr) (int, error) {
	wn, err := this.srv.WriteTo(data, addr)
	return wn, err
}
