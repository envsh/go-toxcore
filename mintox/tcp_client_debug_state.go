package mintox

import (
	"gopp"
	"log"
	"time"
)

type TcpClientDebugState struct {
	ConnBegin_       time.Time
	ConnUsed         time.Duration
	Handshake1Used   time.Duration
	Handshake2Begin_ time.Time
	Handshake2Used   time.Duration
	LastRecvPing     time.Time
	LastRecvPong     time.Time
}

func NewTcpClientDebugState() *TcpClientDebugState {
	this := &TcpClientDebugState{}
	return this
}

func (this *TcpClientDebugState) ConnBegin() { this.ConnBegin_ = time.Now() }
func (this *TcpClientDebugState) ConnEnd() {
	this.ConnUsed = time.Since(this.ConnBegin_)
}
func (this *TcpClientDebugState) Handshake2Begin() { this.Handshake2Begin_ = time.Now() }
func (this *TcpClientDebugState) Handshake2End() {
	this.Handshake2Used = time.Since(this.Handshake2Begin_)
}
func (this *TcpClientDebugState) RecvPing() { this.LastRecvPing = time.Now() }
func (this *TcpClientDebugState) RecvPong() { this.LastRecvPong = time.Now() }

// for recv pkt after confirm
func (this *TcpClientDebugState) RecvPkt(plnpkt []byte) {
	ptype := plnpkt[0]
	switch {
	case ptype == TCP_PACKET_PING:
		this.RecvPing()
	case ptype == TCP_PACKET_PONG:
		this.RecvPong()
	case ptype == TCP_PACKET_ROUTING_RESPONSE:
	case ptype == TCP_PACKET_CONNECTION_NOTIFICATION:
	case ptype == TCP_PACKET_DISCONNECT_NOTIFICATION:
	case ptype == TCP_PACKET_OOB_RECV: // TODO
	case ptype == TCP_PACKET_ONION_RESPONSE: // TODO
	case ptype >= NUM_RESERVED_PORTS:
	case ptype > TCP_PACKET_ONION_RESPONSE && ptype < NUM_RESERVED_PORTS:
	default:
		// log.Fatalln("wtf", ptype, tcppktname(ptype))
	}
}

func (this *TcpClientDebugState) Dump() {
	log.Println("ConnUsed:", gopp.Dur2hum(this.ConnUsed))
	log.Println("Handshake2Used:", gopp.Dur2hum(this.Handshake2Used))
	log.Println("LastRecvPing:", gopp.SinceHum(this.LastRecvPing))
	log.Println("LastRecvPong:", gopp.SinceHum(this.LastRecvPong))
	log.Println("AliveTime:", gopp.SinceHum(this.ConnBegin_))
}
