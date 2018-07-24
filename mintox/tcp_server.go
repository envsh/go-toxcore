package mintox

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"gopp"
	"io"
	"log"
	"math/rand"
	"net"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/djherbis/buffer"
	"github.com/pkg/errors"
	deadlock "github.com/sasha-s/go-deadlock"
)

const MAX_INCOMING_CONNECTIONS = 256

const TCP_MAX_BACKLOG = MAX_INCOMING_CONNECTIONS

const MAX_PACKET_SIZE = 2048

const TCP_HANDSHAKE_PLAIN_SIZE = (PUBLIC_KEY_SIZE + NONCE_SIZE)
const TCP_SERVER_HANDSHAKE_SIZE = (NONCE_SIZE + TCP_HANDSHAKE_PLAIN_SIZE + MAC_SIZE)
const TCP_CLIENT_HANDSHAKE_SIZE = (PUBLIC_KEY_SIZE + TCP_SERVER_HANDSHAKE_SIZE)
const TCP_MAX_OOB_DATA_LENGTH = 1024

const NUM_RESERVED_PORTS = 16
const NUM_CLIENT_CONNECTIONS = (256 - NUM_RESERVED_PORTS)

const TCP_PACKET_ROUTING_REQUEST = 0
const TCP_PACKET_ROUTING_RESPONSE = 1
const TCP_PACKET_CONNECTION_NOTIFICATION = 2
const TCP_PACKET_DISCONNECT_NOTIFICATION = 3
const TCP_PACKET_PING = 4
const TCP_PACKET_PONG = 5
const TCP_PACKET_OOB_SEND = 6
const TCP_PACKET_OOB_RECV = 7
const TCP_PACKET_ONION_REQUEST = 8
const TCP_PACKET_ONION_RESPONSE = 9

const ARRAY_ENTRY_SIZE = 6

/* frequency to ping connected nodes and timeout in seconds */
const TCP_PING_FREQUENCY = 30
const TCP_PING_TIMEOUT = 10

const (
	TCP_STATUS_NO_STATUS = iota
	TCP_STATUS_CONNECTED
	TCP_STATUS_UNCONFIRMED
	TCP_STATUS_CONFIRMED
)

//////////

var tcppktnames = map[byte]string{
	TCP_PACKET_ROUTING_REQUEST:         "ROUTING_REQUEST",
	TCP_PACKET_ROUTING_RESPONSE:        "ROUTING_RESPONSE",
	TCP_PACKET_CONNECTION_NOTIFICATION: "CONNECTION_NOTIFICATION",
	TCP_PACKET_DISCONNECT_NOTIFICATION: "DISCONNECT_NOTIFICATION",
	TCP_PACKET_PING:                    "PING",
	TCP_PACKET_PONG:                    "PONG",
	TCP_PACKET_OOB_SEND:                "OOB_SEND",
	TCP_PACKET_OOB_RECV:                "OOB_RECV",
	TCP_PACKET_ONION_REQUEST:           "ONION_REQUEST",
	TCP_PACKET_ONION_RESPONSE:          "ONION_RESPONSE",
}

func tcppktname(ptype byte) string {
	name := "TCP_PACKET_INVALID"
	if ptype > TCP_PACKET_ONION_RESPONSE && ptype < NUM_RESERVED_PORTS {
	} else if ptype >= NUM_RESERVED_PORTS {
		name = fmt.Sprintf("DATA_FOR_CONNID_%d", ptype)
	} else {
		name = tcppktnames[ptype]
	}
	return name
}

/////////
type PeerConnInfo struct {
	Pubkey  *CryptoKey
	Index   uint32 // connid
	Status  uint8
	Otherid uint8
	Connid  uint8 // self
}
type TCPSecureConn struct {
	Sock      net.Conn
	Pubkey    *CryptoKey // client's
	Seckey    *CryptoKey // self
	Shrkey    *CryptoKey
	RecvNonce *CBNonce
	SentNonce *CBNonce

	connmu     deadlock.RWMutex
	ConnInfos  map[string]*PeerConnInfo // binpk => *PeerConnInfo
	ConnInfos2 map[uint8]*PeerConnInfo  // connid =>
	connidmu   deadlock.RWMutex
	ConnIds    map[uint8]bool // connid => used
	Status     uint8

	crbuf      buffer.Buffer // conn read ring buffer
	cwctrlq    chan []byte   // ctrl packets like pong []byte
	cwctrldlen int32         // data length of cwctrlq
	cwdataq    chan []byte
	cwdatadlen int32 // data length of cwdataq

	Identifier uint64

	LastPinged time.Time
	Pingid     uint64

	OnNetRecv   func(int)
	OnClosed    func(Object)
	OnConfirmed func(Object)
	OnNetSent   func(int)

	srvo *TCPServer
}

type TCPServer struct {
	Oniono Object // TODO
	lsners []net.Listener

	Pubkey *CryptoKey
	Seckey *CryptoKey

	// c's flow: accept->incomingq -> unconfirmedq -> acceptedq
	connmu   deadlock.RWMutex
	Conns    map[string]*TCPSecureConn // binsk =>
	hsconnmu deadlock.RWMutex
	HSConns  map[net.Conn]*TCPSecureConn
}

/////
func NewTCPSecureConn(c net.Conn) *TCPSecureConn {
	this := &TCPSecureConn{}
	this.Sock = c
	c.(*net.TCPConn).SetWriteBuffer(128 * 1024)

	this.ConnInfos = map[string]*PeerConnInfo{}
	this.ConnInfos2 = map[uint8]*PeerConnInfo{}
	this.ConnIds = this.initConnids()
	this.crbuf = buffer.NewRing(buffer.New(1024 * 1024))
	this.cwctrlq = make(chan []byte, 64)
	this.cwdataq = make(chan []byte, 128)

	return this
}
func (this *TCPSecureConn) Start() {
	go this.runReadLoop()
	go this.runWriteLoop()
}
func (this *TCPSecureConn) runReadLoop() {
	lastLogTime := time.Now().Add(-3 * time.Second)
	spdc := NewSpeedCalc()
	var nxtpktlen uint16
	stop := false
	for !stop {
		c := this.Sock
		if int(time.Since(lastLogTime).Seconds()) >= 1 {
			lastLogTime = time.Now()
			log.Printf("------- async reading... ----- spd: %d, %s ------\n", spdc.Avgspd, c.RemoteAddr())
		}
		rdbuf := make([]byte, 3000)
		rn, err := c.Read(rdbuf)
		gopp.ErrPrint(err, rn, c.RemoteAddr())
		if err == io.EOF {
			this.Status = TCP_STATUS_NO_STATUS
		}
		if err != nil {
			break
		}
		rdbuf = rdbuf[:rn]
		if rn < 1 {
			log.Println("Invalid packet:", rn, c.RemoteAddr())
			break
		}

		if this.OnNetRecv != nil {
			this.OnNetRecv(rn)
		}
		spdc.Data(rn)
		gopp.Assert(this.crbuf.Len()+int64(rn) <= this.crbuf.Cap(), "ring buffer full",
			this.crbuf.Len()+int64(rn), this.crbuf.Cap())
		wn, err := this.crbuf.Write(rdbuf)
		gopp.ErrPrint(err)
		gopp.Assert(wn == rn, "write ring buffer failed", rn, wn)
		this.doReadPacket(&nxtpktlen)
	}
	log.Println("read done.", this.Sock.RemoteAddr(), tcpstname(this.Status))
	this.doClose()
}
func (this *TCPSecureConn) doReadPacket(nxtpktlen *uint16) {
	stop := false
	for !stop {
		var rdbuf []byte
		switch {
		case this.Status == TCP_STATUS_NO_STATUS:
			// handshake request packet
			*nxtpktlen = (PUBLIC_KEY_SIZE+NONCE_SIZE)*2 + MAC_SIZE
			rdbuf = make([]byte, *nxtpktlen)
			rn, err := this.crbuf.Read(rdbuf)
			gopp.ErrPrint(err)
			gopp.Assert(rn == cap(rdbuf), "not read enough data", rn, cap(rdbuf))
		case this.Status == TCP_STATUS_UNCONFIRMED || this.Status == TCP_STATUS_CONFIRMED:
			// length+payload
			if *nxtpktlen == 0 && this.crbuf.Len() < int64(unsafe.Sizeof(uint16(0))) {
				return
			}
			if *nxtpktlen == 0 && this.crbuf.Len() >= int64(unsafe.Sizeof(uint16(0))) {
				pktlenbuf := make([]byte, 2)
				rn, err := this.crbuf.Read(pktlenbuf)
				gopp.ErrPrint(err, rn)
				err = binary.Read(bytes.NewBuffer(pktlenbuf), binary.BigEndian, nxtpktlen)
				gopp.ErrPrint(err)
			}
			if this.crbuf.Len() < int64(*nxtpktlen) {
				return
			}
			rdbuf = make([]byte, 2+*nxtpktlen)
			err := binary.Write(gopp.NewBufferBuf(rdbuf).WBufAt(0), binary.BigEndian, *nxtpktlen)
			gopp.ErrPrint(err)
			rn, err := this.crbuf.Read(rdbuf[2:])
			gopp.ErrPrint(err)
			gopp.Assert(rn+2 == cap(rdbuf), "not read enough data", rn+2, cap(rdbuf))
		}

		switch {
		case this.Status == TCP_STATUS_NO_STATUS:
			this.HandleHandshake(rdbuf)
			this.Status = TCP_STATUS_UNCONFIRMED
		case this.Status == TCP_STATUS_UNCONFIRMED:
			datlen, plnpkt, err := this.Unpacket(rdbuf)
			gopp.ErrPrint(err, len(rdbuf), *nxtpktlen, "//")
			ptype := plnpkt[0]
			log.Println("read data pkt:", len(rdbuf), datlen, ptype, tcppktname(ptype))
			this.HandlePingRequest(plnpkt)
			this.Status = TCP_STATUS_CONFIRMED
			if this.OnConfirmed != nil {
				this.OnConfirmed(this)
			}
			this.LastPinged = time.Now()
			go this.doPingLoop()
		case this.Status == TCP_STATUS_CONFIRMED:
			// TODO read ringbuffer
			datlen, plnpkt, err := this.Unpacket(rdbuf)
			gopp.ErrPrint(err)
			ptype := plnpkt[0]
			if ptype < NUM_RESERVED_PORTS {
				log.Printf("read data pkt: rdlen:%d, datlen:%d, pktype: %d, pktname: %s\n",
					len(rdbuf), datlen, ptype, tcppktname(ptype))
			}
			switch {
			case ptype == TCP_PACKET_PING:
				// this.HandlePingRequest(plnpkt)
			case ptype == TCP_PACKET_PONG:
				// this.HandlePingResponse(plnpkt)
				this.LastPinged = time.Now()
			case ptype == TCP_PACKET_ROUTING_REQUEST:
				this.handleRoutingRequest(plnpkt)
			case ptype == TCP_PACKET_ROUTING_RESPONSE:
				// this.HandleRoutingResponse(plnpkt)
			case ptype == TCP_PACKET_CONNECTION_NOTIFICATION:
				// this.HandleConnectionNotification(plnpkt)
			case ptype == TCP_PACKET_DISCONNECT_NOTIFICATION:
				// this.HandleDisconnectNotification(plnpkt)
			case ptype == TCP_PACKET_OOB_RECV: // TODO
			case ptype == TCP_PACKET_ONION_RESPONSE: // TODO
			case ptype >= NUM_RESERVED_PORTS:
				this.HandleRoutingData(plnpkt)
			case ptype > TCP_PACKET_ONION_RESPONSE && ptype < NUM_RESERVED_PORTS:
				// this.HandleReservedData(plnpkt)
			default:
				log.Fatalln("wtf", ptype, tcppktname(ptype))
			}
		default:
			log.Fatalln("wtf", tcpstname(this.Status))
		}
		*nxtpktlen = 0
	}
}

func (this *TCPSecureConn) runWriteLoop() {
	spdc := NewSpeedCalc()

	flushCtrl := func() error {
		for len(this.cwctrlq) > 0 {
			data := <-this.cwctrlq
			atomic.AddInt32(&this.cwctrldlen, -int32(len(data)))
			var datai = []interface{}{data}
			wn, err := this.WritePacket(datai[0].([]byte))
			gopp.ErrPrint(err, wn, this.Sock.RemoteAddr())
			if err != nil {
				return err
			}
			spdc.Data(wn)
			if this.OnNetSent != nil {
				this.OnNetSent(wn)
			}
			// gopp.Assert(wn == len(datai[0].([]byte)), "write lost", wn, len(datai[0].([]byte)), this.ServAddr)
		}
		return nil
	}

	lastLogTime := time.Now().Add(-3 * time.Second)
	stop := false
	for !stop {
		data, rdok, ctrlq := []byte(nil), false, false
		select {
		case data, rdok = <-this.cwctrlq:
			atomic.AddInt32(&this.cwctrldlen, -int32(len(data)))
			ctrlq = true
		case data, rdok = <-this.cwdataq:
			atomic.AddInt32(&this.cwdatadlen, -int32(len(data)))
		}
		if !rdok && len(data) == 0 { // maybe close
			break
		}

		var datai = []interface{}{data}
		wn, err := this.WritePacket(datai[0].([]byte))
		gopp.ErrPrint(err, wn, this.Sock.RemoteAddr())
		if err != nil {
			goto endloop
		}
		spdc.Data(wn)
		if this.OnNetSent != nil {
			this.OnNetSent(wn)
		}
		// gopp.Assert(wn == len(datai[0].([]byte)), "write lost", wn, len(datai[0].([]byte)), this.ServAddr)
		if !ctrlq {
			err = flushCtrl()
			gopp.ErrPrint(err)
			if err != nil {
				goto endloop
			}
		}

		if int(time.Since(lastLogTime).Seconds()) >= 1 {
			lastLogTime = time.Now()
			log.Printf("------- async wrote ----- spd: %d, %s, pq:%d, cq:%d------\n",
				spdc.Avgspd, this.Sock.RemoteAddr(), len(this.cwctrlq), len(this.cwdataq))
		}
	}
endloop:
	log.Println("write routine done:", this.Sock.RemoteAddr())
	this.doClose()
}
func (this *TCPSecureConn) SetHandshakeInfo() {

}
func (this *TCPSecureConn) doPingLoop() {
	stop := false
	for !stop {
		time.Sleep(TCP_PING_FREQUENCY * time.Second / 1)
		if int(time.Since(this.LastPinged).Seconds()) > (TCP_PING_FREQUENCY+TCP_PING_TIMEOUT)/1 {
			log.Println("srv ping timeout:", int(time.Since(this.LastPinged).Seconds()), this.Sock.RemoteAddr())
			break
		}
		pingpkt := this.MakePingPacket()
		_, err := this.Sock.Write(pingpkt)
		gopp.ErrPrint(err, this.Sock.RemoteAddr())
		if err != nil {
			break
		}
		this.SentNonce.Incr()
		// this.LastPinged = time.Now()
		// log.Println("sent ping to:", len(pingpkt), this.Sock.RemoteAddr(), this.Pingid)
	}
	log.Println("ping routine done:", this.Sock.RemoteAddr())
	this.doClose()
}
func (this *TCPSecureConn) doClose() {
	info := this.Sock.RemoteAddr()
	defer func() {
		if err := recover(); err != nil {
			log.Println("already closed:", info, err)
		}
	}()
	this.Sock.Close()
	close(this.cwctrlq)
	close(this.cwdataq)
	this.Status = TCP_STATUS_NO_STATUS
	if this.OnClosed != nil {
		this.OnClosed(this)
	}
	this.OnClosed = nil
	this.OnConfirmed = nil
	this.OnNetRecv = nil
	this.OnNetSent = nil
}
func (this *TCPSecureConn) Close() { this.doClose() }

func (this *TCPSecureConn) HandleRoutingData(rpkt []byte) {
	connid := rpkt[0]
	pci, ok := this.ConnInfos2[connid]
	if !ok {
		log.Println("connid not found:", connid)
		return
	}
	peerco, ok2 := this.srvo.Conns[pci.Pubkey.BinStr()]
	if !ok2 {
		log.Println("peer not found:", pci.Pubkey.ToHex20())
		return
	}
	pci3, ok3 := peerco.ConnInfos[this.Pubkey.BinStr()]
	if !ok3 {
		log.Println("peer not connect you:", peerco.Sock.RemoteAddr())
		return
	}
	log.Println("src/dst connid:", connid, pci3.Connid, peerco.Sock.RemoteAddr())
	_, err := peerco.SendDataPacket(pci3.Connid, rpkt[1:])
	gopp.ErrPrint(err, connid, this.Sock.RemoteAddr(), pci3.Connid, peerco.Sock.RemoteAddr())
}

func (*TCPSecureConn) initConnids() map[uint8]bool {
	ids := map[uint8]bool{}
	for i := 0; i < NUM_CLIENT_CONNECTIONS; i++ {
		ids[uint8(i)] = false
	}
	return ids
}
func (this *TCPSecureConn) nextConnid() uint8 {
	this.connidmu.Lock()
	defer this.connidmu.Unlock()
	for connid, used := range this.ConnIds {
		if !used {
			this.ConnIds[connid] = true
			return connid + NUM_RESERVED_PORTS
		}
	}
	return 0 //math.MaxUint8
}
func (this *TCPSecureConn) freeConnid(connid uint8) {
	this.connidmu.Lock()
	defer this.connidmu.Unlock()
	this.ConnIds[connid-NUM_RESERVED_PORTS] = false
}

func (this *TCPSecureConn) handleRoutingRequest(reqpkt []byte) {
	peerpk := NewCryptoKey(reqpkt[1 : 1+PUBLIC_KEY_SIZE])
	/* If person tries to cennect to himself we deny the request*/
	if peerpk.Equal(this.Pubkey.Bytes()) {
		// response connid=0
		this.sendRoutingResponse(0, peerpk)
		return
	}
	// 检查和该peer的连接是否已经存在，存在则直接返回
	// 检查是否到了连接数上限，如果到了则返回connid=0。否则创建新的连接并返回连接号
	// 检查是否peerpk也请求连接自己了，如果有则发送connect_notification

	if cio, ok := this.ConnInfos[peerpk.BinStr()]; ok {
		if cio.Status > 0 {
			// send_routing_resonse()
			this.sendRoutingResponse(cio.Connid, peerpk)
			return
		}
	}

	///
	connid := this.nextConnid()
	if connid == 0 {
		log.Println("No free connid")
		// response connid=0
		// send_routing_resonse()
		this.sendRoutingResponse(0, peerpk)
		return
	}

	pci := &PeerConnInfo{}
	pci.Status = 1
	pci.Pubkey = peerpk
	pci.Connid = connid

	this.ConnInfos[peerpk.BinStr()] = pci
	this.ConnInfos2[connid] = pci
	log.Println("Use routing connid:", connid, peerpk.ToHex())
	// send_routing_resonse()
	this.sendRoutingResponse(connid, peerpk)

	///
	this.srvo.connmu.Lock()
	peerco, ok := this.srvo.Conns[peerpk.BinStr()]
	this.srvo.connmu.Unlock()
	if ok {
		peerco.connmu.Lock()
		pci2, ok2 := peerco.ConnInfos[this.Pubkey.BinStr()]
		peerco.connmu.Unlock()
		if ok2 {
			pci.Status = 2
			pci.Otherid = pci2.Connid

			pci2.Status = 2
			pci2.Otherid = connid
			log.Println("two peer connected each other:", this.Sock.RemoteAddr(), peerco.Sock.RemoteAddr())
			this.SendConnectNotification(pci.Connid)
			peerco.SendConnectNotification(pci2.Connid)
		}
	}
}

func (this *TCPSecureConn) sendRoutingResponse(connid uint8, peerpk *CryptoKey) {
	plnpkt := gopp.NewBufferZero()
	plnpkt.WriteByte(uint8(TCP_PACKET_ROUTING_RESPONSE))
	plnpkt.WriteByte(connid)
	plnpkt.Write(peerpk.Bytes())
	_, err := this.SendCtrlPacket(plnpkt.Bytes())
	gopp.ErrPrint(err, connid, plnpkt.Len())
}

func (this *TCPSecureConn) SendConnectNotification(connid uint8) {
	data := []byte{TCP_PACKET_CONNECTION_NOTIFICATION, connid}
	this.SendCtrlPacket(data)
}
func (this *TCPSecureConn) SendDisconnectNotification() {
	data := []byte{TCP_PACKET_DISCONNECT_NOTIFICATION, connid}
	this.SendCtrlPacket(data)
}

func (this *TCPSecureConn) HandleHandshake(rdbuf []byte) {
	cliPubkey := NewCryptoKey(rdbuf[:PUBLIC_KEY_SIZE])
	cliTmpNonce := NewCBNonce(rdbuf[PUBLIC_KEY_SIZE : PUBLIC_KEY_SIZE+NONCE_SIZE])
	shrkey, err := CBBeforeNm(cliPubkey, this.Seckey)
	gopp.ErrPrint(err)
	this.Pubkey = cliPubkey

	cliplnpkt, err := DecryptDataSymmetric(shrkey, cliTmpNonce, rdbuf[PUBLIC_KEY_SIZE+NONCE_SIZE:])
	gopp.ErrPrint(err, len(rdbuf), len(cliplnpkt))
	hstmppk := NewCryptoKey(cliplnpkt[:PUBLIC_KEY_SIZE])
	log.Println("hs request from:", this.Sock.RemoteAddr(), hstmppk.ToHex()[:20], cliPubkey.ToHex()[:20])
	// gopp.Assert(hstmppk.Equal(this.SelfPubkey), info string, args ...interface{})
	this.RecvNonce = NewCBNonce(cliplnpkt[PUBLIC_KEY_SIZE : PUBLIC_KEY_SIZE+NONCE_SIZE])

	this.SentNonce = CBRandomNonce()
	srvTmpNonce := CBRandomNonce()

	tmpPubkey, tmpSeckey, _ := NewCBKeyPair()
	this.Shrkey, _ = CBBeforeNm(hstmppk, tmpSeckey)
	srvplnpkt := gopp.NewBufferZero()
	srvplnpkt.Write(tmpPubkey.Bytes())
	srvplnpkt.Write(this.SentNonce.Bytes())

	encpkt, err := EncryptDataSymmetric(shrkey, srvTmpNonce, srvplnpkt.Bytes())
	gopp.ErrPrint(err)

	wrbuf := gopp.NewBufferZero()
	wrbuf.Write(srvTmpNonce.Bytes())
	wrbuf.Write(encpkt)
	wn, err := this.Sock.Write(wrbuf.Bytes())
	gopp.ErrPrint(err, wn, wrbuf.Len())
}

func (this *TCPSecureConn) HandlePingRequest(rpkt []byte) {
	plnpkt := gopp.NewBufferZero()
	plnpkt.WriteByte(byte(TCP_PACKET_PONG))
	plnpkt.Write(rpkt[1:]) // pingid

	this.SendCtrlPacket(plnpkt.Bytes())
	// encpkt, err := this.CreatePacket(plnpkt.Bytes())
	// gopp.ErrPrint(err)
	// wn, err := this.conn.Write(encpkt)
	// gopp.ErrPrint(err, wn)
}

func (this *TCPSecureConn) WritePacket(data []byte) (int, error) {
	encpkt, err := this.CreatePacket(data)
	gopp.ErrPrint(err)
	wn, err := this.Sock.Write(encpkt)
	gopp.ErrPrint(err)
	if err == nil {
		this.SentNonce.Incr()
	}
	return wn, err
}

func (this *TCPSecureConn) SendCtrlPacket(data []byte) (encpkt []byte, err error) {
	if len(data) > 2048 {
		return nil, errors.Errorf("Data too long: %d, want: %d", len(data), 2048)
	}
	if len(this.cwctrlq) >= cap(this.cwctrlq) {
		log.Println("Ctrl queue is full, drop pkt...", len(data), this.cwctrldlen)
		return nil, errors.New("Ctrl queue is full")
	}
	btime := time.Now()
	select {
	case this.cwctrlq <- data:
		atomic.AddInt32(&this.cwctrldlen, int32(len(data)))
	default:
		log.Println("Ctrl queue is full, drop pkt...", len(data), this.cwctrldlen)
		return nil, errors.New("Ctrl queue is full")
	}
	// encpkt, err = this.CreatePacket(buf.Bytes())
	// this.WritePacket(encpkt)
	dtime := time.Since(btime)
	if dtime > 5*time.Millisecond {
		log.Fatalln("send use too long", len(data), dtime)
	} else if dtime > 2*time.Millisecond {
		log.Println("send use too long", len(data), dtime)
	}
	return
}

// TODO split data
func (this *TCPSecureConn) SendDataPacket(connid uint8, data []byte) (encpkt []byte, err error) {
	if len(data) > 2048 {
		return nil, errors.Errorf("Data too long: %d, want: %d", len(data), 2048)
	}
	if len(this.cwdataq) >= cap(this.cwdataq) {
		log.Println("Data queue is full, drop pkt.", len(this.cwdataq), connid, len(data), this.cwdatadlen)
		return nil, errors.New("Data queue is full")
	}
	buf := gopp.NewBufferZero()
	buf.WriteByte(byte(connid))
	buf.Write(data)
	btime := time.Now()
	select {
	case this.cwdataq <- buf.Bytes():
		atomic.AddInt32(&this.cwdatadlen, int32(buf.Len()))
	default:
		log.Println("Data queue is full, drop pkt.", len(this.cwdataq), connid, len(data), this.cwdatadlen)
		return nil, errors.New("Data queue is full")
	}
	dtime := time.Since(btime)
	if dtime > 2*time.Millisecond {
		log.Println("send use too long", len(data), dtime)
	}
	return
}

func (this *TCPSecureConn) MakePingPacket() []byte {
	/// first ping
	ping_plain := gopp.NewBufferZero()
	ping_plain.WriteByte(byte(TCP_PACKET_PING))
	pingid := rand.Uint64()
	pingid = gopp.IfElse(pingid == 0, uint64(1), pingid).(uint64)
	this.Pingid = pingid
	binary.Write(ping_plain, binary.BigEndian, pingid)
	// log.Println("ping plnpkt len:", ping_plain.Len())

	encpkt, err := this.CreatePacket(ping_plain.Bytes())
	gopp.ErrPrint(err)

	if false {
		ping_encrypted, err := EncryptDataSymmetric(this.Shrkey, this.SentNonce, ping_plain.Bytes())
		gopp.ErrPrint(err)

		ping_pkt := gopp.NewBufferZero()
		binary.Write(ping_pkt, binary.BigEndian, uint16(len(ping_encrypted)))
		ping_pkt.Write(ping_encrypted)
		log.Println(ping_pkt.Len(), len(ping_encrypted))
		return ping_pkt.Bytes()
	}

	return encpkt
}

// tcp data packet, not include handshake packet
func (this *TCPSecureConn) CreatePacket(plain []byte) (encpkt []byte, err error) {
	// log.Println(len(plain), this.Shrkey.ToHex()[:20], this.SentNonce.ToHex())
	encdat, err := EncryptDataSymmetric(this.Shrkey, this.SentNonce, plain)
	gopp.ErrPrint(err)

	pktbuf := gopp.NewBufferZero()
	binary.Write(pktbuf, binary.BigEndian, uint16(len(encdat)))
	pktbuf.Write(encdat)
	encpkt = pktbuf.Bytes()
	// log.Println("create pkg:", tcppktname(plain[0]), len(encpkt), len(plain))
	// this.SentNonce.Incr()
	return
}
func (this *TCPSecureConn) Unpacket(encpkt []byte) (datlen uint16, plnpkt []byte, err error) {
	err = binary.Read(bytes.NewReader(encpkt), binary.BigEndian, &datlen)
	gopp.ErrPrint(err)
	plnpkt, err = DecryptDataSymmetric(this.Shrkey, this.RecvNonce, encpkt[2:])
	this.RecvNonce.Incr()
	return
}

/////
func NewTCPServer(ports []uint16, seckey *CryptoKey, oniono Object) *TCPServer {
	this := &TCPServer{}
	this.Seckey = seckey
	this.Pubkey = CBDerivePubkey(seckey)
	this.Conns = map[string]*TCPSecureConn{}
	this.HSConns = map[net.Conn]*TCPSecureConn{}

	for i, port := range ports {
		lsner, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		gopp.ErrPrint(err, port)
		if err != nil {
			return nil
		}
		log.Println("listened on:", i, lsner.Addr().String())
		this.lsners = append(this.lsners, lsner)
	}

	return this
}

func (this *TCPServer) Start() {
	for _, lsner := range this.lsners {
		go this.runAcceptProc(lsner)
	}
}

// should block
func (this *TCPServer) runAcceptProc(lsner net.Listener) {
	stop := false
	for !stop {
		c, err := lsner.Accept()
		gopp.ErrPrint(err, lsner.Addr())
		if err != nil {
			break
		}
		this.startHandshake(c)
	}
	log.Println("done", lsner.Addr())
}

func (this *TCPServer) startHandshake(c net.Conn) {
	this.hsconnmu.Lock()
	defer this.hsconnmu.Unlock()
	secon := NewTCPSecureConn(c)
	secon.srvo = this
	secon.Seckey = this.Seckey
	secon.OnConfirmed = this.onConnConfirmed
	secon.OnClosed = this.onConnClosed
	this.HSConns[c] = secon
	secon.Start()
}
func (this *TCPServer) onConnConfirmed(obj Object) {
	c := obj.(*TCPSecureConn)
	this.hsconnmu.Lock()
	defer this.hsconnmu.Unlock()
	if _, ok := this.HSConns[c.Sock]; ok {
		delete(this.HSConns, c.Sock)
	}
	this.connmu.Lock()
	defer this.connmu.Unlock()
	if oc, ok := this.Conns[c.Pubkey.BinStr()]; ok {
		log.Println("Already connected:", c.Pubkey.ToHex()[:20])
		delete(this.Conns, c.Pubkey.BinStr())
		oc.OnClosed = nil
		oc.Close()
	}
	this.Conns[c.Pubkey.BinStr()] = c
}
func (this *TCPServer) onConnClosed(obj Object) {
	c := obj.(*TCPSecureConn)
	this.hsconnmu.Lock()
	defer this.hsconnmu.Unlock()
	if _, ok := this.HSConns[c.Sock]; ok {
		delete(this.HSConns, c.Sock)
	}
	this.connmu.Lock()
	defer this.connmu.Unlock()
	if _, ok := this.Conns[c.Pubkey.BinStr()]; ok {
		delete(this.Conns, c.Pubkey.BinStr())
	}
}
