package mintox

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"gopp"
	"io"
	"log"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/djherbis/buffer"
	"github.com/goph/emperror"
	deadlock "github.com/sasha-s/go-deadlock"

	// "github.com/pkg/errors"
	funk "github.com/thoas/go-funk"
)

const (
	TCP_CLIENT_NO_STATUS = iota
	TCP_CLIENT_PROXY_HTTP_CONNECTING
	TCP_CLIENT_PROXY_SOCKS5_CONNECTING
	TCP_CLIENT_PROXY_SOCKS5_UNCONFIRMED
	TCP_CLIENT_CONNECTING
	TCP_CLIENT_UNCONFIRMED
	TCP_CLIENT_CONFIRMED
	TCP_CLIENT_DISCONNECTED
)

var tcpstnames = map[uint8]string{
	TCP_CLIENT_NO_STATUS:                "NO_STATUS",
	TCP_CLIENT_PROXY_HTTP_CONNECTING:    "PROXY_HTTP_CONNECTING",
	TCP_CLIENT_PROXY_SOCKS5_CONNECTING:  "PROXY_SOCKS5_CONNECTING",
	TCP_CLIENT_PROXY_SOCKS5_UNCONFIRMED: "PROXY_SOCKS5_UNCONFIRMED",
	TCP_CLIENT_CONNECTING:               "CONNECTING",
	TCP_CLIENT_UNCONFIRMED:              "UNCONFIRMED",
	TCP_CLIENT_CONFIRMED:                "CONFIRMED",
	TCP_CLIENT_DISCONNECTED:             "DISCONNECTED",
}

func tcpstname(status uint8) string {
	if name, ok := tcpstnames[status]; ok {
		return name
	}
	return "Unknown"
}

const TCP_CONNECTION_TIMEOUT = 10

type ClientHandshake struct {
	SelfPubkey *CryptoKey
	ServerHandshake
}

func NewClientHandshake(TempPubkey, SelfPubkey *CryptoKey, TempNonce, SentNonce *CBNonce) *ClientHandshake {
	return &ClientHandshake{SelfPubkey, ServerHandshake{TempNonce, TempPubkey, SentNonce}}
}
func (this *ClientHandshake) Encrypt() (encrypted []byte, err error) {
	return
}
func ClientHandshakeFrom(encpkt []byte, shrkey *CryptoKey) *ClientHandshake {
	return nil
}

type ServerHandshake struct {
	TempNonce *CBNonce
	//
	TempPubkey *CryptoKey
	SentNonce  *CBNonce
}

func NewServerHandshake() *ServerHandshake { return &ServerHandshake{} }
func ServerHandshakeFrom(encpkt []byte, shrkey *CryptoKey) *ServerHandshake {
	return nil
}

type PeekableRing struct {
	*bufio.Reader
	buf_ buffer.Buffer
}

func (this *PeekableRing) Write(p []byte) (int, error) { return this.buf_.Write(p) }
func (this *PeekableRing) Size() int64                 { return this.Len() }
func (this *PeekableRing) Len() int64 {
	rd := this.Reader
	n := int64(rd.Buffered()) + this.buf_.Len()
	return n
}
func (this *PeekableRing) Cap() int64 {
	rd := this.Reader
	n := int64(rd.Size()) + this.buf_.Cap()
	return n
}
func NewPeekableRing(b buffer.Buffer) *PeekableRing {
	this := &PeekableRing{}
	b = buffer.New(1024 * 1024)
	this.buf_ = b
	this.Reader = bufio.NewReader(bufio.NewReader(b))
	return this
}

type TCPClient struct {
	status   uint8
	stmu     deadlock.RWMutex
	ServAddr string

	SelfPubkey *CryptoKey
	SelfSeckey *CryptoKey
	ServPubkey *CryptoKey
	ServSeckey *CryptoKey // for test
	Shrkey     *CryptoKey // combined key
	// temp_pubkey *CryptoKey
	TempSeckey *CryptoKey
	SentNonce  *CBNonce
	RecvNonce  *CBNonce
	TempNonce  *CBNonce

	KillAt    time.Time
	LastPined uint64
	PingDoneC chan struct{}

	PingRequestId uint64

	// peer connections via this relay tcp tunnel
	Conns [NUM_CLIENT_CONNECTIONS]struct {
		Status uint8
		Pubkey *CryptoKey
		Number uint32
	}

	conn       net.Conn
	crbuf_     buffer.Buffer // conn read ring buffer
	crbuf      *PeekableRing // crbuf with peek
	cwctrlq    chan []byte   // ctrl packets like pong []byte
	cwctrldlen int32         // data length of cwctrlq
	cwdataq    chan []byte
	cwdatadlen int32  // data length of cwdataq
	conns      *BiMap // connid uint8 <=> pkbinstr

	hs2tmer *time.Timer
	hs2done bool

	RoutingResponseFunc   func(object Object, connection_id uint8, pubkey *CryptoKey)
	RoutingResponseCbdata Object
	RoutingStatusFunc     func(object Object, number uint32, connection_id uint8, status uint8)
	RoutingStatusCbdata   Object
	RoutingDataFunc       func(object Object, number uint32, connection_id uint8, data []byte, cbdata Object)
	RoutingDataCbdata     Object
	OOBDataFunc           func(object Object, pubkey *CryptoKey, data []byte, cbdata Object)
	OOBDataCbdata         Object
	OnionResponseFunc     func(object Object, data []byte, cbdata Object)
	OnionResponseCbdata   Object

	/* Can be used by user. */
	CustomObject Object
	CustomInt    uint32

	OnConfirmed    func()
	OnClosed       func(*TCPClient)
	OnNetRecv      func(n int)
	OnNetSent      func(n int)
	OnReservedData func(object Object, number uint32, connection_id uint8, data []byte, cbdata Object)

	dbgst *TcpClientDebugState
}

// TODO proxy
func NewTCPClientRaw(serv_addr string, serv_pubkey string, self_pubkey, self_seckey string) *TCPClient {
	this := NewTCPClient(serv_addr, NewCryptoKeyFromHex(serv_pubkey),
		NewCryptoKeyFromHex(self_pubkey), NewCryptoKeyFromHex(self_seckey))
	return this
}

func NewTCPClient(serv_addr string, serv_pubkey, self_pubkey, self_seckey *CryptoKey) *TCPClient {
	this := &TCPClient{}
	this.ServAddr = serv_addr
	this.dbgst = NewTcpClientDebugState()

	var err error
	//
	this.ServPubkey = serv_pubkey
	// log.Println(len(serv_pubkey_str), this.serv_pubkey.Len(), this.serv_pubkey.ToHex() == serv_pubkey_str)
	// this.serv_pubkey, this.serv_seckey, err = NewCBKeyPair()
	this.SelfPubkey, this.SelfSeckey, err = NewCBKeyPair()
	this.SetKeyPair(self_pubkey, self_seckey)

	//
	this.Shrkey, err = CBBeforeNm(this.ServPubkey, this.SelfSeckey)
	gopp.ErrPrint(err)

	this.conns = NewBiMap()

	go this.doinit()
	return this
}

func (this *TCPClient) SetKeyPairRaw(pubkey, seckey string) {
	this.SelfPubkey = NewCryptoKeyFromHex(pubkey)
	this.SelfSeckey = NewCryptoKeyFromHex(seckey)
	var err error
	this.Shrkey, err = CBBeforeNm(this.ServPubkey, this.SelfSeckey)
	gopp.ErrPrint(err)
}

func (this *TCPClient) SetKeyPair(pubkey, seckey *CryptoKey) {
	this.SelfPubkey = NewCryptoKeyFromHex(pubkey.ToHex())
	this.SelfSeckey = NewCryptoKeyFromHex(seckey.ToHex())
	var err error
	this.Shrkey, err = CBBeforeNm(this.ServPubkey, this.SelfSeckey)
	gopp.ErrPrint(err)
}

// should block
func (this *TCPClient) doinit() {
	err := this.connect()
	gopp.ErrPrint(err)
	if err == nil {
		err = this.SendHandshake()
		gopp.ErrPrint(err, this.ServAddr)
	} else {
		if this.OnClosed != nil {
			this.OnClosed(this)
		}
	}
}
func (this *TCPClient) connect() error {
	btime := time.Now()
	this.dbgst.ConnBegin()
	this.setStatus(TCP_CLIENT_CONNECTING)
	c, err := net.Dial("tcp", this.ServAddr)
	// c, err := net.DialTimeout("tcp", this.ServAddr, 35*time.Second)
	gopp.ErrPrint(err, this.ServAddr)
	if err != nil {
		return err
	}
	tcpc := c.(*net.TCPConn)
	err = tcpc.SetWriteBuffer(128 * 1024)
	gopp.ErrPrint(err)
	log.Println("Connected to:", c.RemoteAddr(), err, gopp.SinceHum(btime))
	this.dbgst.ConnEnd()

	this.conn = c
	this.crbuf_ = buffer.NewRing(buffer.New(1024 * 1024))
	this.crbuf = NewPeekableRing(this.crbuf_)
	this.cwctrlq = make(chan []byte, 32)
	this.cwdataq = make(chan []byte, 128) // TODO 如果每次1k的话，这个缓存就太小了

	go this.runmainproc()
	return nil
}

func (this *TCPClient) Close() error {
	if this.conn != nil {
		err := this.conn.Close()
		if err != nil {
			err = emperror.With(err, this.ServAddr)
		}
		return err
	}
	return emperror.With(fmt.Errorf("Not connected: %s", this.ServAddr))
}

func (this *TCPClient) runmainproc() {
	wg := sync.WaitGroup{}
	wg.Add(2)

	this.PingDoneC = make(chan struct{}, 0)

	go func() {
		err := this.doWriteConn()
		gopp.ErrPrint(err, this.ServAddr)
		wg.Done()
		err = this.conn.Close()
		gopp.ErrPrint(err)
	}()
	go func() {
		err := this.doReadConn()
		gopp.ErrPrint(err, this.ServAddr)
		wg.Done()
		err = this.conn.Close()
		gopp.ErrPrint(err)
	}()

	wg.Wait()
	this.setStatus(TCP_CLIENT_DISCONNECTED)
	close(this.PingDoneC)
	// close(this.cwctrlq)
	// close(this.cwdataq)

	log.Println("client proc done", this.ServAddr)
	this.dbgst.Dump()
	if this.OnClosed != nil {
		this.OnClosed(this)
	}
	log.Println("client proc done 2", this.ServAddr)
}
func (this *TCPClient) doPing() error {
	log.Println("our ping proc started", this.ServAddr)
	// first ping after confirmed
	pingpkt := this.MakePingPacket2()
	_, err := this.SendCtrlPacket(pingpkt)
	gopp.ErrPrint(err)

	for {
		select {
		case <-this.PingDoneC:
			goto endfor
		case <-time.After(20 * time.Second):
			pingpkt := this.MakePingPacket2()
			_, err := this.SendCtrlPacket(pingpkt)
			gopp.ErrPrint(err)
		}
	}
endfor:
	log.Println("our ping proc stopped", this.ServAddr)
	return nil
}
func (this *TCPClient) doWriteConn() error {
	spdc := NewSpeedCalc()

	var rerr error
	flushCtrl := func() error {
		for len(this.cwctrlq) > 0 {
			data := <-this.cwctrlq
			atomic.AddInt32(&this.cwctrldlen, -int32(len(data)))
			var datai = []interface{}{data}
			wn, err := this.WritePacket(datai[0].([]byte))
			gopp.ErrPrint(err, wn, this.ServAddr)
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
		data, ctrlq, rok := []byte(nil), false, false
		select {
		case data, rok = <-this.cwctrlq:
			atomic.AddInt32(&this.cwctrldlen, -int32(len(data)))
			ctrlq = true
		case data, rok = <-this.cwdataq:
			atomic.AddInt32(&this.cwdatadlen, -int32(len(data)))
		}
		if !rok {
			rerr = fmt.Errorf("send chan closed")
			goto endloop
		}

		if !ctrlq {
			// log.Println("sending ctrl pkt", len(this.cwctrlq), this.ServAddr)
			err := flushCtrl()
			gopp.ErrPrint(err)
			if err != nil {
				rerr = err
				goto endloop
			}
		}
		if ctrlq {
			// log.Println("sending ctrl pkt", len(this.cwctrlq), this.ServAddr)
		}

		var datai = []interface{}{data}
		wn, err := this.WritePacket(datai[0].([]byte))
		gopp.ErrPrint(err, wn, this.ServAddr)
		if err != nil {
			rerr = err
			goto endloop
		}
		spdc.Data(wn)
		if this.OnNetSent != nil {
			this.OnNetSent(wn)
		}
		// gopp.Assert(wn == len(datai[0].([]byte)), "write lost", wn, len(datai[0].([]byte)), this.ServAddr)

		if false && int(time.Since(lastLogTime).Seconds()) >= 1 {
			lastLogTime = time.Now()
			log.Printf("------- async wrote ----- spd: %d, %s, pq:%d, cq:%d------\n",
				spdc.Avgspd, this.ServAddr, len(this.cwctrlq), len(this.cwdataq))
		}
	}
endloop:
	log.Println("write routine done:", this.ServAddr)
	return rerr
}
func (this *TCPClient) doReadConn() error {
	lastLogTime := time.Now().Add(-3 * time.Second)
	spdc := NewSpeedCalc()
	var rerr error
	stop := false
	for !stop {
		c := this.conn
		if false && int(time.Since(lastLogTime).Seconds()) >= 1 {
			lastLogTime = time.Now()
			log.Printf("------- async reading... ----- spd: %d, %s ------\n", spdc.Avgspd, this.ServAddr)
		}
		rdbuf := make([]byte, 3000)
		rn, err := c.Read(rdbuf)
		gopp.ErrPrint(err, rn, this.ServAddr)
		if err == io.EOF {
			this.setStatus(TCP_CLIENT_DISCONNECTED)
		}
		if err != nil {
			rerr = err
			break
		}
		rdbuf = rdbuf[:rn]
		if rn < 1 {
			rerr = fmt.Errorf("Invalid packet, pktlen too short, %v %v", rn, this.ServAddr)
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
		err = this.doReadPacket()
		gopp.ErrPrint(err)
	}
	log.Println("tcp read done.", this.ServAddr, tcpstname(this.getStatus()))
	return rerr
}
func (this *TCPClient) doReadPacket() error {
	stop := false
	for !stop {
		var rdbuf []byte
		switch {
		case this.isConnecting():
			// handshake response packet
			pktlen := NONCE_SIZE + (PUBLIC_KEY_SIZE + NONCE_SIZE + MAC_SIZE)
			rdbuf = make([]byte, pktlen)
			rn, err := this.crbuf.Read(rdbuf)
			gopp.ErrPrint(err, rn)
			gopp.Assert(rn == cap(rdbuf), "not read enough data", rn, cap(rdbuf), this.crbuf.Len())
		case this.isUnconfirmed() || this.isConfirmed():
			// length+payload
			u16sz := int(unsafe.Sizeof(uint16(0)))
			pktlenbuf, err := this.crbuf.Peek(u16sz)
			if err != nil {
				if err == io.EOF {
					// log.Println("no data header 2B", this.crbuf.Len())
					return nil
				} else {
					gopp.ErrPrint(err, this.crbuf.Len())
					return err
				}
			}
			var pktlen uint16
			err = binary.Read(bytes.NewBuffer(pktlenbuf), binary.BigEndian, &pktlen)
			gopp.ErrPrint(err)
			_, err = this.crbuf.Peek(u16sz + int(pktlen))
			if err != nil {
				if err == io.EOF {
					// log.Printf("no enough data, want %d, have %d", pktlen, this.crbuf.Len())
					return nil
				} else {
					gopp.ErrPrint(err, this.crbuf.Len())
					return err
				}
			}
			rdbuf = make([]byte, u16sz+int(pktlen))
			rn, err := this.crbuf.Read(rdbuf)
			gopp.ErrPrint(err)
			gopp.Assert(rn == cap(rdbuf), "not read enough data", rn, cap(rdbuf))

		}

		switch {
		case this.isConnecting():
			this.HandleHandshake(rdbuf)
			// ping
			pingpkt := this.CreatePingPacket()
			wn, err := this.conn.Write(pingpkt)
			gopp.ErrPrint(err, wn)
			this.SentNonce.Incr()
			this.setStatus(TCP_CLIENT_UNCONFIRMED)
			this.hs2tmer = time.NewTimer(5 * time.Second)
			go func() {
				if !this.hs2tmer.Stop() {
					<-this.hs2tmer.C
					if this.hs2done {
					} else {
						log.Println("handshake 2 timeout", this.ServAddr)
					}
				}
			}()
			this.dbgst.Handshake2Begin()
		case this.isUnconfirmed():
			this.hs2tmer.Stop()
			datlen, plnpkt, err := this.Unpacket(rdbuf)
			gopp.ErrPrint(err)
			ptype := plnpkt[0]
			_, _ = datlen, ptype
			// log.Println("read data pkt:", len(rdbuf), datlen, ptype, tcppktname(ptype))
			this.HandlePingResponse(plnpkt)
			this.setStatus(TCP_CLIENT_CONFIRMED)
			if this.OnConfirmed != nil {
				go this.doPing()
				this.OnConfirmed()
			}
			this.dbgst.Handshake2End()
		case this.isConfirmed():
			// TODO read ringbuffer
			datlen, plnpkt, err := this.Unpacket(rdbuf)
			gopp.ErrPrint(err)
			ptype := plnpkt[0]
			omitys := []byte{TCP_PACKET_PING, TCP_PACKET_PONG}
			if ptype < NUM_RESERVED_PORTS && !funk.Contains(omitys, ptype) {
				log.Printf("read data pkt: rdlen:%d, datlen:%d, pktype: %d, pktname: %s, from: %s\n",
					len(rdbuf), datlen, ptype, tcppktname(ptype), this.conn.RemoteAddr().String())
			}
			switch {
			case ptype == TCP_PACKET_PING:
				this.HandlePingRequest(plnpkt)
			case ptype == TCP_PACKET_PONG:
				this.HandlePingResponse2(plnpkt)
			case ptype == TCP_PACKET_ROUTING_RESPONSE:
				this.HandleRoutingResponse(plnpkt)
			case ptype == TCP_PACKET_CONNECTION_NOTIFICATION:
				this.HandleConnectionNotification(plnpkt)
			case ptype == TCP_PACKET_DISCONNECT_NOTIFICATION:
				this.HandleDisconnectNotification(plnpkt)
			case ptype == TCP_PACKET_OOB_RECV: // TODO
			case ptype == TCP_PACKET_ONION_RESPONSE: // TODO
			case ptype >= NUM_RESERVED_PORTS:
				this.HandleRoutingData(plnpkt)
			case ptype > TCP_PACKET_ONION_RESPONSE && ptype < NUM_RESERVED_PORTS:
				this.HandleReservedData(plnpkt)
			default:
				log.Fatalln("wtf", ptype, tcppktname(ptype))
			}
			this.dbgst.RecvPkt(plnpkt)
		default:
			log.Fatalln("wtf", tcpstname(this.status))
		}
	}
	return nil
}

func (this *TCPClient) DoHandshake() {
	hspkt, err := this.GenerateHandshake()
	log.Println("last_packet len:", len(hspkt), err)

	c, err := net.Dial("tcp", this.ServAddr)
	gopp.ErrPrint(err)
	log.Println(c, c.RemoteAddr().String())
	this.conn = c

	wn, err := c.Write(hspkt)
	gopp.ErrPrint(err)
	gopp.NilPrint(err, "sent handshake packet:", wn)

	rdbuf := make([]byte, 300)
	rn, err := c.Read(rdbuf)
	gopp.ErrPrint(err, rn)
	gopp.TruePrint(err == io.EOF,
		"sent handshake packet invalid, serv close conn without anything response.")
	gopp.NilPrint(err, "sent handshake packet valid")
	gopp.TruePrint(rn != TCP_SERVER_HANDSHAKE_SIZE, "recv packet invalid", rn, TCP_SERVER_HANDSHAKE_SIZE)
	gopp.NilPrint(err, "recv handshake packet:", rn, hex.EncodeToString(rdbuf[:rn]))
	rdbuf = rdbuf[:rn]
	this.HandleHandshake(rdbuf)

	// ping
	ping_pkt := this.CreatePingPacket()
	wn, err = c.Write(ping_pkt)
	gopp.ErrPrint(err, wn)

	rdbuf = make([]byte, 300)
	rn, err = c.Read(rdbuf)
	gopp.ErrPrint(err, rn)
	rdbuf = rdbuf[:rn]
	gopp.NilPrint(err, "recv pong packet success", rn)
	this.HandlePingResponse(rdbuf)
	this.conn = c
	this.RecvNonce.Incr()

	//
	log.Println("waiting...")
	// select {}
}

func (this *TCPClient) SendHandshake() (err error) {
	encpkt, err := this.GenerateHandshake()
	wn, err := this.conn.Write(encpkt)
	gopp.ErrPrint(err, wn, len(encpkt))
	return
}
func (this *TCPClient) GenerateHandshake() (encpkt []byte, err error) {
	var temp_pubkey *CryptoKey
	temp_pubkey, this.TempSeckey, err = NewCBKeyPair()
	gopp.ErrPrint(err)
	this.SentNonce = CBRandomNonce()
	this.TempNonce = CBRandomNonce()

	plain := []byte{}
	plain = append(plain, temp_pubkey.Bytes()...)
	plain = append(plain, this.SentNonce.Bytes()...)
	gopp.Assert(len(plain) == PUBLIC_KEY_SIZE+NONCE_SIZE, "size error:", len(plain))

	encrypted, err := EncryptDataSymmetric(this.Shrkey, this.TempNonce, plain)
	gopp.ErrPrint(err)
	gopp.Assert(len(encrypted) == PUBLIC_KEY_SIZE+NONCE_SIZE+MAC_SIZE,
		"Invalid packet length:", len(encrypted), PUBLIC_KEY_SIZE+NONCE_SIZE+MAC_SIZE)

	if false { // self decrypt
		shrkey, err_ := CBBeforeNm(this.ServSeckey, this.SelfPubkey)
		gopp.ErrPrint(err_)
		plain_, err_ := DecryptDataSymmetric(shrkey, this.TempNonce, encrypted)
		gopp.Assert(err_ == nil, "decrypt err:", err_, len(plain_))
	}
	if true { // self decrypt
		plain_, err_ := DecryptDataSymmetric(this.Shrkey, this.TempNonce, encrypted)
		gopp.Assert(err_ == nil, "decrypt err:", err_, len(plain_))
	}

	LastPacket := this.SelfPubkey.Bytes()
	LastPacket = append(LastPacket, this.TempNonce.Bytes()...)
	LastPacket = append(LastPacket, encrypted...)

	wantlen := PUBLIC_KEY_SIZE + NONCE_SIZE + MAC_SIZE + len(plain) // 128
	gopp.Assert(len(LastPacket) == wantlen,
		"Invalid packet length:", len(LastPacket), wantlen)
	return LastPacket, err
}

func (this *TCPClient) HandleHandshake(rdbuf []byte) {
	temp_nonce := NewCBNonce(rdbuf[:NONCE_SIZE])
	encrypted_serv := rdbuf[NONCE_SIZE:]
	plain_resp, err := DecryptDataSymmetric(this.Shrkey, temp_nonce, encrypted_serv)
	gopp.ErrPrint(err, "decrypt recv handshake packet failed")
	gopp.NilPrint(err, "decrypt recv handshake packet success", len(plain_resp))
	temp_pubkey := NewCryptoKey(plain_resp[:PUBLIC_KEY_SIZE])
	this.RecvNonce = NewCBNonce(plain_resp[PUBLIC_KEY_SIZE:])
	log.Println("temp_pubkey", temp_pubkey.ToHex())
	log.Println("this.temp_seckey", this.TempSeckey.ToHex())
	log.Println("this.recv_nonce", this.RecvNonce.ToHex())
	this.Shrkey, err = CBBeforeNm(temp_pubkey, this.TempSeckey)
	gopp.ErrPrint(err)
	this.TempSeckey = nil                          // handshake done, have new shrkey, free
	log.Println("handshake 1 done", this.ServAddr) // handshake 2 is confirm
}

func (this *TCPClient) CreatePingPacket() []byte {
	/// first ping
	pingpkt := this.MakePingPacket2()
	encpkt, err := this.CreatePacket(pingpkt)
	gopp.ErrPrint(err)

	return encpkt
}

func (this *TCPClient) MakePingPacket2() []byte {
	/// first ping
	pingpkt := gopp.NewBufferZero()
	pingpkt.WriteByte(byte(TCP_PACKET_PING))
	pingid := rand.Uint64()
	pingid = gopp.IfElse(pingid == 0, uint64(1), pingid).(uint64)
	// this.PingRequestId = pingid
	atomic.StoreUint64(&this.PingRequestId, pingid)
	binary.Write(pingpkt, binary.BigEndian, pingid)
	// log.Println("ping plnpkt len:", ping_plain.Len())
	return pingpkt.Bytes()
}

func (this *TCPClient) HandlePingResponse(rpkt []byte) {
	pongpkt := gopp.NewBufferBuf(rpkt)
	var pongid uint64
	err := binary.Read(pongpkt.RBufAt(1), binary.BigEndian, &pongid)
	gopp.ErrPrint(err)

	gopp.Assert(pongid == atomic.LoadUint64(&this.PingRequestId), "Invalid pongid")
	// atomic.CompareAndSwapUint64(&this.Pingid, pongid, 0)
	log.Println("handshake 2 done. confirmed.", this.ServAddr)
	// this.PingRequestId = 0
	atomic.StoreUint64(&this.PingRequestId, 0)
}

func (this *TCPClient) HandlePingResponse2(rpkt []byte) error {
	pong_pkt := gopp.NewBufferBuf(rpkt)
	// log.Println("pong type:", gopp.Retn(pong_pkt.ReadByte()))
	var pongid uint64
	err := binary.Read(pong_pkt.RBufAt(1), binary.BigEndian, &pongid)
	gopp.ErrPrint(err)

	if pongid != atomic.LoadUint64(&this.PingRequestId) {
		err := fmt.Errorf("Invalid pongid %d %d", pongid, atomic.LoadUint64(&this.PingRequestId))
		log.Println(err)
		return err
	}
	// this.PingRequestId = 0
	atomic.StoreUint64(&this.PingRequestId, 0)
	return nil
}

func (this *TCPClient) HandlePingRequest(rpkt []byte) {
	plnpkt := gopp.NewBufferZero()
	plnpkt.WriteByte(byte(TCP_PACKET_PONG))
	plnpkt.Write(rpkt[1:]) // pingid

	_, err := this.SendCtrlPacket(plnpkt.Bytes())
	gopp.ErrPrint(err)
	// log.Println("response pong:", err)
	// encpkt, err := this.CreatePacket(plnpkt.Bytes())
	// gopp.ErrPrint(err)
	// wn, err := this.conn.Write(encpkt)
	// gopp.ErrPrint(err, wn)
}

func (this *TCPClient) ConnectPeer(pubkey string) error {
	c := this.conn
	if c == nil {
		return fmt.Errorf("Not connected %s", this.ServAddr)
	}
	if !this.isConfirmed() {
		return fmt.Errorf("Connection not confirmed %s", this.ServAddr)
	}

	// routing request
	encpkt, err := this.SendRoutingRequest(NewCryptoKeyFromHex(pubkey))
	gopp.ErrPrint(err, len(encpkt))
	return err
}

func (this *TCPClient) SendRoutingRequest(pubkey *CryptoKey) (encpkt []byte, err error) {
	buf := gopp.NewBufferZero()
	buf.WriteByte(byte(TCP_PACKET_ROUTING_REQUEST))
	buf.Write(pubkey.Bytes())

	_, err = this.SendCtrlPacket(buf.Bytes())
	// encpkt, err = this.CreatePacket(buf.Bytes())
	return
}

func (this *TCPClient) HandleRoutingResponse(rpkt []byte) {
	rspdat := rpkt
	gopp.Assert(rspdat[0] == TCP_PACKET_ROUTING_RESPONSE, "Invalid packet", rspdat[0])
	connid := rspdat[1]
	pubkey := NewCryptoKey(rspdat[2 : 2+PUBLIC_KEY_SIZE])
	log.Println(rspdat[0], connid, pubkey.ToHex()[:20], "<=", this.SelfPubkey.ToHex()[:20])

	this.conns.Insert(connid, pubkey.BinStr())
	if this.RoutingResponseFunc != nil {
		this.RoutingResponseFunc(this.RoutingResponseCbdata, connid, pubkey)
	}
}

func (this *TCPClient) HandleRoutingData(rpkt []byte) {
	connid := rpkt[0]
	if this.RoutingDataFunc != nil {
		this.RoutingDataFunc(this.RoutingDataCbdata, 0, connid, rpkt[1:], nil)
	}
}

func (this *TCPClient) HandleReservedData(rpkt []byte) {
	connid := rpkt[0]
	if this.OnReservedData != nil {
		this.OnReservedData(this.RoutingDataCbdata, 0, connid, rpkt[1:], nil)
	}
}

func (this *TCPClient) SendCtrlPacket(data []byte) (encpkt []byte, err error) {
	if len(data) > 2048 {
		return nil, emperror.With(fmt.Errorf("Data too long: %d, want: %d", len(data), 2048))
	}
	if len(this.cwctrlq) >= cap(this.cwctrlq) {
		log.Println("Ctrl queue is full, drop pkt...", len(data), this.cwctrldlen)
		return nil, emperror.With(fmt.Errorf("Ctrl queue is full"))
	}
	if !this.isConfirmed() {
		return nil, emperror.With(fmt.Errorf("Cannot send data status is %v", tcpstname(this.getStatus())))
	}
	btime := time.Now()
	select {
	case this.cwctrlq <- data:
		atomic.AddInt32(&this.cwctrldlen, int32(len(data)))
	case <-time.After(5 * time.Second):
		// default:
		log.Println("Ctrl queue is full, drop pkt...", len(data), this.cwctrldlen)
		return nil, emperror.With(fmt.Errorf("Ctrl queue is full"))
	}
	// encpkt, err = this.CreatePacket(buf.Bytes())
	// this.WritePacket(encpkt)
	dtime := time.Since(btime)
	if dtime > 5*time.Millisecond {
		log.Println("send use too long", len(data), dtime)
	} else if dtime > 2*time.Millisecond {
		log.Println("send use too long", len(data), dtime)
	}
	return
}

// TODO split data
func (this *TCPClient) SendDataPacket(connid uint8, data []byte, prior bool) (encpkt []byte, err error) {
	if len(data) > 2048 {
		return nil, emperror.With(fmt.Errorf("Data too long: %d, want: %d", len(data), 2048))
	}
	// if len(this.cwdataq) >= cap(this.cwdataq) {
	if atomic.LoadInt32(&this.cwdatadlen) > 1024*1024 {
		// log.Println("Data queue is full, blocking pkt.", len(this.cwdataq), connid, len(data), this.cwdatadlen)
		// return nil, emperror.With(fmt.Errorf("Data queue is full"))
	}
	if !this.isConfirmed() {
		return nil, emperror.With(fmt.Errorf("Cannot send data status is %v", tcpstname(this.getStatus())))
	}

	buf := gopp.NewBufferZero()
	buf.WriteByte(byte(connid))
	buf.Write(data)
	if prior {
		this.SendCtrlPacket(buf.Bytes())
	}

	btime := time.Now()
	select {
	case this.cwdataq <- buf.Bytes():
		atomic.AddInt32(&this.cwdatadlen, int32(buf.Len()))
	case <-time.After(5 * time.Second):
		// default:
		// log.Println("Data queue is full, drop pkt.", len(this.cwdataq), connid, len(data), this.cwdatadlen)
		log.Println("Write queue timeout, drop pkt.", len(this.cwdataq), connid, len(data), this.cwdatadlen)
		return nil, emperror.With(fmt.Errorf("Data queue is full"))
	}
	dtime := time.Since(btime)
	if dtime > 2*time.Millisecond {
		log.Println("send use too long time", len(data), dtime)
	}
	return
}

func (this *TCPClient) SendOOBPacket(pubkey *CryptoKey, data []byte) (encpkt []byte, err error) {
	buf := gopp.NewBufferZero()
	buf.WriteByte(byte(TCP_PACKET_OOB_SEND))
	buf.Write(pubkey.Bytes())
	buf.Write(data)

	_, err = this.SendCtrlPacket(buf.Bytes())
	return
}

func (this *TCPClient) SendConnectNotification(connid uint8) (encpkt []byte, err error) {
	plnpkt := []byte{byte(TCP_PACKET_CONNECTION_NOTIFICATION), connid}
	_, err = this.SendCtrlPacket(plnpkt)
	return
}

func (this *TCPClient) SendDisconnectNotification(connid uint8) (encpkt []byte, err error) {
	plnpkt := []byte{byte(TCP_PACKET_DISCONNECT_NOTIFICATION), connid}
	_, err = this.SendCtrlPacket(plnpkt)
	return
}

func (this *TCPClient) SendOnionRequest(data []byte) (encpkt []byte, err error) {
	plnbuf := gopp.NewBufferZero()
	plnbuf.WriteByte(byte(TCP_PACKET_ONION_REQUEST))
	plnbuf.Write(data)
	_, err = this.SendCtrlPacket(plnbuf.Bytes())
	return
}

func (this *TCPClient) HandleConnectionNotification(rpkt []byte) {
	connid := rpkt[1]
	if this.RoutingStatusFunc != nil {
		this.RoutingStatusFunc(this.RoutingStatusCbdata, 0, connid, 2)
	}
}
func (this *TCPClient) HandleDisconnectNotification(rpkt []byte) {
	connid := rpkt[1]
	if this.RoutingStatusFunc != nil {
		this.RoutingStatusFunc(this.RoutingStatusCbdata, 0, connid, 1)
	}
}

func (this *TCPClient) WritePacket(data []byte) (int, error) {
	encpkt, err := this.CreatePacket(data)
	gopp.ErrPrint(err)
	wn, err := this.conn.Write(encpkt)
	gopp.ErrPrint(err)
	if err == nil {
		this.SentNonce.Incr()
	}
	return wn, err
}

// tcp data packet, not include handshake packet
func (this *TCPClient) CreatePacket(plain []byte) (encpkt []byte, err error) {
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

func (this *TCPClient) Unpacket(encpkt []byte) (datlen uint16, plnpkt []byte, err error) {
	err = binary.Read(bytes.NewReader(encpkt), binary.BigEndian, &datlen)
	gopp.ErrPrint(err)
	plnpkt, err = DecryptDataSymmetric(this.Shrkey, this.RecvNonce, encpkt[2:])
	this.RecvNonce.Incr()
	return
}

///
func (this *TCPClient) setStatus(status int) {
	this.stmu.Lock()
	defer this.stmu.Unlock()
	this.status = uint8(status)
}
func (this *TCPClient) getStatus() uint8 {
	this.stmu.RLock()
	defer this.stmu.RUnlock()
	return this.status
}
func (this *TCPClient) isConnecting() bool {
	this.stmu.RLock()
	defer this.stmu.RUnlock()
	return this.status == TCP_CLIENT_CONNECTING
}
func (this *TCPClient) isConfirmed() bool {
	this.stmu.RLock()
	defer this.stmu.RUnlock()
	return this.status == TCP_CLIENT_CONFIRMED
}
func (this *TCPClient) isUnconfirmed() bool {
	this.stmu.RLock()
	defer this.stmu.RUnlock()
	return this.status == TCP_CLIENT_UNCONFIRMED
}
func (this *TCPClient) isDisconnected() bool {
	this.stmu.RLock()
	defer this.stmu.RUnlock()
	return this.status == TCP_CLIENT_DISCONNECTED
}
