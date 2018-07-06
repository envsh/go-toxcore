package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"gopp"
	"io"
	"log"
	"math/rand"
	"net"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
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

type TCPClient struct {
	Status   uint8
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
	Pingid    uint64

	PingResponseId uint64
	PingRequestId  uint64

	// peer connections via this relay tcp tunnel
	Conns [NUM_CLIENT_CONNECTIONS]struct {
		Status uint8
		Pubkey *CryptoKey
		Number uint32
	}

	conn  net.Conn
	conns *BiMap // connid uint8 <=> pkbinstr

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

	OnConfirmed func()
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

	go this.connect().SendHandshake()
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

func (this *TCPClient) connect() *TCPClient {
	this.Status = TCP_CLIENT_CONNECTING
	c, err := net.Dial("tcp", this.ServAddr)
	gopp.ErrPrint(err, this.ServAddr)
	log.Println("Connected to:", c.RemoteAddr())
	this.conn = c

	this.start()
	return this
}

func (this *TCPClient) Close() error {
	if this.conn != nil {
		err := errors.Wrap(this.conn.Close(), this.ServAddr)
		return err
	}
	return errors.Errorf("Not connected: %s", this.ServAddr)
}

func (this *TCPClient) start() { go this.doRead() }
func (this *TCPClient) doRead() {
	stop := false
	for !stop {
		c := this.conn
		log.Println("async reading...")
		rdbuf := make([]byte, 300)
		rn, err := c.Read(rdbuf)
		gopp.ErrPrint(err, rn)
		if err == io.EOF {
			this.Status = TCP_CLIENT_DISCONNECTED
		}
		if err != nil {
			break
		}
		rdbuf = rdbuf[:rn]

		if rn < 1 {
			log.Println("Invalid packet:", rn, this.ServAddr)
			break
		}
		switch {
		case this.Status == TCP_CLIENT_CONNECTING:
			this.HandleHandshake(rdbuf)
			// ping
			ping_pkt := this.MakePingPacket()
			wn, err := c.Write(ping_pkt)
			gopp.ErrPrint(err, wn)
			this.Status = TCP_CLIENT_UNCONFIRMED
		case this.Status == TCP_CLIENT_UNCONFIRMED:
			datlen, plnpkt, err := this.Unpacket(rdbuf)
			gopp.ErrPrint(err)
			ptype := plnpkt[0]
			log.Println("read data pkt:", len(rdbuf), datlen, ptype, tcppktname(ptype))
			this.HandlePingResponse(plnpkt)
			this.Status = TCP_CLIENT_CONFIRMED
			if this.OnConfirmed != nil {
				this.OnConfirmed()
			}
		case this.Status == TCP_CLIENT_CONFIRMED:
			// TODO read ringbuffer
			datlen, plnpkt, err := this.Unpacket(rdbuf)
			gopp.ErrPrint(err)
			ptype := plnpkt[0]
			log.Printf("read data pkt: rdlen:%d, datlen:%d, pktype: %d, pktname: %s\n",
				len(rdbuf), datlen, ptype, tcppktname(ptype))

			switch {
			case ptype == TCP_PACKET_PING:
				this.HandlePingRequest(plnpkt)
			case ptype == TCP_PACKET_PONG:
				this.HandlePingResponse(plnpkt)
			case ptype == TCP_PACKET_ROUTING_RESPONSE:
				this.HandleRoutingResponse(plnpkt)
			case ptype == TCP_PACKET_CONNECTION_NOTIFICATION:
				this.HandleConnectionNotification(plnpkt)
			case ptype == TCP_PACKET_DISCONNECT_NOTIFICATION:
				this.HandleDisconnectNotification(plnpkt)
			case ptype == TCP_PACKET_OOB_RECV:
			case ptype == TCP_PACKET_ONION_RESPONSE:
			case ptype >= NUM_RESERVED_PORTS:
			default:
				log.Fatalln("wtf", ptype, tcppktname(ptype))
			}
		default:
			log.Fatalln("wtf", tcpstname(this.Status))
		}
	}
	log.Println("tcp client done.", this.ServAddr, tcpstname(this.Status))
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
	ping_pkt := this.MakePingPacket()
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
	this.TempSeckey = nil           // handshake done, have new shrkey, free
	log.Println("handshake 1 done") // handshake 2 is confirm
}

func (this *TCPClient) MakePingPacket() []byte {
	/// first ping
	ping_plain := gopp.NewBufferZero()
	ping_plain.WriteByte(byte(TCP_PACKET_PING))
	pingid := rand.Uint64()
	pingid = gopp.IfElse(pingid == 0, uint64(1), pingid).(uint64)
	this.Pingid = pingid
	binary.Write(ping_plain, binary.BigEndian, pingid)
	log.Println("ping plnpkt len:", ping_plain.Len())

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

func (this *TCPClient) HandlePingResponse(rpkt []byte) {
	pong_pkt := gopp.NewBufferBuf(rpkt)
	log.Println("pong type:", gopp.Retn(pong_pkt.ReadByte()))
	var pongid uint64
	err := binary.Read(pong_pkt.BufAt(1), binary.BigEndian, &pongid)
	gopp.ErrPrint(err)

	pingid := this.Pingid
	log.Println(pongid == pingid, pongid, pingid)
	atomic.CompareAndSwapUint64(&this.Pingid, pongid, 0)
	log.Println("handshake 2 done. confirmed.")
}

func (this *TCPClient) HandlePingRequest(rpkt []byte) {
	plnpkt := gopp.NewBufferZero()
	plnpkt.WriteByte(byte(TCP_PACKET_PONG))
	plnpkt.Write(rpkt[1:]) // pingid

	encpkt, err := this.CreatePacket(plnpkt.Bytes())
	gopp.ErrPrint(err)
	wn, err := this.conn.Write(encpkt)
	gopp.ErrPrint(err, wn)
}

func (this *TCPClient) ConnectPeer(pubkey string) {
	c := this.conn
	if c == nil {
		return
	}

	// routing request
	// encpkt, err := this.SendRoutingRequest(NewCryptoKeyFromHex(echo_serv_pubkey_str))
	encpkt, err := this.SendRoutingRequest(NewCryptoKeyFromHex(pubkey))
	gopp.ErrPrint(err)
	wn, err := c.Write(encpkt)
	gopp.ErrPrint(err, wn)

	/*
		rdbuf := make([]byte, 300)
		rn, err := c.Read(rdbuf)
		gopp.ErrPrint(err, rn)
		rdbuf = rdbuf[:rn]
		gopp.NilPrint(err, "recv routing response packet success", rn)
		this.HandleRoutingResponse(rdbuf)
	*/
}

func (this *TCPClient) SendRoutingRequest(pubkey *CryptoKey) (encpkt []byte, err error) {
	buf := gopp.NewBufferZero()
	buf.WriteByte(byte(TCP_PACKET_ROUTING_REQUEST))
	buf.Write(pubkey.Bytes())

	encpkt, err = this.CreatePacket(buf.Bytes())
	return
}

func (this *TCPClient) HandleRoutingResponse(rpkt []byte) {
	rspdat := rpkt
	gopp.Assert(rspdat[0] == TCP_PACKET_ROUTING_RESPONSE, "Invalid packet", rspdat[0])
	connid := rspdat[1]
	pubkey := NewCryptoKey(rspdat[2 : 2+PUBLIC_KEY_SIZE])
	log.Println(rspdat[0], connid, pubkey.ToHex()[:20], "<=", this.SelfPubkey.ToHex()[:20])

	this.conns.Insert(connid, pubkey.BinStr())

}

func (this *TCPClient) SendDataPacket(connid uint8, data []byte) (encpkt []byte, err error) {
	buf := gopp.NewBufferZero()
	buf.WriteByte(byte(connid))
	buf.Write(data)

	encpkt, err = this.CreatePacket(buf.Bytes())
	this.WritePacket(encpkt)
	return
}

func (this *TCPClient) SendOOBPacket(pubkey *CryptoKey, data []byte) (encpkt []byte, err error) {
	buf := gopp.NewBufferZero()
	buf.WriteByte(byte(TCP_PACKET_OOB_SEND))
	buf.Write(pubkey.Bytes())
	buf.Write(data)

	encpkt, err = this.CreatePacket(buf.Bytes())
	return
}

func (this *TCPClient) SendConnectNotification(connid uint8) (encpkt []byte, err error) {
	plnpkt := []byte{byte(TCP_PACKET_CONNECTION_NOTIFICATION), connid}
	encpkt, err = this.CreatePacket(plnpkt)
	return
}

func (this *TCPClient) SendDisconnectNotification(connid uint8) (encpkt []byte, err error) {
	plnpkt := []byte{byte(TCP_PACKET_DISCONNECT_NOTIFICATION), connid}
	encpkt, err = this.CreatePacket(plnpkt)
	return
}

func (this *TCPClient) SendOnionRequest(data []byte) (encpkt []byte, err error) {
	plnbuf := gopp.NewBufferZero()
	plnbuf.WriteByte(byte(TCP_PACKET_ONION_REQUEST))
	plnbuf.Write(data)
	encpkt, err = this.CreatePacket(plnbuf.Bytes())
	return
}

func (this *TCPClient) HandleConnectionNotification(rpkt []byte) {
	connid := rpkt[1]
	if this.RoutingStatusFunc != nil {
		this.RoutingStatusFunc(nil, 0, connid, 2)
	}
}
func (this *TCPClient) HandleDisconnectNotification(rpkt []byte) {
	connid := rpkt[1]
	if this.RoutingStatusFunc != nil {
		this.RoutingStatusFunc(nil, 0, connid, 1)
	}
}

func (this *TCPClient) WritePacket(data []byte) (int, error) {
	wn, err := this.conn.Write(data)
	gopp.ErrPrint(err)
	return wn, err
}

// tcp data packet, not include handshake packet
func (this *TCPClient) CreatePacket(plain []byte) (encpkt []byte, err error) {
	log.Println(len(plain), this.Shrkey.ToHex()[:20], this.SentNonce.ToHex())
	encdat, err := EncryptDataSymmetric(this.Shrkey, this.SentNonce, plain)
	gopp.ErrPrint(err)

	pktbuf := gopp.NewBufferZero()
	binary.Write(pktbuf, binary.BigEndian, uint16(len(encdat)))
	pktbuf.Write(encdat)
	encpkt = pktbuf.Bytes()
	log.Println("create pkg:", tcppktname(plain[0]), len(encpkt), len(plain))
	this.SentNonce.Incr()
	return
}

func (this *TCPClient) Unpacket(encpkt []byte) (datlen uint16, plnpkt []byte, err error) {
	err = binary.Read(bytes.NewReader(encpkt), binary.BigEndian, &datlen)
	gopp.ErrPrint(err)
	plnpkt, err = DecryptDataSymmetric(this.Shrkey, this.RecvNonce, encpkt[2:])
	this.RecvNonce.Incr()
	return
}
