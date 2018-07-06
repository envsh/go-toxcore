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
)

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
	ServAddr string
	ServConn net.Conn

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

	Pingid     uint64
	LastPacket []byte

	conn  net.Conn
	conns *BiMap // connid uint8 <=> pkbinstr
}

func NewTCPClient(serv_addr string, serv_pubkey string) *TCPClient {
	this := &TCPClient{}

	var err error
	//
	serv_pubkey_str := serv_pubkey
	this.ServAddr = serv_addr
	this.ServPubkey = NewCryptoKeyFromHex(serv_pubkey_str)
	// log.Println(len(serv_pubkey_str), this.serv_pubkey.Len(), this.serv_pubkey.ToHex() == serv_pubkey_str)
	// this.serv_pubkey, this.serv_seckey, err = NewCBKeyPair()
	this.SelfPubkey, this.SelfSeckey, err = NewCBKeyPair()

	//
	this.Shrkey, err = CBBeforeNm(this.ServPubkey, this.SelfSeckey)
	gopp.ErrPrint(err)

	this.conns = NewBiMap()

	return this
}

func (this *TCPClient) SetKeyPair(pubkey, seckey string) {
	this.SelfPubkey = NewCryptoKeyFromHex(pubkey)
	this.SelfSeckey = NewCryptoKeyFromHex(seckey)
	var err error
	this.Shrkey, err = CBBeforeNm(this.ServPubkey, this.SelfSeckey)
	gopp.ErrPrint(err)
}

func (this *TCPClient) DoHandshake() {
	this.GenerateHandshake()
	log.Println("last_packet len:", len(this.LastPacket))

	c, err := net.Dial("tcp", this.ServAddr)
	gopp.ErrPrint(err)
	log.Println(c, c.RemoteAddr().String())
	this.ServConn = c

	wn, err := c.Write(this.LastPacket)
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
	this.SentNonce.Incr()

	rdbuf = make([]byte, 300)
	rn, err = c.Read(rdbuf)
	gopp.ErrPrint(err, rn)
	rdbuf = rdbuf[:rn]
	gopp.NilPrint(err, "recv pong packet success", rn)
	this.HandlePingResponse(rdbuf)
	this.conn = c

	//
	log.Println("waiting...")
	// select {}
}
func (this *TCPClient) StartRead() {
	go func() {
		for {
			c := this.conn
			log.Println("async reading...")
			rdbuf := make([]byte, 300)
			rn, err := c.Read(rdbuf)
			gopp.ErrPrint(err, rn)
			rdbuf = rdbuf[:rn]
			datlen, plnpkt, err := this.Unpacket(rdbuf)
			log.Println("read data pkt:", len(rdbuf), datlen, plnpkt[0], tcppktname(plnpkt[0]))
		}
	}()
}
func (this *TCPClient) GenerateHandshake() {
	var err error
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

	this.LastPacket = append(this.LastPacket, this.SelfPubkey.Bytes()...)
	this.LastPacket = append(this.LastPacket, this.TempNonce.Bytes()...)
	this.LastPacket = append(this.LastPacket, encrypted...)

	wantlen := PUBLIC_KEY_SIZE + NONCE_SIZE + MAC_SIZE + len(plain) // 128
	gopp.Assert(len(this.LastPacket) == wantlen,
		"Invalid packet length:", len(this.LastPacket), wantlen)
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
	log.Println(ping_plain.Len())

	ping_encrypted, err := EncryptDataSymmetric(this.Shrkey, this.SentNonce, ping_plain.Bytes())
	gopp.ErrPrint(err)

	ping_pkt := gopp.NewBufferZero()
	binary.Write(ping_pkt, binary.BigEndian, uint16(len(ping_encrypted)))
	ping_pkt.Write(ping_encrypted)
	log.Println(ping_pkt.Len(), len(ping_encrypted))

	return ping_pkt.Bytes()
}

func (this *TCPClient) HandlePingResponse(rpkt []byte) {
	pong_plain, err := DecryptDataSymmetric(this.Shrkey, this.RecvNonce, rpkt[2:])
	gopp.ErrPrint(err)
	gopp.NilPrint(err, "decrypt pong packet success", len(pong_plain))

	pong_pkt := gopp.NewBufferBuf(pong_plain)
	log.Println("pong type:", gopp.Retn(pong_pkt.ReadByte()))
	var pongid uint64
	err = binary.Read(pong_pkt.BufAt(1), binary.BigEndian, &pongid)
	gopp.ErrPrint(err)

	pingid := this.Pingid
	log.Println(pongid == pingid, pongid, pingid)
	atomic.CompareAndSwapUint64(&this.Pingid, pongid, 0)
	log.Println("handshake 2 done. confirmed.")
	this.RecvNonce.Incr()
}

func (this *TCPClient) ConnectPeer(pubkey string) {
	c := this.conn

	// routing request
	// encpkt, err := this.SendRoutingRequest(NewCryptoKeyFromHex(echo_serv_pubkey_str))
	encpkt, err := this.SendRoutingRequest(NewCryptoKeyFromHex(pubkey))
	gopp.ErrPrint(err)
	wn, err := c.Write(encpkt)
	gopp.ErrPrint(err, wn)
	this.SentNonce.Incr()
	rdbuf := make([]byte, 300)
	rn, err := c.Read(rdbuf)
	gopp.ErrPrint(err, rn)
	rdbuf = rdbuf[:rn]
	gopp.NilPrint(err, "recv routing response packet success", rn)
	this.HandleRoutingResponse(rdbuf)
}

func (this *TCPClient) SendRoutingRequest(pubkey *CryptoKey) (encpkt []byte, err error) {
	buf := gopp.NewBufferZero()
	buf.WriteByte(byte(TCP_PACKET_ROUTING_REQUEST))
	buf.Write(pubkey.Bytes())

	encpkt, err = this.CreatePacket(buf.Bytes())
	return
}

func (this *TCPClient) HandleRoutingResponse(rpkt []byte) {
	var datlen uint16
	err := binary.Read(bytes.NewBuffer(rpkt), binary.BigEndian, &datlen)
	gopp.ErrPrint(err)
	rspdat, err := DecryptDataSymmetric(this.Shrkey, this.RecvNonce, rpkt[2:])
	gopp.ErrPrint(err)
	gopp.Assert(rspdat[0] == TCP_PACKET_ROUTING_RESPONSE, "Invalid packet", rspdat[0])
	connid := rspdat[1]
	pubkey := NewCryptoKey(rspdat[2 : 2+PUBLIC_KEY_SIZE])
	log.Println(rspdat[0], connid, pubkey.ToHex()[:20], "<=", this.SelfPubkey.ToHex()[:20])
	this.RecvNonce.Incr()

	this.conns.Insert(connid, pubkey.BinStr())
}

func (this *TCPClient) SendDataPacket(pubkey *CryptoKey, data []byte) (encpkt []byte, err error) {
	var connid uint8
	buf := gopp.NewBufferZero()
	buf.WriteByte(byte(connid))
	buf.Write(data)

	encpkt, err = this.CreatePacket(buf.Bytes())
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

// tcp packet
func (this *TCPClient) CreatePacket(plain []byte) (encpkt []byte, err error) {
	log.Println(len(plain), this.Shrkey.ToHex()[:20], this.SentNonce.ToHex())
	encdat, err := EncryptDataSymmetric(this.Shrkey, this.SentNonce, plain)
	gopp.ErrPrint(err)

	pktbuf := gopp.NewBufferZero()
	binary.Write(pktbuf, binary.BigEndian, uint16(len(encdat)))
	pktbuf.Write(encdat)
	encpkt = pktbuf.Bytes()
	log.Println(len(encpkt), len(plain))
	return
}

func (this *TCPClient) Unpacket(encpkt []byte) (datlen uint16, plnpkt []byte, err error) {
	err = binary.Read(bytes.NewReader(encpkt), binary.BigEndian, &datlen)
	gopp.ErrPrint(err)
	plnpkt, err = DecryptDataSymmetric(this.Shrkey, this.RecvNonce, encpkt[2:])
	return
}
