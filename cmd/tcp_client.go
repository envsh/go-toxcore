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

	"github.com/GoKillers/libsodium-go/cryptobox"
	"github.com/pkg/errors"
)

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
	serv_addr string
	serv_conn net.Conn

	self_pubkey *CryptoKey
	self_seckey *CryptoKey
	serv_pubkey *CryptoKey
	serv_seckey *CryptoKey // for test
	shrkey      *CryptoKey // combined key
	// temp_pubkey *CryptoKey
	temp_seckey *CryptoKey
	sent_nonce  *CBNonce
	recv_nonce  *CBNonce
	temp_nonce  *CBNonce

	ping_id     uint64
	last_packet []byte

	conn  net.Conn
	conns *BiMap // connid uint8 <=> pkbinstr
}

func NewTCPClient(serv_addr string, serv_pubkey string) *TCPClient {
	this := &TCPClient{}

	var err error
	//
	serv_pubkey_str := serv_pubkey
	this.serv_addr = serv_addr
	this.serv_pubkey = NewCryptoKeyFromHex(serv_pubkey_str)
	// log.Println(len(serv_pubkey_str), this.serv_pubkey.Len(), this.serv_pubkey.ToHex() == serv_pubkey_str)
	// this.serv_pubkey, this.serv_seckey, err = NewCBKeyPair()
	this.self_pubkey, this.self_seckey, err = NewCBKeyPair()

	//
	this.shrkey, err = CBBeforeNm(this.serv_pubkey, this.self_seckey)
	gopp.ErrPrint(err)

	this.conns = NewBiMap()

	return this
}

func (this *TCPClient) SetKeyPair(pubkey, seckey string) {
	this.self_pubkey = NewCryptoKeyFromHex(pubkey)
	this.self_seckey = NewCryptoKeyFromHex(seckey)
	var err error
	this.shrkey, err = CBBeforeNm(this.serv_pubkey, this.self_seckey)
	gopp.ErrPrint(err)
}

func (this *TCPClient) DoHandshake() {
	this.GenerateHandshake()
	log.Println("last_packet len:", len(this.last_packet))

	c, err := net.Dial("tcp", this.serv_addr)
	gopp.ErrPrint(err)
	log.Println(c, c.RemoteAddr().String())
	this.serv_conn = c

	wn, err := c.Write(this.last_packet)
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
	this.sent_nonce.Incr()

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
	temp_pubkey, this.temp_seckey, err = NewCBKeyPair()
	gopp.ErrPrint(err)
	this.sent_nonce = CBRandomNonce()
	this.temp_nonce = CBRandomNonce()

	plain := []byte{}
	plain = append(plain, temp_pubkey.Bytes()...)
	plain = append(plain, this.sent_nonce.Bytes()...)
	gopp.Assert(len(plain) == PUBLIC_KEY_SIZE+NONCE_SIZE, "size error:", len(plain))

	encrypted, err := EncryptDataSymmetric(this.shrkey, this.temp_nonce, plain)
	gopp.ErrPrint(err)
	gopp.Assert(len(encrypted) == PUBLIC_KEY_SIZE+NONCE_SIZE+MAC_SIZE,
		"Invalid packet length:", len(encrypted), PUBLIC_KEY_SIZE+NONCE_SIZE+MAC_SIZE)

	if false { // self decrypt
		shrkey, err_ := CBBeforeNm(this.serv_seckey, this.self_pubkey)
		gopp.ErrPrint(err_)
		plain_, err_ := DecryptDataSymmetric(shrkey, this.temp_nonce, encrypted)
		gopp.Assert(err_ == nil, "decrypt err:", err_, len(plain_))
	}
	if true { // self decrypt
		plain_, err_ := DecryptDataSymmetric(this.shrkey, this.temp_nonce, encrypted)
		gopp.Assert(err_ == nil, "decrypt err:", err_, len(plain_))
	}

	this.last_packet = append(this.last_packet, this.self_pubkey.Bytes()...)
	this.last_packet = append(this.last_packet, this.temp_nonce.Bytes()...)
	this.last_packet = append(this.last_packet, encrypted...)

	wantlen := PUBLIC_KEY_SIZE + NONCE_SIZE + MAC_SIZE + len(plain) // 128
	gopp.Assert(len(this.last_packet) == wantlen,
		"Invalid packet length:", len(this.last_packet), wantlen)
}

func (this *TCPClient) HandleHandshake(rdbuf []byte) {
	temp_nonce := NewCBNonce(rdbuf[:NONCE_SIZE])
	encrypted_serv := rdbuf[NONCE_SIZE:]
	plain_resp, err := DecryptDataSymmetric(this.shrkey, temp_nonce, encrypted_serv)
	gopp.ErrPrint(err, "decrypt recv handshake packet failed")
	gopp.NilPrint(err, "decrypt recv handshake packet success", len(plain_resp))
	temp_pubkey := NewCryptoKey(plain_resp[:PUBLIC_KEY_SIZE])
	this.recv_nonce = NewCBNonce(plain_resp[PUBLIC_KEY_SIZE:])
	log.Println("temp_pubkey", temp_pubkey.ToHex())
	log.Println("this.temp_seckey", this.temp_seckey.ToHex())
	log.Println("this.recv_nonce", this.recv_nonce.ToHex())
	this.shrkey, err = CBBeforeNm(temp_pubkey, this.temp_seckey)
	gopp.ErrPrint(err)
	this.temp_seckey = nil          // handshake done, have new shrkey, free
	log.Println("handshake 1 done") // handshake 2 is confirm
}

func (this *TCPClient) MakePingPacket() []byte {
	/// first ping
	ping_plain := gopp.NewBufferZero()
	ping_plain.WriteByte(byte(TCP_PACKET_PING))
	ping_id := rand.Uint64()
	ping_id = gopp.IfElse(ping_id == 0, uint64(1), ping_id).(uint64)
	this.ping_id = ping_id
	binary.Write(ping_plain, binary.BigEndian, ping_id)
	log.Println(ping_plain.Len())

	ping_encrypted, err := EncryptDataSymmetric(this.shrkey, this.sent_nonce, ping_plain.Bytes())
	gopp.ErrPrint(err)

	ping_pkt := gopp.NewBufferZero()
	binary.Write(ping_pkt, binary.BigEndian, uint16(len(ping_encrypted)))
	ping_pkt.Write(ping_encrypted)
	log.Println(ping_pkt.Len(), len(ping_encrypted))

	return ping_pkt.Bytes()
}

func (this *TCPClient) HandlePingResponse(rpkt []byte) {
	pong_plain, err := DecryptDataSymmetric(this.shrkey, this.recv_nonce, rpkt[2:])
	gopp.ErrPrint(err)
	gopp.NilPrint(err, "decrypt pong packet success", len(pong_plain))

	pong_pkt := gopp.NewBufferBuf(pong_plain)
	log.Println("pong type:", gopp.Retn(pong_pkt.ReadByte()))
	var pong_id uint64
	err = binary.Read(pong_pkt.BufAt(1), binary.BigEndian, &pong_id)
	gopp.ErrPrint(err)

	ping_id := this.ping_id
	log.Println(pong_id == ping_id, pong_id, ping_id)
	atomic.CompareAndSwapUint64(&this.ping_id, pong_id, 0)
	log.Println("handshake 2 done. confirmed.")
	this.recv_nonce.Incr()
}

func (this *TCPClient) ConnectPeer(pubkey string) {
	c := this.conn

	// routing request
	// encpkt, err := this.SendRoutingRequest(NewCryptoKeyFromHex(echo_serv_pubkey_str))
	encpkt, err := this.SendRoutingRequest(NewCryptoKeyFromHex(pubkey))
	gopp.ErrPrint(err)
	wn, err := c.Write(encpkt)
	gopp.ErrPrint(err, wn)
	this.sent_nonce.Incr()
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
	rspdat, err := DecryptDataSymmetric(this.shrkey, this.recv_nonce, rpkt[2:])
	gopp.ErrPrint(err)
	gopp.Assert(rspdat[0] == TCP_PACKET_ROUTING_RESPONSE, "Invalid packet", rspdat[0])
	connid := rspdat[1]
	pubkey := NewCryptoKey(rspdat[2 : 2+PUBLIC_KEY_SIZE])
	log.Println(rspdat[0], connid, pubkey.ToHex()[:20], "<=", this.self_pubkey.ToHex()[:20])
	this.recv_nonce.Incr()

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

// tcp packet
func (this *TCPClient) CreatePacket(plain []byte) (encpkt []byte, err error) {
	log.Println(len(plain), this.shrkey.ToHex()[:20], this.sent_nonce.ToHex())
	encdat, err := EncryptDataSymmetric(this.shrkey, this.sent_nonce, plain)
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
	plnpkt, err = DecryptDataSymmetric(this.shrkey, this.recv_nonce, encpkt[2:])
	return
}

func EncryptDataSymmetric(seckey *CryptoKey, nonce *CBNonce, plain []byte) (encrypted []byte, err error) {
	temp_plain := make([]byte, len(plain)+cryptobox.CryptoBoxZeroBytes())
	n := copy(temp_plain[cryptobox.CryptoBoxZeroBytes():], plain)
	gopp.Assert(n == len(plain), "copy error", n, len(plain))

	encrypted, err = CBAfterNm(seckey, nonce, temp_plain)
	if err != nil {
		err = errors.Wrap(err, "")
		return
	}

	encrypted = encrypted[cryptobox.CryptoBoxBoxZeroBytes():]
	gopp.Assert(len(encrypted) == len(plain)+cryptobox.CryptoBoxMacBytes(),
		"size error:", len(encrypted), len(plain))
	return
}

func DecryptDataSymmetric(seckey *CryptoKey, nonce *CBNonce, encrypted []byte) (plain []byte, err error) {
	temp_encrypted := make([]byte, len(encrypted)+cryptobox.CryptoBoxBoxZeroBytes())
	copy(temp_encrypted[cryptobox.CryptoBoxBoxZeroBytes():], encrypted)

	plain, err = CBOpenAfterNm(seckey, nonce, temp_encrypted)
	gopp.ErrPrint(err, len(plain), len(encrypted))
	plain = plain[cryptobox.CryptoBoxZeroBytes():]
	gopp.Assert(len(plain) == len(encrypted)-cryptobox.CryptoBoxMacBytes(),
		"size error:", len(plain), len(encrypted))
	if err != nil {
		err = errors.Wrap(err, "")
	}
	return
}
