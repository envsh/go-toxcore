package main

import (
	"bytes"
	"encoding/binary"
	"gopp"
	"log"
	"math/rand"
	"net"
	"time"
	"unsafe"
)

type IPPTsPng struct {
	Addr       net.Addr
	Timestamp  time.Time
	LastPinged time.Time

	// Hardening hardening;
	/* Returned by this node. Either our friend or us. */
	RetAddr      net.Addr
	RetTimestamp uint64
}

type ClientData struct {
	Pubkey *CryptoKey
	Assoc4 IPPTsPng
	Assoc6 IPPTsPng
}

type NodeFormat struct {
	Pubkey *CryptoKey
	Addr   net.Addr
}

// name to SharedKeyInfo???
type SharedKey struct {
	Pubkey            *CryptoKey
	Shrkey            *CryptoKey
	TimesRequested    uint32
	Stored            bool
	TimeLastRequested time.Time
}

type CryptoPacketHandleFunc func(object interface{}, addr net.Addr, srcpk *CryptoKey,
	data []byte, cbdata interface{}) (int, error)
type CryptoPacketHandle struct {
	Func func(object interface{}, addr net.Addr, srcpk *CryptoKey,
		data []byte, cbdata interface{}) (int, error)
	Object interface{}
}

type DHT struct {
	Neto *NetworkCore

	SelfPubkey *CryptoKey
	SelfSeckey *CryptoKey

	CloseClientList []*ClientData

	SharedKeysRecv map[string]*SharedKey // binpk =>
	SharedKeysSent map[string]*SharedKey // binpk =>

	CryptoPacketHandlers map[uint8]CryptoPacketHandle

	ToBootstrap []*NodeFormat
}

func NewDHT() *DHT {
	this := &DHT{}
	this.Neto = NewNetworkCore()

	this.SelfPubkey, this.SelfSeckey, _ = NewCBKeyPair()
	log.Println(this.SelfPubkey.ToHex(), this.SelfSeckey.ToHex())

	this.SharedKeysRecv = make(map[string]*SharedKey)
	this.SharedKeysSent = make(map[string]*SharedKey)
	this.CryptoPacketHandlers = make(map[uint8]CryptoPacketHandle)

	this.Neto.RegisterHandle(NET_PACKET_GET_NODES, this.HandleGetNodes, this)
	this.Neto.RegisterHandle(NET_PACKET_SEND_NODES_IPV6, this.HandleSendNodesIpv6, this)
	this.Neto.RegisterHandle(NET_PACKET_CRYPTO, this.HandleCryptoPacket, this)
	// this.RegisterHandleCryptoPacket(ptype uint8, cbfn CryptoPacketHandleFunc, object interface{})
	// this.RegisterHandleCryptoPacket(ptype uint8, cbfn CryptoPacketHandleFunc, object interface{})

	return this
}

func (this *DHT) SetKeyPair(pk *CryptoKey, sk *CryptoKey) {
	this.SelfPubkey, this.SelfSeckey = pk, sk
}

func (this *DHT) HandleGetNodes(object interface{}, addr net.Addr, data []byte, cbdata interface{}) (int, error) {
	log.Println(addr.String(), len(data))
	return 0, nil
}

func (this *DHT) HandleSendNodesIpv6(object interface{}, addr net.Addr, data []byte, cbdata interface{}) (int, error) {
	log.Println(addr.String(), len(data))
	pubkey := NewCryptoKey(data[1 : 1+PUBLIC_KEY_SIZE])
	nonce := NewCBNonce(data[1+PUBLIC_KEY_SIZE : 1+PUBLIC_KEY_SIZE+NONCE_SIZE])
	encrypted := data[1+PUBLIC_KEY_SIZE+NONCE_SIZE:]
	shrkey := this.GetSharedKeySent(pubkey)
	plain, err := DecryptDataSymmetric(shrkey, nonce, encrypted)
	gopp.ErrPrint(err)

	plainBuf := gopp.NewBufferBuf(plain)
	numNodes, err := plainBuf.ReadByte()
	gopp.ErrPrint(err)
	log.Println("numNodes=", numNodes)
	var pingid uint64
	reqidpos := len(plain) - int(unsafe.Sizeof(pingid))
	err = binary.Read(plainBuf.BufAt(reqidpos), binary.BigEndian, &pingid)
	gopp.ErrPrint(err, reqidpos)
	log.Println("pingid=", pingid)
	// TODO check pingid is our sent

	//
	for i, offset := 0, 1; i < int(numNodes); i++ {
		log.Println(i, offset)
		tmpbuf := plainBuf.BufAt(offset)
		tmplen := tmpbuf.Len()
		byte0, err := tmpbuf.ReadByte()
		gopp.ErrPrint(err)

		istcp := byte0&128 == 1
		log.Printf("node: %d, %s, %s\n", i, gopp.IfElseStr(istcp, "TCP", "UDP"),
			gopp.IfElseStr(byte0&127 == 10, "IPV6", "IPV4"))
		var ipobj net.IP = make([]byte, gopp.IfElseInt(byte0&127 == 10, 16, 4))
		tmpbuf.Read(ipobj)
		// var ipobj net.IP = gopp.BytesReverse(ipbuf)
		var port uint16
		binary.Read(tmpbuf, binary.BigEndian, &port)
		addro := gopp.IfElse(istcp, &net.TCPAddr{Port: int(port), IP: ipobj}, &net.UDPAddr{Port: int(port), IP: ipobj}).(net.Addr)

		nodekey_, err := tmpbuf.Readn(PUBLIC_KEY_SIZE)
		nodekey := NewCryptoKey(nodekey_)
		log.Println("node: ", i, addro.Network(), addro.String(), nodekey.ToHex())

		offset += tmplen - tmpbuf.Len()
	}

	return 0, nil
}

func (this *DHT) HandleCryptoPacket(object interface{}, addr net.Addr, data []byte, cbdata interface{}) (int, error) {
	log.Println(addr.String(), len(data))
	return 0, nil
}

func (this *DHT) HandleNATPing(object interface{}, addr net.Addr, srcpk *CryptoKey, data []byte, cbdata interface{}) (int, error) {
	log.Println(addr.String(), len(data))
	return 0, nil
}
func (this *DHT) HandleHardingPacket(object interface{}, addr net.Addr, srcpk *CryptoKey, data []byte, cbdata interface{}) (int, error) {
	log.Println(addr.String(), len(data))
	return 0, nil
}

func (this *DHT) RegisterHandleCryptoPacket(ptype uint8, cbfn CryptoPacketHandleFunc, object interface{}) {
	this.CryptoPacketHandlers[ptype] = CryptoPacketHandle{cbfn, object}
}

/* Send a getnodes request.
   sendback_node is the node that it will send back the response to (set to NULL to disable this) */
func (this *DHT) GetNodes(addr net.Addr, pubkey *CryptoKey, client_id *CryptoKey) {
	pingid := rand.Uint64()
	gopp.CmpAndSwapN(&pingid, 0, 1)

	plain := gopp.NewBufferZero()
	plain.Write(client_id.Bytes())
	binary.Write(plain, binary.BigEndian, pingid)

	shrkey := this.GetSharedKeySent(pubkey)
	pkt, err := this.CreatePacket(this.SelfPubkey, shrkey, NET_PACKET_GET_NODES, plain.Bytes())
	gopp.ErrPrint(err)
	wntlen := 1 + PUBLIC_KEY_SIZE + NONCE_SIZE + plain.Len() + MAC_SIZE
	gopp.TruePrint(len(pkt) != wntlen, "Invalid pkt,", wntlen, len(pkt))

	go func() {
		for i := 0; i < 1; i++ {
			wn, err := this.Neto.WriteTo(pkt, addr)
			gopp.ErrPrint(err, wn)
			time.Sleep(3 * time.Second)
		}
		log.Println("send done")
	}()
	log.Println("Sent get nodes request:", len(pkt), addr.String(), pingid)
}

func (this *DHT) Bootstrap(addr net.Addr, pubkey *CryptoKey) error {
	this.GetNodes(addr, pubkey, this.SelfPubkey)
	return nil
}

func (this *DHT) BootstrapFromAddr(addr string, pubkey *CryptoKey) error {
	addro, err := net.ResolveUDPAddr("udp", addr)
	gopp.ErrPrint(err, addr)
	if err != nil {
		return err
	}
	return this.Bootstrap(addro, pubkey)
}

// pubkey: always current DHT's pubkey?
func (this *DHT) CreatePacket(pubkey *CryptoKey, shrkey *CryptoKey, ptype uint8, plain []byte) (pkt []byte, err error) {
	nonce := CBRandomNonce()
	encrypted, err := EncryptDataSymmetric(shrkey, nonce, plain)
	gopp.ErrPrint(err)
	if err != nil {
		return
	}
	wbuf := bytes.NewBuffer([]byte{})
	wbuf.WriteByte(byte(ptype))
	wbuf.Write(pubkey.Bytes())
	wbuf.Write(nonce.Bytes())
	wbuf.Write(encrypted)

	pkt = wbuf.Bytes()
	return
}

func (this *DHT) GetSharedKeyRecv(pubkey *CryptoKey) *CryptoKey {
	return this.GetSharedKey(this.SharedKeysRecv, pubkey)
}
func (this *DHT) GetSharedKeySent(pubkey *CryptoKey) *CryptoKey {
	return this.GetSharedKey(this.SharedKeysSent, pubkey)
}
func (this *DHT) GetSharedKey(shrkeys map[string]*SharedKey, pubkey *CryptoKey) *CryptoKey {
	if shrkeyo, ok := shrkeys[pubkey.BinStr()]; ok {
		return shrkeyo.Shrkey
	} else {
		shrkey, err := CBBeforeNm(pubkey, this.SelfSeckey)
		gopp.ErrPrint(err)
		log.Println("New shrkey for:", pubkey.ToHex(), shrkey.ToHex())
		shrkeyo := &SharedKey{}
		shrkeyo.Shrkey = shrkey
		shrkeyo.Pubkey = pubkey
		shrkeyo.TimesRequested += 1
		shrkeys[pubkey.BinStr()] = shrkeyo
		return shrkey
	}
}
