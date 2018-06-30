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

	"github.com/Workiva/go-datastructures/queue"
)

/* Maximum number of clients stored per friend. */
const MAX_FRIEND_CLIENTS = 8

const LCLIENT_NODES = (MAX_FRIEND_CLIENTS)
const LCLIENT_LENGTH = 128

/* A list of the clients mathematically closest to ours. */
const LCLIENT_LIST = (LCLIENT_LENGTH * LCLIENT_NODES)

const MAX_CLOSE_TO_BOOTSTRAP_NODES = 8

/* The max number of nodes to send with send nodes. */
const MAX_SENT_NODES = 4

/* Ping timeout in seconds */
const PING_TIMEOUT = 5

/* size of DHT ping arrays. */
const DHT_PING_ARRAY_SIZE = 512

/* Ping interval in seconds for each node in our lists. */
const PING_INTERVAL = 60

/* The number of seconds for a non responsive node to become bad. */
const PINGS_MISSED_NODE_GOES_BAD = 1
const PING_ROUNDTRIP = 2
const BAD_NODE_TIMEOUT = (PING_INTERVAL + PINGS_MISSED_NODE_GOES_BAD*(PING_INTERVAL+PING_ROUNDTRIP))

/* Redefinitions of variables for safe transfer over wire. */
const TOX_AF_INET = 2
const TOX_AF_INET6 = 10
const TOX_TCP_INET = 130
const TOX_TCP_INET6 = 138

/* The number of "fake" friends to add (for optimization purposes and so our paths for the onion part are more random) */
const DHT_FAKE_FRIEND_NUMBER = 2

const MAX_CRYPTO_REQUEST_SIZE = 1024

const CRYPTO_PACKET_FRIEND_REQ = 32 /* Friend request crypto packet ID. */
const CRYPTO_PACKET_HARDENING = 48  /* Hardening crypto packet ID. */
const CRYPTO_PACKET_DHTPK = 156
const CRYPTO_PACKET_NAT_PING = 254 /* NAT ping crypto packet ID. */

/////////
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
	// Assoc4 IPPTsPng
	// Assoc6 IPPTsPng
	Assoc IPPTsPng

	cmppk *CryptoKey // selfpk
}

func (this *ClientData) Compare(thati queue.Item) int {
	that := thati.(*ClientData)
	n := IDClosest(this.cmppk, this.Pubkey, that.Pubkey)
	if n == 1 {
		now := time.Now()
		if now.Sub(this.Assoc.Timestamp) > now.Sub(that.Assoc.Timestamp) {
			return -1
		}
	}
	return n
}

type NodeFormat struct {
	Pubkey *CryptoKey
	Addr   net.Addr

	//
	cmppk *CryptoKey // selfpk
}

func (this *NodeFormat) Compare(that queue.Item) int {
	return IDClosest(this.cmppk, this.Pubkey, that.(*NodeFormat).Pubkey)
}

type DHTFriend struct {
	Pubkey *CryptoKey

	ClientList *queue.PriorityQueue // Client_data client_list[MAX_FRIEND_CLIENTS];

	/* Time at which the last get_nodes request was sent. */
	LastGetnode time.Time
	/* number of times get_node packets were sent. */
	BootstrapTimes uint32

	/* Symetric NAT hole punching stuff. */
	// NAT         nat;

	LockCount uint16
	/*
	   struct {
	       void (*ip_callback)(void *, int32_t, IP_Port);
	       void *data;
	       int32_t number;
	   } callbacks[DHT_FRIEND_MAX_LOCKS];
	*/

	ToBootstrap *queue.PriorityQueue //    Node_format to_bootstrap[MAX_SENT_NODES];

	//
	cmppk *CryptoKey
}

func NewDHTFriend() *DHTFriend {
	this := &DHTFriend{}
	this.ClientList = queue.NewPriorityQueue(MAX_FRIEND_CLIENTS, false)
	this.ToBootstrap = queue.NewPriorityQueue(MAX_SENT_NODES, false)
	return this
}

func (this *DHTFriend) AddNode(n *NodeFormat) {
	this.ClientList.Put(n)
	pqkeepn(this.ClientList, MAX_FRIEND_CLIENTS)
	this.ToBootstrap.Put(n)
	pqkeepn(this.ToBootstrap, MAX_SENT_NODES)
}

// name to SharedKeyInfo???
/*----------------------------------------------------------------------------------*/
/* struct to store some shared keys so we don't have to regenerate them for each request. */
const MAX_KEYS_PER_SLOT = 4
const KEYS_TIMEOUT = 600

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
	Neto  *NetworkCore
	Pingo *Ping

	SelfPubkey *CryptoKey
	SelfSeckey *CryptoKey

	CloseClientList *queue.PriorityQueue // [LCLIENT_LIST]*ClientData

	FriendsList map[string]*DHTFriend // binpk =>

	SharedKeysRecv map[string]*SharedKey // binpk =>
	SharedKeysSent map[string]*SharedKey // binpk =>

	CryptoPacketHandlers map[uint8]CryptoPacketHandle

	ToBootstrap *queue.PriorityQueue // [MAX_CLOSE_TO_BOOTSTRAP_NODES]*NodeFormat
}

func NewDHT() *DHT {
	this := &DHT{}
	this.Neto = NewNetworkCore()
	this.Pingo = NewPing(this, this.SelfPubkey, this.Neto)

	this.SelfPubkey, this.SelfSeckey, _ = NewCBKeyPair()
	log.Println(this.SelfPubkey.ToHex(), this.SelfSeckey.ToHex())

	this.SharedKeysRecv = make(map[string]*SharedKey)
	this.SharedKeysSent = make(map[string]*SharedKey)
	this.CloseClientList = queue.NewPriorityQueue(LCLIENT_LIST, false)
	this.FriendsList = make(map[string]*DHTFriend)
	this.ToBootstrap = queue.NewPriorityQueue(MAX_CLOSE_TO_BOOTSTRAP_NODES, false)
	this.CryptoPacketHandlers = make(map[uint8]CryptoPacketHandle)

	this.Neto.RegisterHandle(NET_PACKET_GET_NODES, this.HandleGetNodes, this)
	this.Neto.RegisterHandle(NET_PACKET_SEND_NODES_IPV6, this.HandleSendNodesIpv6, this)
	this.Neto.RegisterHandle(NET_PACKET_CRYPTO, this.HandleCryptoPacket, this)
	// this.RegisterHandleCryptoPacket(ptype uint8, cbfn CryptoPacketHandleFunc, object interface{})
	// this.RegisterHandleCryptoPacket(ptype uint8, cbfn CryptoPacketHandleFunc, object interface{})

	this.start()
	return this
}

func (this *DHT) SetKeyPair(pk *CryptoKey, sk *CryptoKey) {
	// this.SelfPubkey, this.SelfSeckey = pk, sk
	copy(this.SelfPubkey.Bytes(), pk.Bytes())
	copy(this.SelfSeckey.Bytes(), sk.Bytes())
}

func (this *DHT) start() { go this.doDHT() }
func (this *DHT) doDHT() {
	closesttm := time.NewTicker(3 * time.Second)
	frndtm := time.NewTicker(5 * time.Second)
	nattm := time.NewTicker(5 * time.Second)
	pingtm := time.NewTicker(PING_INTERVAL * time.Second)
	doneC := make(chan struct{}, 0)
	stop := false
	for !stop {
		select {
		case <-closesttm.C:
			this.doClosest()
		case <-frndtm.C:
			this.doDHTFriends()
		case <-nattm.C:
			this.doNAT()
		case <-pingtm.C:
			this.doToPing()
		case <-doneC:
			stop = true
			break
		}
	}
	log.Println("doDHT done")
}

func (this *DHT) doClosest() {
	items, err := this.ToBootstrap.Get(this.ToBootstrap.Len())
	gopp.ErrPrint(err)
	err = this.ToBootstrap.Put(items...)
	gopp.ErrPrint(err)
	if len(items) > 0 {
		idx := rand.Int() % len(items)
		item := items[idx].(*NodeFormat)
		this.GetNodes(item.Addr, item.Pubkey, this.SelfPubkey)
	}
	/*
		for _, itemi := range items {
			item := itemi.(*NodeFormat)
			this.GetNodes(item.Addr, item.Pubkey, this.SelfPubkey)
		}
	*/
}

func (this *DHT) doDHTFriends() {

}
func (this *DHT) doNAT() {

}
func (this *DHT) doToPing() {

}
func (this *DHT) doHardening() {

}

func (this *DHT) HandleGetNodes(object interface{}, addr net.Addr, data []byte, cbdata interface{}) (int, error) {
	log.Println("Handle getnodes request:", addr.String(), len(data))
	return 0, nil
}

func (this *DHT) HandleSendNodesIpv6(object interface{}, addr net.Addr, data []byte, cbdata interface{}) (int, error) {
	// log.Println(addr.String(), len(data))
	pubkey := NewCryptoKey(data[1 : 1+PUBLIC_KEY_SIZE])
	nonce := NewCBNonce(data[1+PUBLIC_KEY_SIZE : 1+PUBLIC_KEY_SIZE+NONCE_SIZE])
	encrypted := data[1+PUBLIC_KEY_SIZE+NONCE_SIZE:]
	shrkey := this.GetSharedKeySent(pubkey)
	plain, err := DecryptDataSymmetric(shrkey, nonce, encrypted)
	gopp.ErrPrint(err)

	plainBuf := gopp.NewBufferBuf(plain)
	numNodes, err := plainBuf.ReadByte()
	gopp.ErrPrint(err)
	// log.Println("numNodes=", numNodes)
	var pingid uint64
	reqidpos := len(plain) - int(unsafe.Sizeof(pingid))
	err = binary.Read(plainBuf.BufAt(reqidpos), binary.BigEndian, &pingid)
	gopp.ErrPrint(err, reqidpos)
	// log.Println("pingid=", pingid)
	// TODO check pingid is our sent

	//
	for i, offset := 0, 1; i < int(numNodes); i++ {
		tmpbuf := plainBuf.BufAt(offset)
		tmplen := tmpbuf.Len()
		byte0, err := tmpbuf.ReadByte()
		gopp.ErrPrint(err)

		istcp := byte0&128 == 1
		isip6 := byte0&127 == 10
		// log.Printf("node: %d, %s, %s\n", i, gopp.IfElseStr(istcp, "TCP", "UDP"),
		//	gopp.IfElseStr(isip6, "IPV6", "IPV4"))
		var ipobj net.IP = make([]byte, gopp.IfElseInt(isip6, 16, 4))
		tmpbuf.Read(ipobj)
		// var ipobj net.IP = gopp.BytesReverse(ipbuf)
		var port uint16
		binary.Read(tmpbuf, binary.BigEndian, &port)
		addro := gopp.IfElse(istcp, &net.TCPAddr{Port: int(port), IP: ipobj}, &net.UDPAddr{Port: int(port), IP: ipobj}).(net.Addr)

		nodekey_, err := tmpbuf.Readn(PUBLIC_KEY_SIZE)
		nodekey := NewCryptoKey(nodekey_)
		log.Println("node: ", i, addro.Network(), addro.String(), nodekey.ToHex())

		offset += tmplen - tmpbuf.Len()

		// process node
		nodfmt := &NodeFormat{Pubkey: nodekey, Addr: addro, cmppk: this.SelfPubkey}
		this.ToBootstrap.Put(nodfmt)
		pqkeepn(this.ToBootstrap, MAX_CLOSE_TO_BOOTSTRAP_NODES)
		clidat := &ClientData{Pubkey: nodekey, cmppk: this.SelfPubkey}
		clidat.Assoc.Addr = addro
		this.CloseClientList.Put(clidat)
		pqkeepn(this.CloseClientList, LCLIENT_LIST)
		log.Println("tobslen:", this.ToBootstrap.Len(), "closestlen:", this.CloseClientList.Len())
		for _, dhtfrnd := range this.FriendsList {
			dhtfrnd.AddNode(nodfmt)
		}
	}
	log.Println()

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
			// time.Sleep(3 * time.Second)
		}
		// log.Println("send done")
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
		log.Println("New shrkey for:", pubkey.ToHex(), shrkey.ToHex(), len(shrkeys)+1)
		shrkeyo := &SharedKey{}
		shrkeyo.Shrkey = shrkey
		shrkeyo.Pubkey = pubkey
		shrkeyo.TimesRequested += 1
		shrkeys[pubkey.BinStr()] = shrkeyo
		return shrkey
	}
}

func pqkeepn(q *queue.PriorityQueue, n int) {
	for q.Len() > n {
		q.Get(1)
	}
}

/* Compares pk1 and pk2 with pk.
 *
 *  return 0 if both are same distance.
 *  return 1 if pk1 is closer.
 *  return 2 if pk2 is closer.
 */
func IDClosest(pk *CryptoKey, pk1 *CryptoKey, pk2 *CryptoKey) int {
	pkb, pk1b, pk2b := pk.Bytes(), pk1.Bytes(), pk2.Bytes()
	for i := 0; i < PUBLIC_KEY_SIZE; i++ {

		distance1 := pkb[i] ^ pk1b[i]
		distance2 := pkb[i] ^ pk2b[i]

		if distance1 < distance2 {
			return 1
		}
		if distance1 > distance2 {
			return -1 // 2
		}
	}
	return 0
}

// need?
func IDDistance(pk1 *CryptoKey, pk2 *CryptoKey) int {
	return 0
}
