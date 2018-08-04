package mintox

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"gopp"
	"log"
	"net"
	"time"
	"unsafe"
)

const ONION_ANNOUNCE_MAX_ENTRIES = 160
const ONION_ANNOUNCE_TIMEOUT = 300
const ONION_PING_ID_SIZE = SHA256_SIZE

const ONION_ANNOUNCE_SENDBACK_DATA_LENGTH = int(unsafe.Sizeof(uint64(0)))

const ONION_ANNOUNCE_REQUEST_SIZE = (1 + NONCE_SIZE + PUBLIC_KEY_SIZE + ONION_PING_ID_SIZE + PUBLIC_KEY_SIZE + PUBLIC_KEY_SIZE + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + MAC_SIZE)

const ONION_ANNOUNCE_RESPONSE_MIN_SIZE = (1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + NONCE_SIZE + 1 + ONION_PING_ID_SIZE + MAC_SIZE)

// const ONION_ANNOUNCE_RESPONSE_MAX_SIZE = (ONION_ANNOUNCE_RESPONSE_MIN_SIZE + sizeof(Node_format)*MAX_SENT_NODES)

const ONION_DATA_RESPONSE_MIN_SIZE = (1 + NONCE_SIZE + PUBLIC_KEY_SIZE + MAC_SIZE)

const ONION_DATA_REQUEST_MIN_SIZE = (1 + PUBLIC_KEY_SIZE + NONCE_SIZE + PUBLIC_KEY_SIZE + MAC_SIZE)
const MAX_DATA_REQUEST_SIZE = (ONION_MAX_DATA_SIZE - ONION_DATA_REQUEST_MIN_SIZE)

type Onion_Announce_Entry struct {
	Pubkey    *CryptoKey
	RetAddr   net.Addr
	RetDat    []byte // ONION_RETURN_3
	DatPubkey *CryptoKey
	Timestamp time.Time

	cmppk *CryptoKey
}

func (this *Onion_Announce_Entry) Key() string { return this.Pubkey.BinStr() }
func (this *Onion_Announce_Entry) Compare(thatx PLItem) int {
	that := thatx.(*Onion_Announce_Entry)
	t1 := IsTimeout4Now(this.Timestamp, ONION_ANNOUNCE_TIMEOUT)
	t2 := IsTimeout4Now(that.Timestamp, ONION_ANNOUNCE_TIMEOUT)
	if t1 && t2 {
		return 0
	}
	if t1 {
		return -1
	}
	if t2 {
		return 1
	}

	return IDClosest(this.cmppk, this.Pubkey, that.Pubkey)
}
func (this *Onion_Announce_Entry) Update(thatx PLItem) {
	that := thatx.(*Onion_Announce_Entry)
	this.Timestamp = that.Timestamp
}

type Onion_Announce struct {
	dhto *DHT
	neto *NetworkCore
	// Entries [ONION_ANNOUNCE_MAX_ENTRIES]*Onion_Announce_Entry
	Entries *PriorityList
	/* This is CRYPTO_SYMMETRIC_KEY_SIZE long just so we can use new_symmetric_key() to fill it */
	SecBytes *CryptoKey

	SharedKeysRecv map[string]*SharedKey // binpk =>
}

/////
const PING_ID_TIMEOUT = 20

const ANNOUNCE_REQUEST_SIZE_RECV = (ONION_ANNOUNCE_REQUEST_SIZE + ONION_RETURN_3)

const DATA_REQUEST_MIN_SIZE = ONION_DATA_REQUEST_MIN_SIZE
const DATA_REQUEST_MIN_SIZE_RECV = (DATA_REQUEST_MIN_SIZE + ONION_RETURN_3)

func NewOnionAnnounce(dhto *DHT) *Onion_Announce {
	this := &Onion_Announce{}
	this.dhto = dhto
	this.neto = dhto.Neto
	this.Entries = NewPriorityList(ONION_ANNOUNCE_MAX_ENTRIES)
	_, this.SecBytes, _ = NewCBKeyPair()
	this.SharedKeysRecv = map[string]*SharedKey{}

	neto := dhto.Neto
	neto.RegisterHandle(NET_PACKET_ANNOUNCE_REQUEST, this.handleAnnounceRequest, this)
	// neto.RegisterHandle(NET_PACKET_ONION_DATA_REQUEST, this.handleDataRequest, this)

	return this
}

func (this *Onion_Announce) Kill() {
	neto := this.neto
	neto.RegisterHandle(NET_PACKET_ANNOUNCE_REQUEST, nil, nil)
	// neto.RegisterHandle(NET_PACKET_ONION_DATA_REQUEST, nil,nil)
	this = nil
}

///// private handlers
func (this *Onion_Announce) handleAnnounceRequest(object interface{}, addr net.Addr, data []byte, cbdata interface{}) (int, error) {
	log.Println("handle announce request:", len(data), addr, data[0])
	gopp.Assert(len(data) == ANNOUNCE_REQUEST_SIZE_RECV, "Invalid packet")

	nonce := NewCBNonce(data[1 : 1+NONCE_SIZE])
	pktpk := NewCryptoKey(data[1+NONCE_SIZE : 1+NONCE_SIZE+PUBLIC_KEY_SIZE])
	shrkey := this.dhto.GetSharedKey(this.SharedKeysRecv, pktpk)

	wntsz := ONION_PING_ID_SIZE + PUBLIC_KEY_SIZE + PUBLIC_KEY_SIZE + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + MAC_SIZE
	// log.Printf("0x%x, %d, %s, %d, %d, %d\n", data[1+NONCE_SIZE+PUBLIC_KEY_SIZE+wntsz], data[1+NONCE_SIZE+PUBLIC_KEY_SIZE+wntsz], netpktname(data[1+NONCE_SIZE+PUBLIC_KEY_SIZE+wntsz]), ONION_ANNOUNCE_REQUEST_SIZE+ONION_RETURN_3, ONION_ANNOUNCE_REQUEST_SIZE, ONION_RETURN_3)
	plnpkt, err := DecryptDataSymmetric(shrkey, nonce, data[1+NONCE_SIZE+PUBLIC_KEY_SIZE:1+NONCE_SIZE+PUBLIC_KEY_SIZE+wntsz])
	gopp.ErrPrint(err, "decrypt:", nonce.ToHex20(), pktpk.ToHex20(), shrkey.ToHex20(), len(data), len(data)-1-NONCE_SIZE-PUBLIC_KEY_SIZE, wntsz)

	pingid := plnpkt[:ONION_PING_ID_SIZE]
	searchpk := NewCryptoKey(plnpkt[ONION_PING_ID_SIZE : ONION_PING_ID_SIZE+PUBLIC_KEY_SIZE])
	datpubkey := NewCryptoKey(plnpkt[ONION_PING_ID_SIZE+PUBLIC_KEY_SIZE : ONION_PING_ID_SIZE+PUBLIC_KEY_SIZE*2])
	sbdata := plnpkt[ONION_PING_ID_SIZE+PUBLIC_KEY_SIZE*2:]
	retdat := data[ANNOUNCE_REQUEST_SIZE_RECV-ONION_RETURN_3:]
	gopp.G_USED(pingid, searchpk, datpubkey, sbdata)
	log.Printf("annreq from %v pktpk: %s pingid: %s searchpk: %s datpk: %s sbdata: %v\n",
		addr, pktpk.ToHex20(), NewCryptoKey(pingid).ToHex20(), searchpk.ToHex20(), datpubkey.ToHex20(), len(sbdata))

	// if pingid==00000, then is announce ourselves step1
	// if datpk==00000, then is searching searchpkg(friend realpk)
	// TODO which is announce themself, which is searching others
	// TODO is client ping nodes
	pingidok := len(bytes.Trim(pingid, string(byte(0)))) != 0
	if len(bytes.Trim(datpubkey.Bytes(), string(byte(0)))) == 0 {
		log.Printf("%v with dhtpk %s is searching for friend realpk %s\n",
			addr, pktpk.ToHex20(), searchpk.ToHex())
	} else {

	}

	pingid1 := this.generate_ping_id(time.Now(), pktpk, addr)
	pingid2 := this.generate_ping_id(time.Now().Add(PING_ID_TIMEOUT*time.Second), pktpk, addr)
	rspnonce := CBRandomNonce()
	nodes := this.dhto.get_close_nodes(searchpk, 0, false, true)

	var inentry *Onion_Announce_Entry
	if bytes.Compare(pingid1, pingid) == 0 || bytes.Compare(pingid2, pingid) == 0 {
		inentry = this.add_to_entries(addr, pktpk, datpubkey, retdat)
	} else {
		inentry = this.find_in_entries(searchpk)
	}
	// log.Println(inentry == nil, bytes.Compare(pingid1, pingid), bytes.Compare(pingid2, pingid))

	plbuf := gopp.NewBufferZero()
	if inentry == nil {
		is_stored := byte(0)
		plbuf.WriteByte(is_stored)
		plbuf.Write(pingid2)
	} else {
		if inentry.Pubkey.Equal2(pktpk) {
			if !inentry.DatPubkey.Equal2(datpubkey) {
				is_stored := byte(0)
				plbuf.WriteByte(is_stored)
				plbuf.Write(pingid2)
			} else {
				is_stored := byte(2)
				plbuf.WriteByte(is_stored)
				plbuf.Write(pingid2)
			}
		} else {
			is_stored := byte(1)
			plbuf.WriteByte(is_stored)
			plbuf.Write(inentry.DatPubkey.Bytes())
		}
	}

	if !pingidok {
		// 	log.Printf("announce of %v, realpk: %s, dhtpk: %s\n", addr, pktpk.ToHex(), datpubkey.ToHex())
	}

	for _, node := range nodes {
		plbuf.Write(pack_ip_port(node.Addr))
		plbuf.Write(node.Pubkey.Bytes())
	}
	encplpkt, err := EncryptDataSymmetric(shrkey, rspnonce, plbuf.Bytes())
	gopp.ErrPrint(err)

	rspbuf := gopp.NewBufferZero()
	rspbuf.WriteByte(NET_PACKET_ANNOUNCE_RESPONSE)
	rspbuf.Write(sbdata)
	rspbuf.Write(rspnonce.Bytes())
	rspbuf.Write(encplpkt)

	err = this.neto.SendOnionResponse(addr, rspbuf.Bytes(), retdat)
	gopp.ErrPrint(err)
	log.Println("retdat:", len(retdat), pingidok, plbuf.Bytes()[0], NewCryptoKey(pingid1).ToHex20(), NewCryptoKey(pingid2).ToHex20())

	return 0, nil
}

func (this *Onion_Announce) handleDataRequest(object interface{}, addr net.Addr, data []byte, cbdata interface{}) (int, error) {
	log.Println("handle announce request:", len(data), addr)
	return 0, nil
}

func (this *Onion_Announce) generate_ping_id(t time.Time, pubkey *CryptoKey, retaddr net.Addr) []byte {
	ts := t.Unix() / PING_ID_TIMEOUT
	buf := gopp.NewBufferZero()
	buf.Write(this.SecBytes.Bytes())
	binary.Write(buf, binary.BigEndian, ts)
	buf.Write(pubkey.Bytes())
	buf.Write(retaddr.(*net.UDPAddr).IP)
	binary.Write(buf, binary.BigEndian, uint16(retaddr.(*net.UDPAddr).Port))
	hval := sha256.Sum256(buf.Bytes())
	return hval[:]
}

func (this *Onion_Announce) add_to_entries(retaddr net.Addr, pubkey *CryptoKey, datpubkey *CryptoKey, retdat []byte) *Onion_Announce_Entry {
	entry := &Onion_Announce_Entry{}
	entry.DatPubkey = datpubkey
	entry.RetAddr = retaddr
	entry.Pubkey = pubkey
	entry.Timestamp = time.Now()
	entry.RetDat = retdat

	entry.cmppk = this.dhto.SelfPubkey

	ok := this.Entries.Put(entry)
	if !ok {
		return nil
	}
	return this.find_in_entries(pubkey)
}
func (this *Onion_Announce) find_in_entries(searchpk *CryptoKey) *Onion_Announce_Entry {
	itemx := this.Entries.GetByKey(searchpk.BinStr())
	if itemx == nil {
		return nil
	}
	item := itemx.(*Onion_Announce_Entry)
	if IsTimeout4Now(item.Timestamp, ONION_ANNOUNCE_TIMEOUT) {
		this.Entries.Remove(itemx)
		return nil
	}
	return item
}

/////
