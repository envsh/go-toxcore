package main

import (
	"gopp"
	"log"
	"math/rand"
	"net"
)

// distinct from messager api

type DHTApi struct {
	dhto *DHT
	neto *NetworkCore

	SelfPubkey *CryptoKey
	SelfSeckey *CryptoKey
}

// hex string
func NewDHTApi(pubkey, seckey string) *DHTApi {
	this := &DHTApi{}
	this.SelfPubkey = NewCryptoKeyFromHex(pubkey)
	this.SelfSeckey = NewCryptoKeyFromHex(seckey)

	dht := NewDHT()
	dht.SetKeyPair(this.SelfPubkey, this.SelfSeckey)
	this.dhto = dht
	log.Println("dht key:", this.SelfPubkey.ToHex(), this.SelfSeckey.ToHex())
	dht.Neto.RegisterHandle(NET_PACKET_CRYPTO_DATA, this.HandleCryptoDataPacket, this)
	return this
}

func NewDHTApiAutoKey() *DHTApi {
	pubkey, seckey, _ := NewCBKeyPair()
	return NewDHTApi(pubkey.ToHex(), seckey.ToHex())
}

func (this *DHTApi) AddFriend(pubkey string) {
	pubkeyo := NewCryptoKeyFromHex(pubkey)
	this.dhto.AddFriend(pubkeyo, func(cbdata interface{}, num int32, addr net.Addr) {
		log.Println("hehhe", num, addr, pubkey)
	}, nil, 0)
}

func (this *DHTApi) HandleCryptoDataPacket(object interface{}, addr net.Addr, data []byte, cbdata interface{}) (int, error) {
	log.Println(netpktname(data[0]), addr, len(data))
	ptype, pubkey, nonce, plain, err := this.dhto.Unpacket(data)
	gopp.ErrPrint(err)
	log.Println(ptype, plain[0], PACKET_ID_MESSAGE, len(plain), string(plain[1:]), pubkey == nil, nonce == nil)

	return 0, nil
}

func (this *DHTApi) SendData(data string, pubkey string) {
	plainpkt := gopp.NewBufferZero()
	plainpkt.WriteByte(byte(PACKET_ID_MESSAGE))
	plainpkt.Write([]byte(data))
	pubkeyo := NewCryptoKeyFromHex(pubkey)
	shrkey := this.dhto.GetSharedKeySent(pubkeyo)
	encpkt, err := this.dhto.CreatePacket(this.SelfPubkey, shrkey, NET_PACKET_CRYPTO_DATA, plainpkt.Bytes())
	gopp.ErrPrint(err)

	this.sendPacketToFriend(pubkeyo, encpkt)
}

func (this *DHTApi) sendPacketToFriend(pubkey *CryptoKey, pkt []byte) {
	var addr net.Addr
	{
		itemi := this.dhto.FriendsList.GetByKey(pubkey.BinStr())
		if itemi == nil {
			log.Println("can not find friend", pubkey.ToHex()[:20])
		} else {
			itemi2 := itemi.(*DHTFriend).ClientList.GetByKey(pubkey.BinStr())
			if itemi2 == nil {
				log.Println("can not find friend info", pubkey.ToHex()[:20])
			} else {
				clidat := itemi2.(*NodeFormat)
				log.Println("found friend:", clidat.Addr, pubkey.ToHex()[:20])
				addr = clidat.Addr
			}
		}
	}
	{
		itemi := this.dhto.CloseClientList.GetByKey(pubkey.BinStr())
		if itemi == nil {
			log.Println("can not find friend from closest", pubkey.ToHex()[:20])
		}
	}

	if addr != nil {
		if rand.Intn(32)%2 == 1 {
		}
	}

	if true {
		ipo := net.ParseIP("10.0.0.32")
		addru := &net.UDPAddr{}
		addru.IP = ipo
		addru.Port = 33345
		addr = addru
	}

	if addr != nil {
		wn, err := this.dhto.Neto.WriteTo(pkt, addr)
		gopp.ErrPrint(err, wn, addr)
		log.Println("sent data:", addr, wn, pubkey.ToHex()[:20])
	}

	if false {
		this.dhto.Pingo.SendPingRequest(addr, pubkey)
	}
}

func (this *DHTApi) BootstrapFromAddr(addr string, pubkey string) {
	this.dhto.BootstrapFromAddr(addr, pubkey)
}
