package main

import (
	"gopp"
	"log"
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
				log.Println("find friend:", clidat.Addr, pubkey.ToHex()[:20])
			}
		}
	}
	{
		itemi := this.dhto.CloseClientList.GetByKey(pubkey.BinStr())
		if itemi == nil {
			log.Println("can not find friend from closest", pubkey.ToHex()[:20])
		}
	}

	ipo := net.ParseIP("10.0.0.32")
	addr := &net.UDPAddr{}
	addr.IP = ipo
	addr.Port = 33345

	if false {
		wn, err := this.dhto.Neto.WriteTo(pkt, addr)
		gopp.ErrPrint(err, wn, addr)
	}

	if false {
		this.dhto.Pingo.SendPingRequest(addr, pubkey)
	}
}

func (this *DHTApi) BootstrapFromAddr(addr string, pubkey string) {
	this.dhto.BootstrapFromAddr(addr, pubkey)
}
