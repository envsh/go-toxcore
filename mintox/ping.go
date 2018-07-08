package mintox

import (
	"encoding/binary"
	"gopp"
	"log"
	"math/rand"
	"net"
	"time"
)

type Ping struct {
	dhto       *DHT
	neto       *NetworkCore
	Pubkey     *CryptoKey
	ToPing     []*NodeFormat
	LastToPing time.Time
}

func NewPing(dhto *DHT, pk *CryptoKey, neto *NetworkCore) *Ping {
	this := &Ping{dhto: dhto, Pubkey: pk, neto: neto}

	neto.RegisterHandle(NET_PACKET_PING_REQUEST, this.HandlePingRequest, this)
	neto.RegisterHandle(NET_PACKET_PING_RESPONSE, this.HandlePingResponse, this)
	return this
}

func (this *Ping) HandlePingRequest(object interface{}, source net.Addr, packet []byte, cbdata interface{}) (int, error) {
	pubkey := NewCryptoKey(packet[1 : 1+PUBLIC_KEY_SIZE])
	nonce := NewCBNonce(packet[1+PUBLIC_KEY_SIZE : 1+PUBLIC_KEY_SIZE+NONCE_SIZE])
	shrkey := this.dhto.GetSharedKeyRecv(pubkey)
	plain, err := DecryptDataSymmetric(shrkey, nonce, packet[1+PUBLIC_KEY_SIZE+NONCE_SIZE:])
	gopp.ErrPrint(err)

	var pingid uint64
	err = binary.Read(gopp.NewBufferBuf(plain[1:]), binary.BigEndian, &pingid)
	gopp.ErrPrint(err)
	log.Println("pingid:", pingid)

	this.SendPingResponse(source, pubkey, pingid, shrkey)
	return 0, nil
}

func (this *Ping) HandlePingResponse(object interface{}, source net.Addr, packet []byte, cbdata interface{}) (int, error) {
	log.Println("ping response from:", source, len(packet))
	return 0, nil
}

func (this *Ping) SendPingResponse(source net.Addr, pubkey *CryptoKey, pingid uint64, shrkey *CryptoKey) {
	if pubkey.Equal(this.dhto.SelfPubkey.Bytes()) {
		log.Println("come from self ping???")
		return
	}
	plain := gopp.NewBufferZero()
	plain.WriteByte(byte(NET_PACKET_PING_RESPONSE))
	binary.Write(plain, binary.BigEndian, pingid)

	nonce := CBRandomNonce()
	encrypted, err := EncryptDataSymmetric(shrkey, nonce, plain.Bytes())
	gopp.ErrPrint(err)

	pkt := gopp.NewBufferZero()
	pkt.WriteByte(byte(NET_PACKET_PING_RESPONSE))
	pkt.Write(this.dhto.SelfPubkey.Bytes())
	pkt.Write(nonce.Bytes())
	pkt.Write(encrypted)

	_, err = this.dhto.Neto.WriteTo(pkt.Bytes(), source)
	gopp.ErrPrint(err, pingid)
	log.Println("ping response to:", source, pkt.Len())
}

func (this *Ping) SendPingRequest(addr net.Addr, pubkey *CryptoKey) {
	if pubkey.Equal(this.dhto.SelfPubkey.Bytes()) {
		log.Println("to self ping????")
		return
	}
	plnpkt := gopp.NewBufferZero()
	plnpkt.WriteByte(byte(NET_PACKET_PING_REQUEST))
	pingid := rand.Uint64()
	gopp.CmpAndSwapN(&pingid, 0, 1)
	binary.Write(plnpkt, binary.BigEndian, pingid)

	nonce := CBRandomNonce()
	shrkey := this.dhto.GetSharedKeySent(pubkey)
	encpkt, err := EncryptDataSymmetric(shrkey, nonce, plnpkt.Bytes())
	gopp.ErrPrint(err)

	pingpkt := gopp.NewBufferZero()
	pingpkt.WriteByte(byte(NET_PACKET_PING_REQUEST))
	pingpkt.Write(this.dhto.SelfPubkey.Bytes())
	pingpkt.Write(nonce.Bytes())
	pingpkt.Write(encpkt)

	_, err = this.dhto.Neto.WriteTo(pingpkt.Bytes(), addr)
	gopp.ErrPrint(err)
}

/////
func IsTimeout4Now(oldtime time.Time, timeout int) bool {
	return int(time.Since(oldtime).Seconds()) > timeout
}
func IsTimeout4Time(newtime, oldtime time.Time, timeout int) bool {
	return int(newtime.Sub(oldtime).Seconds()) > timeout
}
