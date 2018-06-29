package main

import (
	"encoding/binary"
	"encoding/hex"
	"gopp"
	"io"
	"log"
	"math/rand"
	"net"
	"sync/atomic"

	"github.com/GoKillers/libsodium-go/cryptobox"
	"github.com/GoKillers/libsodium-go/randombytes"
)

func main() {
	c := NewTCPClient()
	log.Println(&c)
	// testencdec()
	// testencdec2()
}

type TCPClient struct {
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
}

func NewTCPClient() *TCPClient {
	this := &TCPClient{}

	var err error
	//
	serv_pubkey_str := "0FB96EEBFB1650DDB52E70CF773DDFCABE25A95CC3BB50FC251082E4B63EF82A"
	serv_addr := "104.223.122.15:33445"
	// self_pubkey_str := "ABB96EEBFB1650DDB52E70CF773DDFCABE25A95CC3BB50FC251082E4B63EF82A"
	// self_privkey_str := "CDB96EEBFB1650DDB52E70CF773DDFCABE25A95CC3BB50FC251082E4B63EF82A"
	this.serv_pubkey = NewCryptoKeyFromHex(serv_pubkey_str)
	// log.Println(len(serv_pubkey_str), this.serv_pubkey.Len(), this.serv_pubkey.ToHex() == serv_pubkey_str)
	// this.serv_pubkey, this.serv_seckey, err = NewCBKeyPair()
	this.self_pubkey, this.self_seckey, err = NewCBKeyPair()

	//
	this.shrkey, err = CBBeforeNm(this.serv_pubkey, this.self_seckey)
	gopp.ErrPrint(err)

	this.GenerateHandshake()
	log.Println("last_packet len:", len(this.last_packet))

	if true {
		c, err := net.Dial("tcp", serv_addr)
		gopp.ErrPrint(err)
		log.Println(c, c.RemoteAddr().String())

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

		/// first ping
		ping_plain := gopp.NewBufferZero()
		ping_plain.WriteByte(byte(TCP_PACKET_PING))
		ping_id := rand.Uint64()
		ping_id = gopp.IfElse(ping_id == 0, uint64(1), ping_id).(uint64)
		log.Println(ping_id)
		binary.Write(ping_plain, binary.BigEndian, ping_id)
		log.Println(ping_plain.Len())

		ping_encrypted, err := EncryptDataSymmetric(this.shrkey, this.sent_nonce, ping_plain.Bytes())
		gopp.ErrPrint(err)

		ping_pkt := gopp.NewBufferZero()
		binary.Write(ping_pkt, binary.BigEndian, uint16(len(ping_encrypted)))
		ping_pkt.Write(ping_encrypted)
		log.Println(ping_pkt.Len(), len(ping_encrypted))

		wn, err = c.Write(ping_pkt.Bytes())
		gopp.ErrPrint(err, wn)

		rdbuf = make([]byte, 300)
		rn, err = c.Read(rdbuf)
		gopp.ErrPrint(err, rn)
		rdbuf = rdbuf[:rn]
		gopp.NilPrint(err, "recv pong packet success", rn)
		pong_plain, err := DecryptDataSymmetric(this.shrkey, this.recv_nonce, rdbuf[2:])
		gopp.ErrPrint(err)
		gopp.NilPrint(err, "decrypt pong packet success", len(pong_plain))

		pong_pkt := gopp.NewBufferBuf(pong_plain)
		log.Println("pong type:", gopp.Retn(pong_pkt.ReadByte()))
		var pong_id uint64
		err = binary.Read(pong_pkt.BufAt(1), binary.BigEndian, &pong_id)
		gopp.ErrPrint(err)
		log.Println(pong_id == ping_id, pong_id, ping_id)
		atomic.CompareAndSwapUint64(&this.ping_id, pong_id, 0)

		go func() {
			rdbuf = make([]byte, 300)
			rn, err = c.Read(rdbuf)
			gopp.ErrPrint(err, rn)
			rdbuf = rdbuf[:rn]
		}()

		//
		log.Println("waiting...")
		select {}
	}

	return this
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

func (this *TCPClient) HandleHandshake() {

}

func EncryptDataSymmetric(seckey *CryptoKey, nonce *CBNonce, plain []byte) (encrypted []byte, err error) {
	temp_plain := make([]byte, len(plain)+cryptobox.CryptoBoxZeroBytes())
	n := copy(temp_plain[cryptobox.CryptoBoxZeroBytes():], plain)
	gopp.Assert(n == len(plain), "copy error", n, len(plain))

	encrypted, err = CBAfterNm(seckey, nonce, temp_plain)
	if err != nil {
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
	return
}

func testencdec() {
	serv_pubkey, serv_seckey, err := NewCBKeyPair()
	gopp.ErrPrint(err, serv_pubkey, serv_seckey)
	cli_pubkey, cli_seckey, err := NewCBKeyPair()
	gopp.ErrPrint(err, cli_pubkey, cli_seckey)

	// order of argument, need sk1, pk2
	serv_shrkey, err := CBBeforeNm(cli_pubkey, serv_seckey)
	gopp.ErrPrint(err, serv_shrkey)
	cli_shrkey, err := CBBeforeNm(serv_pubkey, cli_seckey)
	gopp.ErrPrint(err, cli_shrkey)
	log.Println(serv_shrkey == cli_shrkey)

	shrnonce := CBRandomNonce()

	plain := []byte("testok?")
	encrypted, err := EncryptDataSymmetric(cli_shrkey, shrnonce, plain)
	gopp.ErrPrint(err, len(encrypted))
	log.Println(len(encrypted))

	{
		plain_, err := DecryptDataSymmetric(serv_shrkey, shrnonce, encrypted)
		gopp.ErrPrint(err, len(plain_), string(plain_))
		log.Println(string(plain_))
	}

}

func testencdec2() {

	serv_seckey, serv_pubkey, iret := cryptobox.CryptoBoxKeyPair()
	// gopp.ErrPrint(err, serv_pubkey, serv_seckey)
	log.Println(iret)
	cli_seckey, cli_pubkey, iret := cryptobox.CryptoBoxKeyPair()
	// gopp.ErrPrint(err, cli_pubkey, cli_seckey)

	serv_shrkey, iret := cryptobox.CryptoBoxBeforeNm(cli_pubkey, serv_seckey)
	// gopp.ErrPrint(err, serv_shrkey)
	_ = serv_shrkey
	log.Println(hex.EncodeToString(serv_shrkey))
	cli_shrkey, iret := cryptobox.CryptoBoxBeforeNm(serv_pubkey, cli_seckey)
	// gopp.ErrPrint(err, cli_shrkey)
	log.Println(hex.EncodeToString(cli_shrkey))

	nonce := randombytes.RandomBytes(cryptobox.CryptoBoxNonceBytes())
	plain := []byte("testok?")
	log.Println(hex.EncodeToString(plain))

	temp_plain := append(make([]byte, cryptobox.CryptoBoxZeroBytes()), plain...)
	encrypted, iret := cryptobox.CryptoBoxAfterNm(temp_plain, nonce, cli_shrkey)
	log.Println(iret, hex.EncodeToString(encrypted))

	{
		temp_encrypted := append(make([]byte, cryptobox.CryptoBoxBoxZeroBytes()),
			encrypted[cryptobox.CryptoBoxBoxZeroBytes():]...)
		plain_, iret := cryptobox.CryptoBoxOpenAfterNm(temp_encrypted, nonce, serv_shrkey)
		log.Println(iret, len(plain_), hex.EncodeToString(plain_[cryptobox.CryptoBoxZeroBytes():]))
	}

}
