package mintox

import (
	"bytes"
	"encoding/hex"
	"gopp"
	"strings"
	"unsafe"

	// pure go: github.com/kevinburke/nacl
	// pure go: github.com/ArteMisc/libgodium
	// fork of GoKillers/libsodium-go: github.com/jamesruan/sodium

	cbsupport "github.com/GoKillers/libsodium-go/support"
)

// use this switch between pure go nacl and sodium cgo binding
const usepgocryptbox = true

const PUBLIC_KEY_SIZE = 32
const SECRET_KEY_SIZE = 32
const SHARED_KEY_SIZE = 32
const NONCE_SIZE = 24
const MAC_SIZE = 16
const SHA512_SIZE = 64
const SHA256_SIZE = SHA512_SIZE / 2

type byteArray []byte

type Byteable interface {
	Bytes() []byte
	Len() int
}

func (this *byteArray) Bytes() []byte   { return *this }
func (this *byteArray) BinStr() string  { return string(*this) }
func (this *byteArray) ToHex() string   { return strings.ToUpper(hex.EncodeToString(*this)) }
func (this *byteArray) ToHex20() string { return strings.ToUpper(hex.EncodeToString(*this))[:20] }
func (this *byteArray) Len() int        { return len(*this) }
func (this *byteArray) Equal(that []byte) bool {
	return len(*this) == len(that) && bytes.Compare(*this, that) == 0
}
func (this *byteArray) Equal2(that Byteable) bool {
	return len(*this) == that.Len() && bytes.Compare(*this, that.Bytes()) == 0
}

type _CryptoKey [PUBLIC_KEY_SIZE]byte
type CryptoKey struct {
	byteArray
	*_CryptoKey
}

func NewCryptoKeyFromHex(key string) *CryptoKey {
	keybin, err := hex.DecodeString(key)
	gopp.ErrPrint(err, key)
	gopp.Assert(len(keybin) == PUBLIC_KEY_SIZE, "Invalid key:", key)
	return &CryptoKey{keybin, (*_CryptoKey)(unsafe.Pointer(&keybin[0]))}
}

func NewCryptoKey(b []byte) *CryptoKey {
	gopp.Assert(len(b) == PUBLIC_KEY_SIZE, "Invalid key:", len(b))
	kv := make([]byte, PUBLIC_KEY_SIZE)
	copy(kv, b)
	kc := (*_CryptoKey)(unsafe.Pointer(&kv[0]))
	return &CryptoKey{kv, kc}
}

func NewCBKeyPair() (pk *CryptoKey, sk *CryptoKey, err error) {
	// note: order is: sk, pk from under call, but return order is: pk, sk
	if usepgocryptbox {
		return NewCBKeyPair2()
	} else {
		return NewCBKeyPair1()
	}
}

func (this *CryptoKey) Dup() *CryptoKey { return NewCryptoKey(this.Bytes()) }

type _CBNonce [NONCE_SIZE]byte
type CBNonce struct {
	byteArray
	*_CBNonce
}

func CBRandomNonce() *CBNonce {
	if usepgocryptbox {
		return CBRandomNonce2()
	} else {
		return CBRandomNonce1()
	}
}

func NewCBNonce(nonce []byte) *CBNonce {
	cbsupport.CheckSize(nonce, NONCE_SIZE, "Invalid nonce size")
	return &CBNonce{nonce, (*_CBNonce)(unsafe.Pointer(&nonce[0]))}
}
func (this *CBNonce) Incr() {
	if usepgocryptbox {
		this.Incr2()
	} else {
		this.Incr1()
	}
}

func (this *CBNonce) Incrn(n int) {
	if usepgocryptbox {
		this.Incrn2(n)
	} else {
		this.Incrn1(n)
	}
}

func CBRandomBytes(n int) []byte {
	if usepgocryptbox {
		return CBRandomBytes2(n)
	} else {
		return CBRandomBytes1(n)
	}
}

func CBDerivePubkey(seckey *CryptoKey) (pubkey *CryptoKey) {
	if usepgocryptbox {
		return CBDerivePubkey2(seckey)
	} else {
		return CBDerivePubkey1(seckey)
	}
}

func CBBeforeNm(pk *CryptoKey, sk *CryptoKey) (*CryptoKey, error) {
	if usepgocryptbox {
		return CBBeforeNm2(pk, sk)
	} else {
		return CBBeforeNm1(pk, sk)
	}
}

func CBAfterNm(seckey *CryptoKey, nonce *CBNonce, plain []byte) (encrypted []byte, err error) {
	if usepgocryptbox {
		return CBAfterNm2(seckey, nonce, plain)
	} else {
		return CBAfterNm1(seckey, nonce, plain)
	}
}

func CBOpenAfterNm(seckey *CryptoKey, nonce *CBNonce, encrypted []byte) (plain []byte, err error) {
	if usepgocryptbox {
		return CBOpenAfterNm2(seckey, nonce, encrypted)
	} else {
		return CBOpenAfterNm1(seckey, nonce, encrypted)
	}
}

/////
func EncryptDataSymmetric(seckey *CryptoKey, nonce *CBNonce, plain []byte) (encrypted []byte, err error) {
	if usepgocryptbox {
		return EncryptDataSymmetric2(seckey, nonce, plain)
	} else {
		return EncryptDataSymmetric1(seckey, nonce, plain)
	}
}

func DecryptDataSymmetric(seckey *CryptoKey, nonce *CBNonce, encrypted []byte) (plain []byte, err error) {
	if usepgocryptbox {
		return DecryptDataSymmetric2(seckey, nonce, encrypted)
	} else {
		return DecryptDataSymmetric1(seckey, nonce, encrypted)
	}
}
