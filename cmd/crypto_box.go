package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"gopp"
	"strings"
	"unsafe"

	"github.com/GoKillers/libsodium-go/cryptobox"
	"github.com/GoKillers/libsodium-go/randombytes"
	cbsupport "github.com/GoKillers/libsodium-go/support"
)

const PUBLIC_KEY_SIZE = 32
const SECRET_KEY_SIZE = 32
const SHARED_KEY_SIZE = 32
const NONCE_SIZE = 24
const MAC_SIZE = 16
const SHA512_SIZE = 64

type byteArray []byte

func (this *byteArray) Bytes() []byte  { return *this }
func (this *byteArray) BinStr() string { return string(*this) }
func (this *byteArray) ToHex() string  { return strings.ToUpper(hex.EncodeToString(*this)) }
func (this *byteArray) Len() int       { return len(*this) }
func (this *byteArray) Equal(that []byte) bool {
	return len(*this) == len(that) && bytes.Compare(*this, that) == 0
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
	seckey, pubkey, iret := cryptobox.CryptoBoxKeyPair()
	return NewCryptoKey(pubkey), NewCryptoKey(seckey), cbiret2err(iret)
}

func cbiret2err(iret int) error {
	if iret != 0 {
		return fmt.Errorf("cryptobox error: %d", iret)
	}
	return nil
}

func CBBeforeNm(pk *CryptoKey, sk *CryptoKey) (*CryptoKey, error) {
	keybin, iret := cryptobox.CryptoBoxBeforeNm(pk.Bytes(), sk.Bytes())
	return NewCryptoKey(keybin), cbiret2err(iret)
}

func CBAfterNm(seckey *CryptoKey, nonce *CBNonce, plain []byte) (encrypted []byte, err error) {
	encrypted, iret := cryptobox.CryptoBoxAfterNm(plain, nonce.Bytes(), seckey.Bytes())
	return encrypted, cbiret2err(iret)
}

func CBOpenAfterNm(seckey *CryptoKey, nonce *CBNonce, encrypted []byte) (plain []byte, err error) {
	plain, iret := cryptobox.CryptoBoxOpenAfterNm(encrypted, nonce.Bytes(), seckey.Bytes())
	return plain, cbiret2err(iret)
}

type _CBNonce [NONCE_SIZE]byte
type CBNonce struct {
	byteArray
	*_CBNonce
}

func CBRandomNonce() *CBNonce {
	buf := randombytes.RandomBytes(cryptobox.CryptoBoxNonceBytes())
	return &CBNonce{buf, (*_CBNonce)(unsafe.Pointer(&buf[0]))}
}

func NewCBNonce(nonce []byte) *CBNonce {
	cbsupport.CheckSize(nonce, cryptobox.CryptoBoxNonceBytes(), "Invalid nonce size")
	return &CBNonce{nonce, (*_CBNonce)(unsafe.Pointer(&nonce[0]))}
}
