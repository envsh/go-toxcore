package mintox

/*
#cgo LDFLAGS: -lsodium

#include <stdint.h>
#include <sodium.h>
*/
import "C"
import (
	"bytes"
	"encoding/hex"
	"fmt"
	"gopp"
	"strings"
	"unsafe"

	// pure go: github.com/kevinburke/nacl
	// pure go: github.com/ArteMisc/libgodium
	// fork of GoKillers/libsodium-go: github.com/jamesruan/sodium
	"github.com/GoKillers/libsodium-go/cryptobox"
	"github.com/GoKillers/libsodium-go/randombytes"
	cbsupport "github.com/GoKillers/libsodium-go/support"
	"github.com/pkg/errors"
)

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
	seckey, pubkey, iret := cryptobox.CryptoBoxKeyPair()
	return NewCryptoKey(pubkey), NewCryptoKey(seckey), cbiret2err(iret)
}

func (this *CryptoKey) Dup() *CryptoKey { return NewCryptoKey(this.Bytes()) }

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
func (this *CBNonce) Incr() {
	gopp.BytesReverse(this.byteArray)
	p := (*C.uint8_t)(unsafe.Pointer(&this.byteArray[0]))
	C.sodium_increment(p, C.size_t(len(this.byteArray)))
	gopp.BytesReverse(this.byteArray)
}

func (this *CBNonce) Incrn(n int) {
	gopp.BytesReverse(this.byteArray)
	p := (*C.uint8_t)(unsafe.Pointer(&this.byteArray[0]))
	for i := 0; i < n; i++ {
		C.sodium_increment(p, C.size_t(len(this.byteArray)))
	}
	gopp.BytesReverse(this.byteArray)
}

func CBRandomBytes(n int) []byte { return randombytes.RandomBytes(n) }

func CBDerivePubkey(seckey *CryptoKey) (pubkey *CryptoKey) {
	buf := randombytes.RandomBytes(cryptobox.CryptoBoxPublicKeyBytes())
	C.crypto_scalarmult_curve25519_base((*C.uint8_t)(unsafe.Pointer(&buf[0])),
		(*C.uint8_t)(unsafe.Pointer(&seckey.byteArray[0])))
	pubkey = NewCryptoKey(buf)
	return
}

/////
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
