package mintox

/*
#cgo LDFLAGS: -lsodium

#include <stdint.h>
#include <sodium.h>
*/
import "C"
import (
	"fmt"
	"gopp"
	"unsafe"

	// pure go: github.com/kevinburke/nacl
	// pure go: github.com/ArteMisc/libgodium
	// fork of GoKillers/libsodium-go: github.com/jamesruan/sodium
	"github.com/GoKillers/libsodium-go/cryptobox"
	"github.com/GoKillers/libsodium-go/randombytes"
	"github.com/pkg/errors"
)

func NewCBKeyPair1() (pk *CryptoKey, sk *CryptoKey, err error) {
	// note: order is: sk, pk from under call, but return order is: pk, sk
	seckey, pubkey, iret := cryptobox.CryptoBoxKeyPair()
	return NewCryptoKey(pubkey), NewCryptoKey(seckey), cbiret2err1(iret)
}

func CBRandomNonce1() *CBNonce {
	buf := randombytes.RandomBytes(cryptobox.CryptoBoxNonceBytes())
	return &CBNonce{buf, (*_CBNonce)(unsafe.Pointer(&buf[0]))}
}

func (this *CBNonce) Incr1() {
	gopp.BytesReverse(this.byteArray)
	p := (*C.uint8_t)(unsafe.Pointer(&this.byteArray[0]))
	C.sodium_increment(p, C.size_t(len(this.byteArray)))
	gopp.BytesReverse(this.byteArray)
}

func (this *CBNonce) Incrn1(n int) {
	gopp.BytesReverse(this.byteArray)
	p := (*C.uint8_t)(unsafe.Pointer(&this.byteArray[0]))
	for i := 0; i < n; i++ {
		C.sodium_increment(p, C.size_t(len(this.byteArray)))
	}
	gopp.BytesReverse(this.byteArray)
}

func CBRandomBytes1(n int) []byte { return randombytes.RandomBytes(n) }

func CBDerivePubkey1(seckey *CryptoKey) (pubkey *CryptoKey) {
	buf := randombytes.RandomBytes(cryptobox.CryptoBoxPublicKeyBytes())
	C.crypto_scalarmult_curve25519_base((*C.uint8_t)(unsafe.Pointer(&buf[0])),
		(*C.uint8_t)(unsafe.Pointer(&seckey.byteArray[0])))
	pubkey = NewCryptoKey(buf)
	return
}

func cbiret2err1(iret int) error {
	if iret != 0 {
		return fmt.Errorf("cryptobox error: %d", iret)
	}
	return nil
}

func CBBeforeNm1(pk *CryptoKey, sk *CryptoKey) (*CryptoKey, error) {
	keybin, iret := cryptobox.CryptoBoxBeforeNm(pk.Bytes(), sk.Bytes())
	return NewCryptoKey(keybin), cbiret2err1(iret)
}

func CBAfterNm1(seckey *CryptoKey, nonce *CBNonce, plain []byte) (encrypted []byte, err error) {
	encrypted, iret := cryptobox.CryptoBoxAfterNm(plain, nonce.Bytes(), seckey.Bytes())
	return encrypted, cbiret2err1(iret)
}

func CBOpenAfterNm1(seckey *CryptoKey, nonce *CBNonce, encrypted []byte) (plain []byte, err error) {
	plain, iret := cryptobox.CryptoBoxOpenAfterNm(encrypted, nonce.Bytes(), seckey.Bytes())
	return plain, cbiret2err1(iret)
}

/////
func EncryptDataSymmetric1(seckey *CryptoKey, nonce *CBNonce, plain []byte) (encrypted []byte, err error) {
	temp_plain := make([]byte, len(plain)+cryptobox.CryptoBoxZeroBytes())
	n := copy(temp_plain[cryptobox.CryptoBoxZeroBytes():], plain)
	gopp.Assert(n == len(plain), "copy error", n, len(plain))

	encrypted, err = CBAfterNm1(seckey, nonce, temp_plain)
	if err != nil {
		err = errors.Wrap(err, "")
		return
	}

	encrypted = encrypted[cryptobox.CryptoBoxBoxZeroBytes():]
	gopp.Assert(len(encrypted) == len(plain)+cryptobox.CryptoBoxMacBytes(),
		"size error:", len(encrypted), len(plain))
	return
}

func DecryptDataSymmetric1(seckey *CryptoKey, nonce *CBNonce, encrypted []byte) (plain []byte, err error) {
	temp_encrypted := make([]byte, len(encrypted)+cryptobox.CryptoBoxBoxZeroBytes())
	copy(temp_encrypted[cryptobox.CryptoBoxBoxZeroBytes():], encrypted)

	plain, err = CBOpenAfterNm1(seckey, nonce, temp_encrypted)
	gopp.ErrPrint(err, len(plain), len(encrypted))
	plain = plain[cryptobox.CryptoBoxZeroBytes():]
	gopp.Assert(len(plain) == len(encrypted)-cryptobox.CryptoBoxMacBytes(),
		"size error:", len(plain), len(encrypted))
	if err != nil {
		err = errors.Wrap(err, "")
	}
	return
}
