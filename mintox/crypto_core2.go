package mintox

import (
	"crypto/rand"
	"fmt"
	"gopp"
	"unsafe"

	"github.com/kevinburke/nacl"
	"github.com/kevinburke/nacl/box"
	naclrdbytes "github.com/kevinburke/nacl/randombytes"
	"github.com/kevinburke/nacl/scalarmult"
	"github.com/pkg/errors"

	//
	_ "github.com/ianlancetaylor/cgosymbolizer"
)

func naclkey2byte(k nacl.Key) []byte {
	return (*(*[nacl.KeySize]byte)(k))[:]
}
func byte2naclkey(buf []byte) nacl.Key {
	return (*[scalarmult.Size]byte)(unsafe.Pointer(&buf[0]))
}

func NewCBKeyPair2() (pk *CryptoKey, sk *CryptoKey, err error) {
	// note: order is: sk, pk from under call, but return order is: pk, sk
	pubkey, seckey, err := box.GenerateKey(rand.Reader)
	return NewCryptoKey(naclkey2byte(pubkey)), NewCryptoKey(naclkey2byte(seckey)), err
}

func CBDerivePubkey2(seckey *CryptoKey) (pubkey *CryptoKey) {
	keyo := scalarmult.Base(byte2naclkey(seckey.Bytes()))
	pubkey = NewCryptoKey(naclkey2byte(keyo))
	return
}

func naclnonce2byte(n nacl.Nonce) []byte {
	return (*(*[nacl.NonceSize]byte)(n))[:]
}
func byte2naclnonce(buf []byte) nacl.Nonce {
	return (*[nacl.NonceSize]byte)(unsafe.Pointer(&buf[0]))
}

func CBRandomNonce2() *CBNonce {
	nonce := nacl.NewNonce()
	buf := naclnonce2byte(nonce)
	return &CBNonce{buf, (*_CBNonce)(unsafe.Pointer(&buf[0]))}
}

func (this *CBNonce) Incr2() { this.Incr2le() }
func (this *CBNonce) Incr2le() {
	blen := this.Len()
	c := uint16(1)
	for i := blen - 1; i >= 0; i-- {
		c += uint16(this.byteArray[i])
		this.byteArray[i] = byte(c)
		c >>= 8
	}
}
func (this *CBNonce) Incr2be() {
	blen := this.Len()
	c := uint16(1)
	for i := 0; i < blen; i++ {
		c += uint16(this.byteArray[i])
		this.byteArray[i] = byte(c)
		c >>= 8
	}
}

func (this *CBNonce) Incrn2(n int) {
	for i := 0; i < n; i++ {
		this.Incr2()
	}
}

func CBRandomBytes2(n int) []byte {
	buf := make([]byte, n)
	naclrdbytes.MustRead(buf)
	return buf
}

func cbiret2err2(iret int) error {
	if iret != 0 {
		return fmt.Errorf("naclbox error: %d", iret)
	}
	return nil
}

func CBBeforeNm2(pk *CryptoKey, sk *CryptoKey) (*CryptoKey, error) {
	tmpkey := box.Precompute(byte2naclkey(pk.Bytes()), byte2naclkey(sk.Bytes()))
	return NewCryptoKey(naclkey2byte(tmpkey)), cbiret2err2(0)
}

func CBAfterNm2(seckey *CryptoKey, nonce *CBNonce, plain []byte) (encrypted []byte, err error) {
	encrypted = box.SealAfterPrecomputation(nil, plain, byte2naclnonce(nonce.Bytes()), byte2naclkey(seckey.Bytes()))
	return encrypted, cbiret2err2(0)
}

func CBOpenAfterNm2(seckey *CryptoKey, nonce *CBNonce, encrypted []byte) (plain []byte, err error) {
	plain, bret := box.OpenAfterPrecomputation(nil, encrypted, byte2naclnonce(nonce.Bytes()), byte2naclkey(seckey.Bytes()))
	return plain, cbiret2err2(gopp.IfElseInt(bret, 0, 1))
}

/////
func EncryptDataSymmetric2(seckey *CryptoKey, nonce *CBNonce, plain []byte) (encrypted []byte, err error) {
	encrypted, err = CBAfterNm2(seckey, nonce, plain)
	if err != nil {
		err = errors.Wrap(err, "")
		return
	}

	gopp.Assert(len(encrypted) == len(plain)+MAC_SIZE,
		"size error:", len(encrypted), len(plain))
	return
}

func DecryptDataSymmetric2(seckey *CryptoKey, nonce *CBNonce, encrypted []byte) (plain []byte, err error) {
	plain, err = CBOpenAfterNm2(seckey, nonce, encrypted)
	gopp.ErrPrint(err, len(plain), len(encrypted))
	// plain = plain[:]
	gopp.Assert(len(plain) == len(encrypted)-MAC_SIZE,
		"size error:", len(plain), len(encrypted))
	if err != nil {
		err = errors.Wrap(err, "")
	}
	return
}
