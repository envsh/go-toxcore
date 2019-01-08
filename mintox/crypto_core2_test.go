package mintox

import (
	"bytes"
	crypto_rand "crypto/rand"
	"log"
	"testing"

	"github.com/kevinburke/nacl"
	"github.com/kevinburke/nacl/box"
)

func TestC20(t *testing.T) {
	senderPublicKey, senderPrivateKey, err := box.GenerateKey(crypto_rand.Reader)
	if err != nil {
		panic(err)
	}

	recipientPublicKey, recipientPrivateKey, err := box.GenerateKey(crypto_rand.Reader)
	if err != nil {
		panic(err)
	}

	// The shared key can be used to speed up processing when using the same
	// pair of keys repeatedly.
	sharedEncryptKey := box.Precompute(recipientPublicKey, senderPrivateKey)

	// You must use a different nonce for each message you encrypt with the
	// same key. Since the nonce here is 192 bits long, a random value
	// provides a sufficiently small probability of repeats.
	nonce := nacl.NewNonce()

	msg := []byte("A fellow of infinite jest, of most excellent fancy")
	// This encrypts msg and appends the result to the nonce.
	encrypted := box.SealAfterPrecomputation(nil, msg, nonce, sharedEncryptKey)
	log.Println(len(msg), len(encrypted))

	// The shared key can be used to speed up processing when using the same
	// pair of keys repeatedly.
	sharedDecryptKey := box.Precompute(senderPublicKey, recipientPrivateKey)

	// The recipient can decrypt the message using the shared key. When you
	// decrypt, you must use the same nonce you used to encrypt the message.
	// One way to achieve this is to store the nonce alongside the encrypted
	// message. Above, we stored the nonce in the first 24 bytes of the
	// encrypted text.
	var decryptNonce [24]byte
	// copy(decryptNonce[:], encrypted[:24])
	copy(decryptNonce[:], nonce[:])
	decrypted, ok := box.OpenAfterPrecomputation(nil, encrypted, &decryptNonce, sharedDecryptKey)
	if !ok {
		panic("decryption error")
	}
	log.Println(len(decrypted), string(decrypted))

	// use our wrapper func to encrypt
	encrypted2, err := EncryptDataSymmetric(NewCryptoKey(naclkey2byte(sharedEncryptKey)),
		NewCBNonce(naclnonce2byte(nonce)), msg)
	log.Println(len(encrypted2), err)

	// decrypt our encrypted use origin nacl box
	decrypted2, ok := box.OpenAfterPrecomputation(nil, encrypted2, &decryptNonce, sharedDecryptKey)
	if !ok {
		t.Errorf("decrypt2 error")
	}
	log.Println(len(decrypted2))

	// decrypt our encrypted use our wrapper func
	decrypted3, err := DecryptDataSymmetric(NewCryptoKey(naclkey2byte(sharedDecryptKey)),
		NewCBNonce(naclnonce2byte(nonce)), encrypted2)
	log.Println(len(decrypted3), err, "cmp", bytes.Compare(decrypted3, msg))
}
