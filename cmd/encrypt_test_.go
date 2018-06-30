package main

import (
	"encoding/hex"
	"gopp"
	"log"

	"github.com/GoKillers/libsodium-go/cryptobox"
	"github.com/GoKillers/libsodium-go/randombytes"
)

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
