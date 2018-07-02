package main

import (
	"flag"
	"log"
	"time"
)

var mode = "srv" // cli

func init() {
	flag.StringVar(&mode, "mode", mode, "echo srv or cli")
}

func main() {
	flag.Parse()

	if mode == "srv" {
		go run_server()
	} else if mode == "cli" {
		go run_client()
	}

	log.Println(mode, "main selecting...")
	/*
		c := NewTCPClient()
		c.DoHandshake()
		log.Println(&c)
		// testencdec()
		// testencdec2()
	*/
	select {}
}

var echo_serv_pubkey_str = "DC783F03439117AE7CE8AC3DC956C4A4CB64AC02169CDFE12709BB55DE950102"

func run_server() {
	self_pubkey, self_seckey, _ := NewCBKeyPair()
	self_pubkey = NewCryptoKeyFromHex(echo_serv_pubkey_str)
	self_seckey = NewCryptoKeyFromHex("F964C868842495EFD1FF5B5A7B043A40DCF3242547D174ECB24A2BC64DC2E1F8")
	log.Println(mode, "pubkey:", self_pubkey.ToHex())
	log.Println(mode, "seckey:", self_seckey.ToHex())

	dht := NewDHT()
	dht.SetKeyPair(self_pubkey, self_seckey)
	dht.AddFriend(NewCryptoKeyFromHex(echo_cli_pubkey_str), nil, nil, 0)
	dht.BootstrapFromAddr(bs_addr, bs_pubkey_str)
}

var echo_cli_pubkey_str = "6C98FA6F2FE3EA1ECE629D9B4AA13BF40043B7B7E9ADF1A2D0F1C4D617191D34"

func run_client() {
	pubkey := echo_cli_pubkey_str
	seckey := "E58BE72DEF39824661CF1212F22C77A0D4CC055F43610C75EDC8CAB860A54E9D"

	cliapi := NewDHTApi(pubkey, seckey)
	cliapi.BootstrapFromAddr(bs_addr, bs_pubkey_str)
	cliapi.AddFriend(echo_serv_pubkey_str)
	// cliapi.AddFriend("C365730A9329EB8162CE841256D2FEE533728C026A8FB6DADFD3A84538819403")

	for {
		time.Sleep(5 * time.Second)
		cliapi.SendData("hello123", echo_serv_pubkey_str)
	}
}

var bs_pubkey_str = "2F0683A8AA6F29B2E043E5423073C7F89F662D3777FE85615963E97EF8AF2803"
var bs_addr = "10.0.0.7:33345"

// var bs_pubkey_str = "F404ABAA1C99A9D37D61AB54898F56793E1DEF8BD46B1038B9D822E8460FAB67"
// var bs_addr = "67.215.253.85:33445"

// var bs_pubkey_str = "0FB96EEBFB1650DDB52E70CF773DDFCABE25A95CC3BB50FC251082E4B63EF82A"
// var bs_addr = "104.223.122.15:33445"
