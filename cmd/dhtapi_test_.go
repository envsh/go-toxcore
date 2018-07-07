package main

import (
	"flag"
	"log"
	"time"
)

var mode = "" // srv or cli

func init() {
	flag.StringVar(&mode, "mode", mode, "echo srv or cli")
}

func test_two_nodes() {
	if mode == "srv" {
		go run_server()
	} else if mode == "cli" {
		go run_client()
	}
}

var echo_serv_pubkey_str = "DC783F03439117AE7CE8AC3DC956C4A4CB64AC02169CDFE12709BB55DE950102"
var echo_serv_seckey_str = "F964C868842495EFD1FF5B5A7B043A40DCF3242547D174ECB24A2BC64DC2E1F8"

func run_server() {
	self_pubkey, self_seckey, _ := NewCBKeyPair()
	self_pubkey = NewCryptoKeyFromHex(echo_serv_pubkey_str)
	self_seckey = NewCryptoKeyFromHex(echo_serv_seckey_str)
	log.Println(mode, "pubkey:", self_pubkey.ToHex())
	log.Println(mode, "seckey:", self_seckey.ToHex())

	apio := NewDHTApi(self_pubkey.ToHex(), self_seckey.ToHex())
	apio.AddFriend(echo_cli_pubkey_str)
	apio.BootstrapFromAddr(bs_addr, bs_pubkey_str)
	/*
		dht := NewDHT()
		dht.SetKeyPair(self_pubkey, self_seckey)
		dht.AddFriend(NewCryptoKeyFromHex(echo_cli_pubkey_str), nil, nil, 0)
		dht.BootstrapFromAddr(bs_addr, bs_pubkey_str)
	*/
}

var echo_cli_pubkey_str = "6C98FA6F2FE3EA1ECE629D9B4AA13BF40043B7B7E9ADF1A2D0F1C4D617191D34"
var echo_cli_seckey_str = "E58BE72DEF39824661CF1212F22C77A0D4CC055F43610C75EDC8CAB860A54E9D"

func run_client() {
	pubkey := echo_cli_pubkey_str
	seckey := echo_cli_seckey_str

	cliapi := NewDHTApi(pubkey, seckey)
	cliapi.BootstrapFromAddr(bs_addr, bs_pubkey_str)
	cliapi.AddFriend(echo_serv_pubkey_str)
	// cliapi.AddFriend("C365730A9329EB8162CE841256D2FEE533728C026A8FB6DADFD3A84538819403")

	for {
		time.Sleep(5 * time.Second)
		cliapi.SendData("hello123", echo_serv_pubkey_str)
	}
}

var bs_pubkey_str = bsnodes[5]
var bs_addr = bsnodes[4]
