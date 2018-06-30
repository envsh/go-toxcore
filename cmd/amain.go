package main

import "log"

func main() {
	self_pubkey, self_seckey, _ := NewCBKeyPair()
	self_pubkey = NewCryptoKeyFromHex("DC783F03439117AE7CE8AC3DC956C4A4CB64AC02169CDFE12709BB55DE950102")
	self_seckey = NewCryptoKeyFromHex("F964C868842495EFD1FF5B5A7B043A40DCF3242547D174ECB24A2BC64DC2E1F8")
	log.Println("pubkey:", self_pubkey.ToHex())
	log.Println("seckey:", self_seckey.ToHex())

	dht := NewDHT()
	dht.SetKeyPair(self_pubkey, self_seckey)
	srvpk := NewCryptoKeyFromHex(serv_pubkey_str)
	dht.BootstrapFromAddr(serv_addr, srvpk)
	log.Println("hhh")
	/*
		c := NewTCPClient()
		c.DoHandshake()
		log.Println(&c)
		// testencdec()
		// testencdec2()
	*/
	select {}
}

var serv_pubkey_str = "2F0683A8AA6F29B2E043E5423073C7F89F662D3777FE85615963E97EF8AF2803"
var serv_addr = "10.0.0.7:33345"

// var serv_pubkey_str = "F404ABAA1C99A9D37D61AB54898F56793E1DEF8BD46B1038B9D822E8460FAB67"
// var serv_addr = "67.215.253.85:33445"

// var serv_pubkey_str = "0FB96EEBFB1650DDB52E70CF773DDFCABE25A95CC3BB50FC251082E4B63EF82A"
// var serv_addr = "104.223.122.15:33445"
