package main

import "log"

var c *TCPClient

func test_tcp_client() {
	bsaddr, bspubkey := bsnodes[0], bsnodes[1]
	if mode == "srv" {
		c = NewTCPClient(bsaddr, bspubkey)
		c.SetKeyPair(echo_serv_pubkey_str, echo_serv_seckey_str)
		c.DoHandshake()
		c.ConnectPeer(echo_cli_pubkey_str)
		c.StartRead()
		log.Println(&c)
	} else {
		c = NewTCPClient(bsaddr, bspubkey)
		c.SetKeyPair(echo_cli_pubkey_str, echo_cli_seckey_str)
		c.DoHandshake()
		c.ConnectPeer(echo_serv_pubkey_str)
		c.StartRead()
		log.Println(&c)
	}
}

var bsnodes = []string{
	"104.223.122.15:33445", "0FB96EEBFB1650DDB52E70CF773DDFCABE25A95CC3BB50FC251082E4B63EF82A",
	"127.0.0.1:23456", "B114C64A74806079ADB30E579CD48D2593738F907A12FD7358A18B35BB1FC025",
	"10.0.0.7:33345", "2F0683A8AA6F29B2E043E5423073C7F89F662D3777FE85615963E97EF8AF2803",
	"67.215.253.85:33445", "F404ABAA1C99A9D37D61AB54898F56793E1DEF8BD46B1038B9D822E8460FAB67",
	"104.223.122.15:33445", "0FB96EEBFB1650DDB52E70CF773DDFCABE25A95CC3BB50FC251082E4B63EF82A",
}
