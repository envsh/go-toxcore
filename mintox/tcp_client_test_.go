package mintox

import (
	"gopp"
	"log"
	"math/rand"
	"time"
)

var c *TCPClient

func test_tcp_client() {
	bsaddr, bspubkey := bsnodes[0], bsnodes[1]
	// bsaddr, bspubkey = bsnodes[2], bsnodes[3]
	if mode == "srv" {
		c = NewTCPClientRaw(bsaddr, bspubkey, echo_serv_pubkey_str, echo_serv_seckey_str)
		c.OnConfirmed = func() { c.ConnectPeer(echo_cli_pubkey_str) }
		log.Println(&c)
	} else if mode == "cli" {
		c = NewTCPClientRaw(bsaddr, bspubkey, echo_cli_pubkey_str, echo_cli_seckey_str)
		c.OnConfirmed = func() { c.ConnectPeer(echo_serv_pubkey_str) }

		c.RoutingStatusFunc = func(object Object, number uint32, connection_id uint8, status uint8) {
			go func() {
				for i := 0; i < 1000000; i++ {
					data := []byte(gopp.RandomStringPrintable(int(rand.Uint32()%2000) + 1))
					time.Sleep(5 * time.Millisecond)
					c.SendDataPacket(connection_id, data, false)
					// break
				}
				// speed send 100KB/s => 90KB/s
				// speed send 200KB/s => 160KB/s
				// speed send 333KB/s => 180KB/s->150KB/s???
				// speed send 500KB/s => 180KB/s???
				// speed send 1000KB/s => KB/s
				// max speed 150KB/s is stable, with send speed at 200KB/s
			}()
		}
		log.Println(&c)
	} else {
		log.Println("Invalid mode:", mode)
	}
}

var bsnodes = []string{
	"104.223.122.15:33445", "0FB96EEBFB1650DDB52E70CF773DDFCABE25A95CC3BB50FC251082E4B63EF82A",
	"113.206.157.102:33445", "AF66C5FFAA6CA67FB8E287A5B1D8581C15B446E12BF330963EF29E3AFB692918",
	// "127.0.0.1:23456", "B114C64A74806079ADB30E579CD48D2593738F907A12FD7358A18B35BB1FC025",
	"10.0.0.7:33345", "2F0683A8AA6F29B2E043E5423073C7F89F662D3777FE85615963E97EF8AF2803",
	"67.215.253.85:33445", "F404ABAA1C99A9D37D61AB54898F56793E1DEF8BD46B1038B9D822E8460FAB67",
	"198.98.51.198:33445", "1D5A5F2F5D6233058BF0259B09622FB40B482E4FA0931EB8FD3AB8E7BF7DAF6F",
}
