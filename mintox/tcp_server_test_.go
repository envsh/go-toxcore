package mintox

import (
	"crypto/sha256"
	"fmt"
	"gopp"
	"log"
	"time"
)

var test_node_sks = []*CryptoKey{}

const test_node_count = 16

func init() {
	for i := 0; i < test_node_count; i++ {
		d := sha256.Sum256([]byte(fmt.Sprintf("testsk%d", i)))
		sk := NewCryptoKey(d[:])
		// pk, _ := CBDerivePubkey(sk)
		test_node_sks = append(test_node_sks, sk)
	}
}

func test_tcp_server() {
	go test_tcp_server_run_server()

	mkclient := func(cno int) *TCPClient {
		selfsk := test_node_sks[gopp.IfElseInt(cno == 0, 0, 1)]
		selfpk := CBDerivePubkey(selfsk)
		peersk := test_node_sks[gopp.IfElseInt(cno == 0, 1, 0)]
		peerpk := CBDerivePubkey(peersk)
		log.Println("tstcli:", cno, selfpk.ToHex20(), "=>", peerpk.ToHex20())
		cli := NewTCPClientRaw("127.0.0.1:54433", echo_serv_pubkey_str, selfpk.ToHex(), selfsk.ToHex())
		log.Println("cli is nil", cno, cli == nil)
		cli.OnConfirmed = func() {
			log.Println("vconnect peer:", cno, peerpk.ToHex20())
			cli.ConnectPeer(peerpk.ToHex())
		}
		cli.RoutingResponseFunc = func(obj Object, connid uint8, pubkey *CryptoKey) {
			sntdat := gopp.RandomStringPrintable(123)
			log.Println(connid, pubkey.ToHex20(), sntdat[:30])
			_, err := cli.SendDataPacket(connid, []byte(sntdat), false)
			gopp.ErrPrint(err)
		}
		cli.RoutingDataFunc = func(obj Object, num uint32, connid uint8, data []byte, cbdata Object) {
			log.Printf("cli%d on connid %d recv data %d[%s] from %s\n",
				cno, connid, len(data), string(data)[:30], peerpk.ToHex20())
		}
		return cli
	}

	go func() {
		time.Sleep(1 * time.Second)
		cli0 := mkclient(0)
		time.Sleep(2 * time.Second)
		cli1 := mkclient(1)
		_, _ = cli0, cli1
		time.Sleep(3 * time.Second)
		err := cli1.Close()
		gopp.ErrPrint(err, "cli1")
		time.Sleep(1 * time.Second)
		err = cli0.Close()
		gopp.ErrPrint(err, "cli0")
		select {}
	}()
}

func test_tcp_server_run_server() {
	seckey := NewCryptoKeyFromHex(echo_serv_seckey_str)
	tcpsrv := NewTCPServer([]uint16{54433}, seckey, nil)
	tcpsrv.Start()

	select {}
}
