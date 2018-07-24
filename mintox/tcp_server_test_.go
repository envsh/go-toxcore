package mintox

import (
	"gopp"
	"log"
	"time"
)

func test_tcp_server() {
	go test_run_tcp_server()
	go func() {
		time.Sleep(1 * time.Second)
		cli := NewTCPClientRaw("127.0.0.1:54433", echo_serv_pubkey_str, echo_cli_pubkey_str, echo_cli_seckey_str)
		log.Println(cli == nil)
		cli.OnConfirmed = func() {
			cli.ConnectPeer("398C8161D038FD328A573FFAA0F5FAAF7FFDE5E8B4350E7D15E6AFD0B993FC52")
		}
		cli.RoutingResponseFunc = func(obj Object, connid uint8, pubkey *CryptoKey) {
			log.Println(connid, pubkey.ToHex())
			_, err := cli.SendDataPacket(connid, []byte(gopp.RandomStringPrintable(123)))
			gopp.ErrPrint(err)
		}
		cli.RoutingDataFunc = func(obj Object, num uint32, connid uint8, data []byte, cbdata Object) {
			log.Println(num, connid, len(data))
		}
		select {}
	}()
}

func test_run_tcp_server() {
	seckey := NewCryptoKeyFromHex(echo_serv_seckey_str)
	tcpsrv := NewTCPServer([]uint16{54433}, seckey, nil)
	tcpsrv.Start()

	select {}
}
