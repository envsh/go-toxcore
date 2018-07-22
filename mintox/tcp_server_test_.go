package mintox

import (
	"log"
	"time"
)

func test_tcp_server() {
	go test_run_tcp_server()
	go func() {
		time.Sleep(1 * time.Second)
		cli := NewTCPClientRaw("127.0.0.1:54433", echo_serv_pubkey_str, echo_cli_pubkey_str, echo_cli_seckey_str)
		log.Println(cli == nil)
		select {}
	}()
}

func test_run_tcp_server() {
	seckey := NewCryptoKeyFromHex(echo_serv_seckey_str)
	tcpsrv := NewTCPServer([]uint16{54433}, seckey, nil)
	tcpsrv.Start()

	select {}
}
