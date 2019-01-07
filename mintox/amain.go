package mintox

import (
	"log"
	"os"
)

func Main() {
	// flag.Parse()
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}

	// test_tcp_server()
	test_tcp_client()
	// test_two_nodes()
	// testencdec()
	// testencdec2()
	log.Println(mode, "main selecting...")
	select {}
}
