package mintox

import (
	"flag"
	"log"
)

func Main() {
	flag.Parse()

	test_tcp_client()
	// test_two_nodes()
	// testencdec()
	// testencdec2()
	log.Println(mode, "main selecting...")
	select {}
}
