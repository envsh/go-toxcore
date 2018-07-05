package main

import (
	"flag"
	"log"
)

func main() {
	flag.Parse()

	test_tcp_client()
	// test_two_nodes()
	// testencdec()
	// testencdec2()
	log.Println(mode, "main selecting...")
	select {}
}
