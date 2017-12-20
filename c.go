package tox

/*
#cgo CFLAGS: -g -O2 -std=c99 -Wall
// #cgo LDFLAGS: -ltoxcore -ltoxdns -ltoxav -ltoxencryptsave -lvpx -lopus -lsodium -lm
#cgo pkg-config: libtoxcore libtoxav
// #cgo LDFLAGS: -L/home/gzleo/oss/toxcore/build/.libs/
*/
import "C"

// TODO what about Windows/MacOS?
