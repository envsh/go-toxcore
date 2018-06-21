package xtox

import (
	"log"
	"reflect"
	"testing"
	"unsafe"

	tox "github.com/TokTok/go-toxcore-c"
)

func Test0(t *testing.T) {
	to := tox.NewTox(nil)
	tov := reflect.ValueOf(to).Elem()
	ctoxField := tov.FieldByName("toxcore")
	p0 := unsafe.Pointer(ctoxField.UnsafeAddr()) // this is wrong way
	p1 := GetCTox(to)                            // this is right way
	log.Println(p0, p1, p0 == p1)
}
