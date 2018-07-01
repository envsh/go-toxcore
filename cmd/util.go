package main

import "time"

// type ByteArray = []byte //can not define method on unnamed type
type ByteArray []byte

func (this ByteArray) Slice(low int, length int) ByteArray {
	return nil
}

var TimeZero time.Time
