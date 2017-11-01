package xtox

import "time"

func Ping0(addr string, timeout int) (time.Duration, error) {
	return 1 * time.Second, nil
}
