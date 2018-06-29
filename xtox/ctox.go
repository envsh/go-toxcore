package xtox

/*
#cgo LDFLAGS: -ltoxcore

#include <stdint.h>

extern uint32_t tox_version_major();
extern uint32_t tox_version_minor();
extern uint32_t tox_version_patch();
*/
import "C"

import (
	"fmt"
	"unsafe"

	tox "github.com/TokTok/go-toxcore-c"
)

// need sync struct to tox.Tox
type _Tox struct {
	opts    *tox.ToxOptions
	toxcore *C.char
	// ...
}

// need sync struct to tox.ToxAV
type _ToxAV struct {
	tox   *tox.Tox
	toxav *C.char
	// ...
}

func GetCTox(t *tox.Tox) unsafe.Pointer {
	temu := (*_Tox)(unsafe.Pointer(t))
	return unsafe.Pointer(temu.toxcore)
}

func GetCToxAV(tav *tox.ToxAV) unsafe.Pointer {
	tavemu := (*_ToxAV)(unsafe.Pointer(tav))
	return unsafe.Pointer(tavemu.toxav)
}

func VersionStr() string {
	return fmt.Sprintf("%d.%d.%d", int(C.tox_version_major()),
		int(C.tox_version_minor()), int(C.tox_version_patch()))
}
