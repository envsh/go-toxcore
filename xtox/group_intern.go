package xtox

/*
#include <stdint.h>
#include <tox/tox.h>

extern uint8_t *xtox_conference_get_pubkey(Tox *tox, uint32_t conference_number, void *pkbuf);
extern uint8_t *xtox_conference_get_identifier(Tox *tox, uint32_t conference_number, void *idbuf);
extern void xtox_conference_set_identifier(Tox *tox, uint32_t conference_number, void *binid);
*/
import "C"
import (
	"encoding/hex"
	"strings"
	"unsafe"

	tox "github.com/TokTok/go-toxcore-c"
)

func ConferenceGetPubkey(this *tox.Tox, groupNumber uint32) (string, error) {
	pkbuf := [C.TOX_PUBLIC_KEY_SIZE]byte{}
	ctoxcore := (*C.Tox)(GetCTox(this))
	C.xtox_conference_get_pubkey(ctoxcore, C.uint32_t(groupNumber), (unsafe.Pointer)(&pkbuf[0]))
	pubkey := strings.ToUpper(hex.EncodeToString(pkbuf[:]))

	return pubkey, nil
}

func ConferenceGetIdentifier(this *tox.Tox, groupNumber uint32) (string, error) {
	idbuf := [1 + C.TOX_PUBLIC_KEY_SIZE]byte{}
	ctoxcore := (*C.Tox)(GetCTox(this))
	C.xtox_conference_get_identifier(ctoxcore, C.uint32_t(groupNumber), (unsafe.Pointer)(&idbuf[0]))
	identifier := strings.ToUpper(hex.EncodeToString(idbuf[:]))
	identifier = identifier[2:] // 1B(type)+32B(identifier)

	return identifier, nil
}

// hexid 64
// not call only just closely after ConferenceNew or AddAVGroupChat. or it's would undefined behavior
// say in one single iterate
// dont use this for invited user, it's undefined behavior
func ConferenceSetIdentifier(this *tox.Tox, groupNumber uint32, hexid string) error {
	ctoxcore := (*C.Tox)(GetCTox(this))
	binid, err := hex.DecodeString(hexid)
	if err != nil {
		return err
	}

	C.xtox_conference_set_identifier(ctoxcore, C.uint32_t(groupNumber), (unsafe.Pointer)(&binid[0]))
	return nil
}
