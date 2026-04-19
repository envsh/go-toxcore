package tbcom

import (
	"log"
	"reflect"
	"strings"

	"github.com/TokTok/go-toxcore-c"
	// "github.com/kitech/gopp"

)

const MaxMsgLen = 999

type BotMan struct {
	// bots map[string]any // type => obj
	bots []any // objs
}

type BotInfo struct {

}

var bms = &BotMan{}

// return obj's method, prefix OnXXX, will set CallbackXXX
func Regit(newfunc any) {
	fno := reflect.ValueOf(newfunc)
	outs := fno.Call(nil)
	bms.bots = append(bms.bots, outs[0].Interface())
}

// called tox.Tox instance creator
func AssocTo(t *tox.Tox, av *tox.ToxAV) {
	tv := reflect.ValueOf(t)
	vv := reflect.ValueOf(av)

	cbcnt := 0
	for _, bx := range bms.bots {
		bv := reflect.ValueOf(bx)
		ty := reflect.TypeOf(bx)

		for i := 0; i < ty.NumMethod(); i++ {
			mty := ty.Method(i)
			if !strings.HasPrefix(mty.Name, "On") {
				continue
			}

			cbmname := "Callback"+mty.Name[2:]
			mo2 := tv.MethodByName(cbmname)
			mo3 := reflect.Value{}
			if av != nil {
				mo3 = vv.MethodByName(cbmname)
			}

			if !mo2.IsValid() && !mo3.IsValid() {
				log.Println("cb not found", mty.Name)
				continue
			}
			if mo2.IsValid() {
				mo2.Call([]reflect.Value{bv.Method(i), bv})
			}else if mo3.IsValid() {
				mo3.Call([]reflect.Value{bv.Method(i), bv})
			}
			cbcnt += 1
		}
	}
	log.Println("assoced", "botcnt", len(bms.bots), "cbcnt", cbcnt)
}


func init() {
	// Regit(newAdderBot)
}

/// demo bot
func newAdderBot() *AdderBot {
	b := &AdderBot{}
	return b
}
type AdderBot struct {

}

func (this *AdderBot) OnSelfConnectionStatus(t *tox.Tox, status int, userData any) {
	log.Println("hehhe")
}

func (this *AdderBot) OnFriendMessage(t *tox.Tox, friendNumber uint32, message string, userData any) {
	log.Println("hehhe")
}

func (this *AdderBot) OnFriendConnectionStatus(t *tox.Tox, friendNumber uint32, status int, userData any) {
	log.Println("hehhe")
}
