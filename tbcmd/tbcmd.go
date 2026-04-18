package tbcmd

import (
	// "fmt"
	// "io/ioutil"
	// "log"
	// "os"
	// "math/rand"
	// "strconv"
	// "strings"
	// "slices"
	// "time"

	// "github.com/envsh/go-toxcore-c"
	"github.com/envsh/toxera/tbcom"
	"github.com/envsh/toxera/botut"
	"github.com/TokTok/go-toxcore-c"
	"github.com/kitech/gopp"
	// "github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"

)

/// bot that execute friend message prefix !cmd which pwd
func init() {
	tbcom.Regit(newAdderBot)
}

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
	log.Println("hehhe",  message)
	ismat, remsg := botut.Runcmd(message)
	if !ismat { return }

	n, err := t.FriendSendMessage(friendNumber, remsg)
	gopp.ErrPrint(err, n)

}

func (this *AdderBot) OnFriendConnectionStatus(t *tox.Tox, friendNumber uint32, status int, userData any) {
	log.Println("hehhe")
}
