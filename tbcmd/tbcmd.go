package tbcmd

import (
	// "fmt"
	// "io/ioutil"
	// "log"
	// "os"
	// "math/rand"
	// "strconv"
	// "strings"
	// "time"

	// "github.com/envsh/go-toxcore-c"
	"github.com/envsh/toxera/tbcom"
	"github.com/TokTok/go-toxcore-c"
	// "github.com/kitech/gopp"
	// "github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"

)

/// demo bot
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
	log.Println("hehhe")
}

func (this *AdderBot) OnFriendConnectionStatus(t *tox.Tox, friendNumber uint32, status int, userData any) {
	log.Println("hehhe")
}
