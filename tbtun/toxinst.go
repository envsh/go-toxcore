package tbtun


import (
	"fmt"
	"io/ioutil"
	log0 "log"
	// "math/rand"
	// "strconv"
	// "strings"
	"time"
	// "runtime"
	// "path"
	_ "embed" // Blank import required for string/[]byte embedding

	// "github.com/envsh/go-toxcore-c"
	"github.com/envsh/toxera/tbcom"
	// _ "github.com/envsh/toxera/tbecho"
	// _ "github.com/envsh/toxera/tbcmd"
	// _ "github.com/envsh/toxera/tbtmpl"
	// _ "github.com/envsh/toxera/tbtun"

	"github.com/TokTok/go-toxcore-c"
	"github.com/kitech/gopp"
	// "github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	// log "github.com/op/go-logging"
	// log "github.com/rs/zerolog/log"

	// _ "github.com/envsh/fedind/httpfs"
	// "github.com/envsh/fedind/httpfs"
	// "github.com/envsh/fedind/envcfg"
)

func init() {
	gopp.Keep()
	log0.SetFlags(log0.Flags()|log0.Lshortfile^log0.Ldate)
	LogrusSetFlags(log0.Flags()|Lshortfunc)

	cmdflagConfig()
	chkflagConfig()

	StartToxechoBot()
	go run_tcp_server()
}

var server = []any {
	"104.225.141.59", uint16(33445), "933BA20B2E258B4C0D475B6DECE90C7E827FE83EFA9655414E7841251B19A72C",
	"43.198.227.166", uint16(3389), "AD13AB0D434BCE6C83FE2649237183964AE3341D0AFB3BE1694B18505E4E135E",
	"3.0.24.15", uint16(33445), "E20ABCF38CDBFFD7D04B29C956B33F7B27A3BB7AF0618101617B036E4AEA402D",
}

var nickPrefix = "TunsitcBot."
var statusText = "Send me text, file, audio, video."
var teb_datasaved func(string) // todo save callback

func StartToxechoBot() {
	go func() {
		toxecho_main()
	}()
}

var gtox *tox.Tox
func gettox() *tox.Tox { return gtox }
func toxecho_main() {
	var tbdebug = gcfg.Debug
	var toxdata_path = gcfg.ToxFilePath()

	opt := tox.NewToxOptions()
	if tox.FileExist(toxdata_path) {
		data, err := ioutil.ReadFile(toxdata_path)
		if err != nil {
			log.Println(err)
		} else {
			opt.Savedata_data = data
			opt.Savedata_type = tox.SAVEDATA_TYPE_TOX_SAVE
		}
	}
	opt.Tcp_port = 33445
	var t *tox.Tox
	for i := 0; i < 5; i++ {
		t = tox.NewTox(opt)
		if t == nil {
			opt.Tcp_port += 1
		} else {
			break
		}
	}
	log.Println(opt.Tcp_port, t)
	gtox = t

	r, err := t.Bootstrap(server[0].(string), server[1].(uint16), server[2].(string))
	r2, err := t.AddTcpRelay(server[0].(string), server[1].(uint16), server[2].(string))
	if tbdebug {
		log.Println("bootstrap:", r, err, r2)
	}

	pubkey := t.SelfGetPublicKey()
	seckey := t.SelfGetSecretKey()
	toxid := t.SelfGetAddress()
	if tbdebug {
		log.Println("keys:", pubkey, seckey, len(pubkey), len(seckey))
	}
	log.Println("toxid:", toxid)

	defaultName := t.SelfGetName()
	humanName := nickPrefix + toxid[0:5]
	if humanName != defaultName {
		t.SelfSetName(humanName)
	}
	humanName = t.SelfGetName()
	if tbdebug {
		log.Println(humanName, defaultName, err)
	}

	defaultStatusText, err := t.SelfGetStatusMessage()
	if defaultStatusText != statusText {
		t.SelfSetStatusMessage(statusText)
	}
	if tbdebug {
		log.Println(statusText, defaultStatusText, err)
	}

	sz := t.GetSavedataSize()
	sd := t.GetSavedata()
	if tbdebug {
		log.Println("savedata:", sz, t)
		log.Println("savedata", len(sd), t)
	}
	err = t.WriteSavedata(toxdata_path)
	if tbdebug {
		log.Println("savedata write:", err)
	}

	// add friend norequest // why?
	fv := t.SelfGetFriendList()
	for _, fno := range fv {
		fid, err := t.FriendGetPublicKey(fno)
		if err != nil {
			log.Println(err)
		} else {
			t.FriendAddNorequest(fid)
		}
	}
	if tbdebug {
		log.Println("add friends:", len(fv))
	}

	// core callbacks, save data
	t.CallbackFriendRequest(func (t *tox.Tox, friendId string, message string, userData any) {
	log.Println(friendId, message)
	num, err := t.FriendAddNorequest(friendId)
	if tbdebug {
		log.Println("on friend request:", num, err)
	}
	if num < 100000 {
		t.WriteSavedata(toxdata_path)
	}
	}, nil)

	// audio/video
	av, err := tox.NewToxAV(t)
	if err != nil {
		log.Println(err, av)
	}
	if av == nil {
	}
	tbcom.AssocTo(t, av)


	// add tun peerid
	_, err = t.FriendAdd(gcfg.Peerid, "haloo")
	if err != nil && !gopp.ErrHave(err, "error: 5") {
		gopp.ErrPrint(err)
	}

	// toxav loops
	go func() {
		shutdown := false
		loopc := 0
		itval := 0
		for !shutdown {
			iv := av.IterationInterval()
			if iv != itval {
				// wtf
				if iv-itval > 20 || itval-iv > 20 {
					log.Println("av itval changed:", itval, iv, iv-itval, itval-iv)
				}
				itval = iv
			}

			av.Iterate()
			loopc += 1
			time.Sleep(1000 * 50 * time.Microsecond)
		}

		av.Kill()
	}()

	// toxcore loops
	shutdown := false
	loopc := 0
	itval := 0
	for !shutdown {
		iv := t.IterationInterval()
		if iv != itval {
			if tbdebug {
				if itval-iv > 20 || iv-itval > 20 {
					log.Println("tox itval changed:", itval, iv)
				}
			}
			itval = iv
		}

		t.Iterate()
		status := t.SelfGetConnectionStatus()
		if loopc%5500 == 0 {
			if status == 0 {
				if tbdebug {
					fmt.Print(".")
				}
			} else {
				if tbdebug {
					fmt.Print(status, ",")
				}
			}
		}
		loopc += 1
		time.Sleep(1000 * 50 * time.Microsecond)
	}

	t.Kill()
}

func _dirty_init() {
	log.Println("ddddddddd")
	tox.KeepPkg()
}
