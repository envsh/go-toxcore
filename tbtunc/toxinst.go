package tbtunc


import (
	"fmt"
	"io/ioutil"
	log0 "log"
	"errors"
	// "math/rand"
	// "strconv"
	// "strings"
	"time"
	// "runtime"
	// "path"
	"context"
	_ "embed" // Blank import required for string/[]byte embedding

	// "github.com/envsh/go-toxcore-c"
	"github.com/envsh/toxera/tbcom"
	// _ "github.com/envsh/toxera/tbecho"
	// _ "github.com/envsh/toxera/tbcmd"
	// _ "github.com/envsh/toxera/tbtmpl"
	// _ "github.com/envsh/toxera/tbtun"

	"github.com/TokTok/go-toxcore-c"
	"github.com/kitech/gopp"
	// _ "github.com/kitech/touse/log1"
	// "github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"

)


/////////////

type ToxStats struct {

}

type ToxInst struct {
	opts *Options
	stats *ToxStats
	newToxsave bool

	TO *tox.Tox
	AV *tox.ToxAV
}
type Options struct {
	tox.ToxOptions

	Debug   bool
	AV_enabled bool
	ToxsaveFile string
	BootstrapNodes []string
	BootstrapFriends []string // auto add friends
	BootstrapGroups []string // auto add groups(NGC)
	Bots_enabled bool

	NickPrefix string
	StatusText string

	// callbacks
	DataSaved func(file string)
	DataLoaded func(file string)
	Errored   func(err error)
	Created   func() // before iterate
}

func NewOptions() *Options {
	opts := &Options{}
	topts := tox.NewToxOptions()
	if topts.Tcp_port == 0 {
		topts.Tcp_port = 33445
	}
	opts.ToxOptions = *topts

	// defualt values
	opts.ToxsaveFile = "tox_save.data"
	opts.NickPrefix = nickPrefix
	opts.StatusText = statusText

	return opts
}

// usage: opts := NewOptions()
//        opts.foo = bar
//        ti := NewToxInst(opts)
//        err := ti.Initilize()
//        if err != nil {}
//        if err == nil { ti.Interate() }
// nil or NewOptions() for defaults
func NewToxInst(opts *Options) *ToxInst {
	ti := &ToxInst{}
	ti.opts = opts
	if opts == nil {
		ti.opts = NewOptions()
	}

	return ti
}
func (this *ToxInst) Initilize() error {
	opts := this.opts

	err := this.loadAccountData()
	if err != nil { return err }

	err = this.selectTcpPort()
	if err != nil { return err }
	t, av := this.TO, this.AV

	err = this.setupMyinfos()
	if err != nil { return err }

	// if true { log.Fatal("ttt") }
	err = this.bootstrapFriends()
	if err != nil { return err }

	err = this.prepareBootstrap()
	if err != nil { return err }

	if opts.Bots_enabled {
		tbcom.AssocTo(t, av)
	}

	err = this.bootstrapNodes()

	return err
}
func (this *ToxInst) loadAccountData() error {
	opts := this.opts
	if opts.Savedata_data != nil {
		return nil
	}

	opt := &opts.ToxOptions
	toxdata_path := opts.ToxsaveFile
	log.Debug("loading ...", toxdata_path)
	if tox.FileExist(toxdata_path) {
		data, err := ioutil.ReadFile(toxdata_path)
		if err != nil {
			log.Println(err)
			return err
		} else {
			opt.Savedata_data = data
			opt.Savedata_type = tox.SAVEDATA_TYPE_TOX_SAVE
		}
	} else {
		log.Warn("create new toxsave ...")
		this.newToxsave = true
	}

	return nil
}
func (this *ToxInst) selectTcpPort() error {
	var topt = &this.opts.ToxOptions
	var t *tox.Tox
	for i := 0; i < 5; i++ {
		t = tox.NewTox(topt)
		if t == nil {
			topt.Tcp_port += 1
		} else {
			break
		}
	}
	if t == nil {
		return errors.New("create tox object error, maybe no port usable")
	}
	log.Println(topt.Tcp_port, t)

	// audio/video
	if this.opts.AV_enabled {
		av, err := tox.NewToxAV(t)
		if err != nil {
			return err
		}
		this.AV = av
	}
	this.TO = t
	return nil
}
func (this *ToxInst) setupMyinfos() error {
	t := this.TO
	tbdebug := this.opts.Debug

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
		log.Println(humanName, defaultName)
	}

	defaultStatusText, err := t.SelfGetStatusMessage()
	if defaultStatusText != statusText {
		t.SelfSetStatusMessage(statusText)
	}
	if tbdebug {
		log.Println(statusText, defaultStatusText, err)
	}
	return nil
}
func (this *ToxInst) bootstrapFriends() error {
	t := this.TO
	tbdebug := this.opts.Debug

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

	reqmsg := "hello from " + this.opts.NickPrefix
	for _, frndid := range this.opts.BootstrapFriends {
		_, err := t.FriendAdd(frndid, reqmsg)
		if err != nil && !gopp.ErrHave(err, "error: 5") {
			gopp.ErrPrint(err)
		}
	}

	for _, grpid := range this.opts.BootstrapGroups {
		_ = grpid
	}

	return nil
}
func (this *ToxInst) prepareBootstrap() error {
	t := this.TO
	tbdebug := this.opts.Debug
	toxdata_path := this.opts.ToxsaveFile

	var err error
	if this.newToxsave {
		// save to file

		log.Println("save new tox ...", toxdata_path)
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

	} else {

	}
	return err
}
func (this *ToxInst) bootstrapNodes() error {
	t := this.TO
	tbdebug := this.opts.Debug

	for i := 0; i < len(server); i += 3 {
		ip, port, pkey := server[i].(string), server[i+1].(uint16), server[i+2].(string)
		// r := 0
		r, err := t.Bootstrap(ip, port, pkey)

		r2, err := t.AddTcpRelay(ip, port, pkey)
		if tbdebug {
			log.Println("bootstrap:", r, err, r2)
		}
	}
	return nil
}

////////////////

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

//////////////

var gtox *tox.Tox
func gettox() *tox.Tox { return gtox }
func toxecho_main() {
	var tbdebug = gcfg.Debug
	var toxdata_path = gcfg.ToxFilePath()

	tiopt := NewOptions()
	tiopt.Debug = tbdebug
	tiopt.Udp_enabled = true
	tiopt.AV_enabled = false
	tiopt.Bots_enabled = true
	tiopt.NickPrefix = nickPrefix
	tiopt.StatusText = statusText
	tiopt.ToxsaveFile = toxdata_path
	tiopt.BootstrapFriends = []string{gcfg.Peerid}

	ti := NewToxInst(tiopt)
	err := ti.Initilize()
	gopp.ErrPrint(err)
	if err != nil {
		return
	}
	var t = ti.TO
	var av = ti.AV
	gtox = t

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

	// toxav loops
	go func() {
		if av == nil { return }
		ToxAVIterate(av, nil)
		av.Kill()
	}()

	// toxcore loops
	{
		ToxIterate(t, nil)
		t.Kill()
	}
}

// toxav loops

func ToxAVIterate(av *tox.ToxAV, ctx context.Context) {
	// var tbdebug = gcfg.Debug

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
}

// toxcore loops

func ToxIterate(t *tox.Tox, ctx context.Context) {
	var tbdebug = gcfg.Debug

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
}

func _dirty_init() {
	log.Println("ddddddddd")
	tox.KeepPkg()
}
