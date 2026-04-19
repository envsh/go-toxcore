package botut

import (
	"fmt"
	"strings"
	"slices"

	"github.com/google/shlex"

	"github.com/kitech/gopp"
)

var cmdpfx = "!cmd"
var cmdflts = strings.Fields("top iotop ping")
var maxrsplen = 999 // 1372

// eg. !cmd which ls
// return ismat, res
func Runcmd(message string) (ismat bool, remsg string) {
	ismat = strings.HasPrefix(message, cmdpfx+" ")
	args, err := shlex.Split(message)
	gopp.ErrPrint(err, message)

	if !ismat {
		return
	}
	if err != nil {
		remsg = err.Error()
	} else if len(args) > 0 && args[0] != cmdpfx {
		return
	} else if slices.Contains(cmdflts, args[1]) {
		remsg = "cannot use ncurses cmd that not return"
	} else {
		args = args[1:] // trim !cmd
		res, err := gopp.RunCmdCout(args[0], args[1:]...)
		gopp.ErrPrint(err, args)

		remsg = gopp.IfElseStr(err==nil, res, fmt.Sprintf("%v", err))
	}

	remsg = gopp.SubStr(remsg, maxrsplen)

	return
}
