package tbtunc

import (
	"fmt"
	// "io/ioutil"
	log0 "log"
	// "math/rand"
	// "strconv"
	"strings"
	// "time"
	"runtime"
	"path"
	// _ "embed" // Blank import required for string/[]byte embedding

	"github.com/kitech/gopp"
	// "github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

// func/func2 ...
func isAnonName(name string) bool {
	if len(name) < 4 {
		return false
	}
	if name == "func" {
		return true
	}
	if gopp.IsNumberic(name[4:]) {
		return true
	}

	return false
}

func trimAnonName(flds []string) []string{
	fc := len(flds)
	for i := fc-1; i>0; i-- {
		if !isAnonName(flds[i]) {
			return flds[:i+1]
		}
	}
	return flds
}

func Text2Gray(text string) string {
	dark := true
	code := gopp.IfElseStr(dark, "\033[90m", "\033[37m")
	return fmt.Sprintf("%s%s\033[0m", code, text)
	// return "\e[90m"+text+"\e[0m"
}

func refmtFuncname(funcname string) string {
	_, nsfunc := path.Split(funcname)
	fields := strings.Split(nsfunc, ".")
	fields = trimAnonName(fields)

	if len(fields) > 1 {
		fields = fields[len(fields)-1:]
	}
	nsfunc = strings.Join(fields, ".")
	nsfunc = strings.Replace(nsfunc, "(", "", -1)
	nsfunc = strings.Replace(nsfunc, ")", "", -1)
	nsfunc = strings.Replace(nsfunc, "*", "", -1)

	return nsfunc
}

var gflags = log0.LstdFlags
var Llongfunc = log0.Lmsgprefix << 2
var Lshortfunc = log0.Lmsgprefix << 3
var Lgrayfile = log0.Lmsgprefix << 4
var Ltimestamp = log0.Lmsgprefix << 5 // 2006-01-02 15:04:05.000
var Lnoyearts = log0.Lmsgprefix << 6 // 01-02 15:04:05


var logrusShortCallerFmter = &log.TextFormatter{
	CallerPrettyfier: func(f *runtime.Frame) (string, string) {
		_, filename := path.Split(f.File)
		filename = fmt.Sprintf(" %s:%d", filename, f.Line)

		nsfunc := refmtFuncname(f.Function)
		filefunc := filename
		if gflags & Lshortfunc != 0 || gflags & Llongfunc != 0 {
			filefunc = filename+":"+nsfunc
		}
		if gflags & Lgrayfile != 0 {
			filefunc = Text2Gray(filefunc)
		}
		filefunc += "\t"
		return "", filefunc
	},
	// TimestampFormat : "2006-01-02 15:04:05.000",
	TimestampFormat : "01-02 15:04:05",
	DisableTimestamp: false,
	FullTimestamp: true,
}

func LogrusSetFlags(flags int) {
	gflags = flags | Lgrayfile | Lnoyearts
	log0.SetFlags(gflags)
	log.SetReportCaller(true)

	if gflags & Ltimestamp != 0 {
		logrusShortCallerFmter.TimestampFormat = "2006-01-02 15:04:05.000"
	} else if gflags & Lnoyearts != 0 {
		// default
	} else {
		s := ""
		if gflags & log0.Ldate != 0 {
			s = "2006-01-02"
		}
		if gflags & log0.Ltime != 0 {
			if s != "" { s += " " }
			s += "15:04:05"
		}
		if gflags & log0.Lmicroseconds != 0 {
			s += ".000"
		}
		if s != "" {
			// logrusShortCallerFmter.TimestampFormat = s
		}
	}
	log.SetFormatter(logrusShortCallerFmter)
}
