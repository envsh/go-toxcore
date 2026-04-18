package tbcom

import (
	"testing"

	"github.com/kitech/gopp"
	"github.com/TokTok/go-toxcore-c"

)

func Test111(t *testing.T) {
	Regit(newAdderBot)
	x := tox.NewTox(nil)
	AssocTo(x, nil)

	gopp.Assert(len(bms.bots)==1, "")
}
