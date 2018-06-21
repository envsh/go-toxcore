package xtox

import (
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/TokTok/go-toxcore-c"
)

type MiniTox struct {
	t      *tox.Tox
	stopch chan struct{}
}

func NewMiniTox() *MiniTox {
	this := &MiniTox{}
	this.t = tox.NewTox(nil)
	this.stopch = make(chan struct{}, 0)
	return this
}

func (this *MiniTox) Iterate() {
	tickch := time.Tick(100 * time.Millisecond)
	for {
		select {
		case <-tickch:
			this.t.Iterate()
		case <-this.stopch:
			return
		}
	}
}

func (this *MiniTox) bootstrap() {
	/*
		for idx := 0; idx < len(bsnodes)/3; idx++ {
			port, err := strconv.Atoi(bsnodes[1+idx*3])
			_, err = this.t.Bootstrap(bsnodes[0+idx*3], uint16(port), bsnodes[2+idx*3])
			if err != nil {
			}
			_, err = this.t.AddTcpRelay(bsnodes[0+idx*3], uint16(port), bsnodes[2+idx*3])
			if err != nil {
			}
		}
	*/
}

func (this *MiniTox) stop() {
	this.stopch <- struct{}{}
}

func TestGid0(t *testing.T) {
	mt := NewMiniTox()
	t0 := mt.t

	go mt.Iterate()

	for i := 0; i < 5; i++ {
		gn, err := t0.ConferenceNew()
		log.Println("gn:", gn, err)

		t0.ConferenceSetTitle(gn, fmt.Sprintf("group###%d", gn))
		id, err := ConferenceGetIdentifier(t0, gn)
		log.Println("id:", id, err)

		newidin := "0123456789" + id[10:]
		ConferenceSetIdentifier(t0, gn, newidin)
		newidout, err := ConferenceGetIdentifier(t0, gn)
		log.Println("newid:", newidin == newidout, newidin, newidout, err)
	}
}
