package mintox

import (
	"time"

	"github.com/sasha-s/go-deadlock"
)

type SpeedCalc struct {
	Btime  time.Time
	Ltime  time.Time // last data time
	Totlen int64
	Avgspd int64
	Datcnt int64
	mu     deadlock.RWMutex
}

func NewSpeedCalc() *SpeedCalc {
	this := &SpeedCalc{}
	this.Btime = time.Now()
	this.Ltime = this.Btime

	return this
}

func (this *SpeedCalc) Data(rn int) {
	this.mu.Lock()
	defer this.mu.Unlock()

	this.Totlen += int64(rn)
	etime := time.Now()
	if etime.Sub(this.Ltime).Seconds() > 30 {
		this.Btime = etime.Add(-1 * time.Second) // reset begin time
		this.Totlen = int64(rn)
	}
	if etime.Sub(this.Ltime).Seconds() > 1 {
		this.Ltime = etime
		d := int64(etime.Sub(this.Btime).Seconds())
		if d != 0 {
			this.Avgspd = this.Totlen / d
		}
	}
	this.Datcnt += 1
}
