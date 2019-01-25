package mintox

import (
	"gopp"
	"log"
	"testing"
)

func TestBQ0(t *testing.T) {
	bpq := NewBlockedPriorityQueue(5, true)
	bpq.Put(&sendItem{nil, 2})
	bpq.Put(&sendItem{nil, 1})
	bpq.Put(&sendItem{nil, 0})
	bpq.Put(&sendItem{nil, 2})
	bpq.Put(&sendItem{nil, 1})
	bpq.Put(&sendItem{nil, 0})
	for i := 0; i < 6; i++ {
		items, err := bpq.Get(1)
		gopp.ErrPrint(err)
		log.Println(i, items[0].(*sendItem).Prior)
	}
}
