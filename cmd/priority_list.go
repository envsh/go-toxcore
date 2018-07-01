package main

import (
	"log"
	"sync"
)

// both support priority queue, double-ended queue, and list foreach and map key test feature

// Hierarchical Heap, Hierarchical Queue, SplayQ(ueue)

type PLItem interface {
	Compare(PLItem) int
	Key() string // unique key
}

type PriorityList struct {
	max  int
	mu   sync.RWMutex
	keys map[string]bool
	lst  []PLItem
}

func NewPriorityList(max int) *PriorityList {
	this := &PriorityList{}
	this.max = max
	this.keys = map[string]bool{}
	this.lst = []PLItem{}
	return this
}

func (this *PriorityList) Len() int { return len(this.lst) }

func (this *PriorityList) Put(item PLItem) bool {
	this.mu.Lock()
	defer this.mu.Unlock()
	if _, ok := this.keys[item.Key()]; ok {
		this.replaceItem(item)
		return true
	}

	// find insert position
	var i int = 0
	for ; i < len(this.lst); i++ {
		if i == len(this.lst)-1 {
			break
		}
		v := item.Compare(this.lst[i])
		if v > 0 {
			break
		}
	}

	this.lst = append(this.lst[:i], append([]PLItem{item}, this.lst[i:]...)...)
	this.keys[item.Key()] = true

	// remove truncated
	if len(this.lst) > this.max {
		todrops := this.lst[this.max:]
		this.lst = this.lst[:this.max]
		for _, todrop := range todrops {
			delete(this.keys, todrop.Key())
		}
	}

	if len(this.lst) != len(this.keys) {
		log.Panicf("internal error, l/k: %d/%d\n", len(this.lst), len(this.keys))
	}
	return true
}

// lock in caller
func (this *PriorityList) replaceItem(item PLItem) {
	for i := 0; i < len(this.lst); i++ {
		if this.lst[i].Key() == item.Key() {
			this.lst[i] = item
			break
		}
	}
}

func (this *PriorityList) Head(n int) (rets []PLItem) {
	if n <= 0 {
		return
	}
	this.mu.RLock()
	defer this.mu.RUnlock()
	if n < len(this.lst) {
		rets = this.lst[0:n]
	} else {
		rets = this.lst
	}
	return
}

func (this *PriorityList) Tail(n int) (rets []PLItem) {
	return // TODO
}

func (this *PriorityList) First() (ret PLItem) {
	this.mu.RLock()
	defer this.mu.RUnlock()
	if len(this.lst) > 0 {
		return this.lst[0]
	}
	return nil
}

func (this *PriorityList) Last() (ret PLItem) {
	this.mu.RLock()
	defer this.mu.RUnlock()
	if len(this.lst) > 0 {
		return this.lst[len(this.lst)-1]
	}
	return nil
}

// Put, --Get, --GetLast, Len, GetAt, Each, Peek, TakeAt, Pop
// all: Empty, Len
// stack: Push, Pop xxx
// queue: Enqueue, Dequeue
// list: Remove
