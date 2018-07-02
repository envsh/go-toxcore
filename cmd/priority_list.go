package main

import (
	"log"
	"math/rand"
	"sync"
)

// both support priority queue, double-ended queue, and list foreach and map key test feature

// Hierarchical Heap, Hierarchical Queue, SplayQ(ueue)

type PLItem interface {
	Compare(PLItem) int
	Key() string // unique key
	Update(PLItem)
}

// unique priority list
type PriorityList struct {
	max  int
	mu   sync.RWMutex
	keys map[string]PLItem
	lst  []PLItem
}

func NewPriorityList(max int) *PriorityList {
	this := &PriorityList{}
	this.max = max
	this.keys = map[string]PLItem{}
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
		// cmppk, item, lsti
		v := item.Compare(this.lst[i])
		// log.Println(i, v, hex.EncodeToString([]byte(item.Key()))[:20],
		//	hex.EncodeToString([]byte(this.lst[i].Key()))[:20])
		if v >= 0 {
			break
		}
	}
	// log.Println(i, hex.EncodeToString([]byte(item.Key()))[:20])

	this.lst = append(this.lst[:i], append([]PLItem{item}, this.lst[i:]...)...)
	this.keys[item.Key()] = item

	// remove truncated
	if len(this.lst) > this.max {
		for _, todrop := range this.lst[this.max:] {
			delete(this.keys, todrop.Key())
		}
		this.lst = this.lst[:this.max]
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

func (this *PriorityList) updateItem(item PLItem) {
	for i := 0; i < len(this.lst); i++ {
		if this.lst[i].Key() == item.Key() {
			this.lst[i].Update(item)
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

func (this *PriorityList) Remove(item PLItem) bool {
	this.mu.Lock()
	defer this.mu.Unlock()

	if _, ok := this.keys[item.Key()]; !ok {
		return false
	}

	var i int = 0
	for ; i < len(this.lst); i++ {
		if this.lst[i].Key() == item.Key() {
			break
		}
	}

	this.lst = append(this.lst[:i], this.lst[i+1:]...)
	delete(this.keys, item.Key())
	return true
}

// snapshot
func (this *PriorityList) EachSnap(f func(itemi PLItem)) {
	if len(this.lst) == 0 || f == nil {
		return
	}
	var lst []PLItem
	this.mu.RLock()
	for _, item := range this.lst {
		lst = append(lst, item)
	}
	this.mu.RUnlock()
	for _, item := range lst {
		f(item)
	}
}

// not call other method in this call, or deadlock
func (this *PriorityList) EachInline(f func(itemi PLItem)) {
	if len(this.lst) == 0 || f == nil {
		return
	}
	this.mu.Lock()
	defer this.mu.Unlock()
	for _, item := range this.lst {
		f(item)
	}
}

// not call other method in this call, or deadlock
func (this *PriorityList) Select(f func(itemi PLItem) bool) (slts []PLItem) {
	this.mu.RLock()
	defer this.mu.RUnlock()
	for _, item := range this.lst {
		if f(item) {
			slts = append(slts, item)
		}
	}
	return
}

func (this *PriorityList) SelectRandn(k int) (slts []PLItem) {
	if k <= 0 {
		return
	}

	this.mu.RLock()
	defer this.mu.RUnlock()

	n := len(this.lst)

	for i := 0; i < k && i < n; i++ {
		slts = append(slts, this.lst[i])
	}
	if len(slts) < k {
		return // not enough
	}

	for x, itemi := range this.lst[k:] {
		j := rand.Intn(x + k)
		if j < k {
			slts[j] = itemi
		}
	}

	return
}

func (this *PriorityList) GetByKey(key string) PLItem {
	this.mu.RLock()
	defer this.mu.RUnlock()
	if item, ok := this.keys[key]; ok {
		return item
	}
	return nil
}

// Put, --Get, --GetLast, Len, GetAt, Each, Peek, TakeAt, Pop
// all: Empty, Len
// stack: Push, Pop xxx
// queue: Enqueue, Dequeue
// list: Remove
