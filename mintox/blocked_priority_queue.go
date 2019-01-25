package mintox

import "github.com/Workiva/go-datastructures/queue"

type BlockedPriorityQueue struct {
	pq   *queue.PriorityQueue
	subC chan bool
	hint int
}

func NewBlockedPriorityQueue(hint int, allowDuplicates bool) *BlockedPriorityQueue {
	this := &BlockedPriorityQueue{}
	this.hint = hint
	this.pq = queue.NewPriorityQueue(hint, allowDuplicates)
	this.subC = make(chan bool, 0)
	return this
}

func (this *BlockedPriorityQueue) Dispose() {
	this.pq.Dispose()
	select {
	case this.subC <- true:
	default:
	}
}
func (this *BlockedPriorityQueue) Disposed() bool { return this.pq.Disposed() }
func (this *BlockedPriorityQueue) Empty() bool    { return this.pq.Empty() }
func (this *BlockedPriorityQueue) Get(number int) ([]queue.Item, error) {
	item, err := this.pq.Get(number)
	if err == nil {
		select {
		case this.subC <- true:
		default:
		}
	}
	return item, err
}
func (this *BlockedPriorityQueue) Len() int         { return this.pq.Len() }
func (this *BlockedPriorityQueue) Peek() queue.Item { return this.pq.Peek() }
func (this *BlockedPriorityQueue) BlockPut(items ...queue.Item) error {
	for {
		if this.pq.Len() >= this.hint {
			<-this.subC
		}
		if this.pq.Len() < this.hint {
			return this.pq.Put(items...)
		}
	}
	return nil
}

// omit length check, used for most prior one
func (this *BlockedPriorityQueue) Put(items ...queue.Item) error {
	return this.pq.Put(items...)
}
