package main

import "sync"

type BiMap struct {
	s         sync.RWMutex
	immutable bool
	forward   map[interface{}]interface{}
	inverse   map[interface{}]interface{}
}

func NewBiMap() *BiMap {
	return &BiMap{forward: make(map[interface{}]interface{}), inverse: make(map[interface{}]interface{}), immutable: false}
}

func (b *BiMap) Insert(k interface{}, v interface{}) {
	b.s.RLock()
	if b.immutable {
		panic("Cannot modify immutable map")
	}
	b.s.RUnlock()

	b.s.Lock()
	defer b.s.Unlock()
	b.forward[k] = v
	b.inverse[v] = k
}

func (b *BiMap) Exists(k interface{}) bool {
	b.s.RLock()
	defer b.s.RUnlock()
	_, ok := b.forward[k]
	return ok
}

func (b *BiMap) ExistsInverse(k interface{}) bool {
	b.s.RLock()
	defer b.s.RUnlock()

	_, ok := b.inverse[k]
	return ok
}

func (b *BiMap) Get(k interface{}) (interface{}, bool) {
	if !b.Exists(k) {
		return "", false
	}
	b.s.RLock()
	defer b.s.RUnlock()
	return b.forward[k], true

}

func (b *BiMap) GetInverse(v interface{}) (interface{}, bool) {
	if !b.ExistsInverse(v) {
		return "", false
	}
	b.s.RLock()
	defer b.s.RUnlock()
	return b.inverse[v], true

}

func (b *BiMap) Delete(k interface{}) {
	b.s.RLock()
	if b.immutable {
		panic("Cannot modify immutable map")
	}
	b.s.RUnlock()

	if !b.Exists(k) {
		return
	}
	val, _ := b.Get(k)
	b.s.Lock()
	defer b.s.Unlock()
	delete(b.forward, k)
	delete(b.inverse, val)
}

func (b *BiMap) DeleteInverse(v interface{}) {
	b.s.RLock()
	if b.immutable {
		panic("Cannot modify immutable map")
	}
	b.s.RUnlock()

	if !b.ExistsInverse(v) {
		return
	}

	key, _ := b.GetInverse(v)
	b.s.Lock()
	defer b.s.Unlock()
	delete(b.inverse, v)
	delete(b.forward, key)

}

func (b *BiMap) Size() int {
	b.s.RLock()
	defer b.s.RUnlock()
	return len(b.forward)
}

func (b *BiMap) MakeImmutable() {
	b.s.Lock()
	defer b.s.Unlock()
	b.immutable = true
}

func (b *BiMap) GetInverseMap() map[interface{}]interface{} {
	return b.inverse
}

func (b *BiMap) GetForwardMap() map[interface{}]interface{} {
	return b.forward
}

func (b *BiMap) Lock() {
	b.s.Lock()
}

func (b *BiMap) Unlock() {
	b.s.Unlock()
}
