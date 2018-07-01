package main

import (
	"testing"
)

func TestPL0(t *testing.T) {
	pk0, _, _ := NewCBKeyPair()
	pl0 := NewPriorityList(8)
	var items []PLItem
	for i := 0; i < 5; i++ {
		pk, _, _ := NewCBKeyPair()
		item := &NodeFormat{Pubkey: pk, cmppk: pk0}
		items = append(items, item)
		pl0.Put(item)
	}

	if pl0.Len() != 5 {
		t.Log("len:", pl0.Len(), "want:", 5)
		t.Fail()
	}

	for i := 0; i < 3; i++ {
		pl0.Remove(items[i])
		if pl0.Len() != 5-i-1 {
			t.Log("len:", pl0.Len(), "want:", 5-i-1)
			t.Fail()
		}
	}
	if pl0.Len() != 2 {
		t.Log("len:", pl0.Len(), "want:", 2)
		t.Fail()
	}
}
