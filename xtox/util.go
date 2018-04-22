package xtox

import funk "github.com/thoas/go-funk"

func DiffSlice(old, new_ interface{}) (added []interface{}, deleted []interface{}) {
	funk.ForEach(old, func(e interface{}) {
		if !funk.Contains(new_, e) {
			deleted = append(deleted, e)
		}
	})
	funk.ForEach(new_, func(e interface{}) {
		if !funk.Contains(old, e) {
			added = append(added, e)
		}
	})
	return
}
