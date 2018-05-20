package xtox

import (
	"bytes"
	"io/ioutil"
	"os"

	tox "github.com/TokTok/go-toxcore-c"
	funk "github.com/thoas/go-funk"
)

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

func FileExist(fname string) bool {
	_, err := os.Stat(fname)
	if err != nil {
		return false
	}
	return true
}

// the go-toxcore-c has data lost problem
// TODO we need first write tmp file, and if ok, then mv to real file
func WriteSavedata(this *tox.Tox, fname string) error {
	if !FileExist(fname) {
		err := ioutil.WriteFile(fname, this.GetSavedata(), 0755)
		if err != nil {
			return err
		}
	} else {
		data, err := ioutil.ReadFile(fname)
		if err != nil {
			return err
		}
		liveData := this.GetSavedata()
		if bytes.Compare(data, liveData) != 0 {
			err := ioutil.WriteFile(fname, this.GetSavedata(), 0755)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func LoadSavedata(this *tox.Tox, fname string) ([]byte, error) {
	return ioutil.ReadFile(fname)
}
