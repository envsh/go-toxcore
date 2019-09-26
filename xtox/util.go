package xtox

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"

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
// we need first write tmp file, and if ok, then mv to real file
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
			tfp, err := ioutil.TempFile(filepath.Dir(fname), "gotcb")
			if err != nil {
				return err
			}
			if _, err := tfp.Write(liveData); err != nil {
				return err
			}
			tfname := tfp.Name()
			if err := tfp.Close(); err != nil {
				return err
			}
			if err := os.Remove(fname); err != nil {
				return err
			}
			if err := os.Rename(filepath.Dir(fname)+"/"+tfname, fname); err != nil {
				return err
			}
		}
	}

	return nil
}

func LoadSavedata(this *tox.Tox, fname string) ([]byte, error) {
	return ioutil.ReadFile(fname)
}

func CallStateString(state uint32) string {
	return ""
}

var connstatus = map[int]string{0: "NON", 1: "TCP", 2: "UDP"}
var userstatus = map[int]string{0: "OFFLINE", 1: "ONLINE", 2: "BUSY", 3: "AWAY"}

func ConnStatus2Str(status int) string {
	if s, ok := connstatus[status]; ok {
		return s
	}
	return "UKN"
}
