package xtox

/*
#include <tox/tox.h>
#include <unistd.h>

#define c_sleep(x) usleep(1000 * (x))

static void xtox_iter_fixed(void*vt, int ms) {
    Tox *t = (Tox*)vt;
    while (1) {
       tox_iterate(t, NULL);
       c_sleep(ms);
    }
}
static void xtox_iter_inner(void*vt) {
    Tox *t = (Tox*)vt;
    while (1) {
       tox_iterate(t, NULL);
       uint32_t itval = tox_iteration_interval(t);
       c_sleep(itval);
    }
}
*/
import "C"
import tox "github.com/TokTok/go-toxcore-c"

func IterFixed(t *tox.Tox, ms int) {
	ctox := GetCTox(t)
	C.xtox_iter_fixed(ctox, C.int(ms))
}

func IterInner(t *tox.Tox) {
	ctox := GetCTox(t)
	C.xtox_iter_inner(ctox)
}
