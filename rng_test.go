package main

import (
	t "testing"
	// "fmt"
	"strings"
	"strconv"
	"os"
)

func Test_MT(tt *t.T) {
	m := MTrng{}
	oeis_seed := uint32(5489)

	// https://oeis.org/A221557
	data, _ := os.ReadFile("./oeis_mersenne.txt")
	expected := strings.Split(string(data), "\n")

	m.mt_init(oeis_seed)
	max := len(expected) - 1
	for i := 0; i <= max; i += 1 {
		if actual := strconv.FormatUint(uint64(m.mt_gen()), 10); actual != strings.Split(expected[i], " ")[1] {
			tt.Fatalf("expected: %s for %dth rand, got: %s\n", expected[i], i + 1, actual)
		}
	}
}