package main

import (
	t "testing"
	// "fmt"
	"strings"
	"strconv"
	"slices"
	"os"
)

func Test_MT(tt *t.T) {
	m := MTrng{}
	oeis_seed := 5489

	// https://oeis.org/A221557
	data, _ := os.ReadFile("./oeis_mersenne.txt")
	expected := strings.Split(string(data), "\n")

	m.mt_init(oeis_seed)
	max := len(expected) - 1
	for i := 0; i <= max; i += 1 {
		if actual := strconv.Itoa(m.mt_gen()); actual != strings.Split(expected[i], " ")[1] {
			tt.Fatalf("expected: %s for %dth rand, got: %s\n", expected[i], i + 1, actual)
		}
	}
}

func Test_MT_Crypt(tt *t.T) {
	m := MTrng{}
	s := []byte("hello world")
	enc := m.process_mt_crypt(5489, s)
	dec := m.process_mt_crypt(5489, enc)

	tt.Logf("MT encryption of %v: %v\n", s, enc)

	if ! slices.Equal(s, dec) {
		tt.Fatalf("expected MT decrypt of %v to yield %v but got %v\n", enc, s, dec)
	}
}