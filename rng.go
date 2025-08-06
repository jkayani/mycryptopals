package main

import (
	"fmt"
)

const (
	mt_w = 32
	mt_n = 624
	mt_m = 397
	mt_r = 31
	mt_a = 0x9908B0DF
	mt_u = 11
	mt_d = 0xFFFFFFFF
	mt_s = 7
	mt_b = 0x9D2C5680
	mt_t = 15
	mt_c = 0xEFC60000
	mt_l = 18
	mt_f = 1812433253
	bit_32 = 0xFFFFFFFF
)

type MTrng struct {
	idx int
	state []int
}

// https://en.wikipedia.org/wiki/Mersenne_Twister

func (m *MTrng) mt_init(seed int) {
	m.state = make([]int, mt_n)
	m.state[0] = seed
	for i := 1; i < mt_n; i += 1 {
		m.state[i] = (mt_f * xorbytes(m.state[i - 1], (m.state[i - 1] >> (mt_w - 2))) + i) & bit_32
	}
	fmt.Sprintf("state: %v\n", m.state)
	m.idx = 0
}

func (m *MTrng) mt_gen() int {
	// idx will only wrap around _after_ idx=623
	// protect k + 1 access by wrapping around early as needed
	xk, xk1 := m.state[m.idx], m.state[(m.idx + 1) % mt_n]

	upper_xk := (0x80000000 & xk)
	lower_xk1 := (0x7FFFFFFF & xk1)

	concat := upper_xk | lower_xk1
	concat_a := concat >> 1
	if concat % 2 == 1 {
		concat_a = xorbytes(concat_a, mt_a)
	}
	nxt := xorbytes(m.state[(mt_m + m.idx) % mt_n], concat_a)

	// k=227, m=397 => overflow
	// after first val (when k=0) is generated, state[0] val is not needed
	// overwrite to maintain circular buffer
	// when dealing with k=227, the desired value (state[624]) will actually be in state[0]
	m.state[m.idx] = nxt

	temper := xorbytes(nxt, (nxt >> mt_u) & mt_d)
	temper = xorbytes(temper, (temper << mt_s) & mt_b)
	temper = xorbytes(temper, (temper << mt_t) & mt_c)
	temper = xorbytes(temper, (temper >> mt_l))

	// idx must wrap around after idx=623
	m.idx = (m.idx + 1) % mt_n
	return temper
}

