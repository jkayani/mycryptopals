package rng

import (
	"fmt"
	"jkayani.local/mycrypto/utils"
)

const (
	Mt_w = 32
	Mt_n = 624
	Mt_m = 397
	Mt_r = 31
	Mt_a = 0x9908B0DF
	Mt_u = 11
	Mt_d = 0xFFFFFFFF
	Mt_s = 7
	Mt_b = 0x9D2C5680
	Mt_t = 15
	Mt_c = 0xEFC60000
	Mt_l = 18
	Mt_f = 1812433253
	bit_32 = 0xFFFFFFFF
)

type MTrng struct {
	Idx int
	State []int
}

// https://en.wikipedia.org/wiki/Mersenne_Twister

func (m *MTrng) Init(seed int) {
	m.State = make([]int, Mt_n)
	m.State[0] = seed
	for i := 1; i < Mt_n; i += 1 {
		m.State[i] = (Mt_f * utils.Xorbytes(m.State[i - 1], (m.State[i - 1] >> (Mt_w - 2))) + i) & bit_32
	}
	fmt.Sprintf("State: %v\n", m.State)
	m.Idx = 0
}

func (m *MTrng) Gen() int {
	// Idx will only wrap around _after_ Idx=623
	// protect k + 1 access by wrapping around early as needed
	xk, xk1 := m.State[m.Idx], m.State[(m.Idx + 1) % Mt_n]
	// fmt.Printf("using xk: %d, xk1: %d\n", xk, xk1)

	upper_xk := (0x80000000 & xk)
	lower_xk1 := (0x7FFFFFFF & xk1)

	concat := upper_xk | lower_xk1
	// fmt.Printf("using concat: %d\n", concat)
	concat_a := concat >> 1
	if concat % 2 == 1 {
		concat_a = utils.Xorbytes(concat_a, Mt_a)
	}
	// fmt.Printf("using concat a: %d\n", concat_a)
	nxt := utils.Xorbytes(m.State[(Mt_m + m.Idx) % Mt_n], concat_a)
	// fmt.Printf("using m: %d (Idx: %d)\n", m.State[(Mt_m + m.Idx) % Mt_n], (Mt_m + m.Idx) % Mt_n)

	// k=227, m=397 => overflow
	// after first val (when k=0) is generated, State[0] val is not needed
	// overwrite to maintain circular buffer
	// when dealing with k=227, the desired value (State[624]) will actually be in State[0]
	m.State[m.Idx] = nxt

	temper := utils.Xorbytes(nxt, (nxt >> Mt_u) & Mt_d)
	// fmt.Printf("nxt: %d, temper 1: %d\n", nxt, temper)
	temper = utils.Xorbytes(temper, (temper << Mt_s) & Mt_b)
	// fmt.Printf("temper 2: %d\n", temper)
	temper = utils.Xorbytes(temper, (temper << Mt_t) & Mt_c)
	// fmt.Printf("temper 3: %d\n", temper)
	temper = utils.Xorbytes(temper, (temper >> Mt_l))
	// fmt.Printf("rnd: %d\n", temper)

	// Idx must wrap around after Idx=623
	m.Idx = (m.Idx + 1) % Mt_n
	return temper
}

func (m *MTrng) Process_MT_crypt(seed int, inbytes []byte) []byte {
	m.Init(seed)

	basemask := 0xFF000000
	masks := []int{basemask, basemask >> 8, basemask >> 16, basemask >> 24}
	keystream := make([]byte, len(inbytes))
	maskIdx := 0
	var rng int
	for i := 0; i < len(inbytes); i += 1 {
		if maskIdx == 0 {
			rng = m.Gen()
			// fmt.Printf("using rng %d for Idx %d\n", rng, i)
		}
		keystream[i] = byte((rng & masks[maskIdx]) >> ((len(masks) - 1 - maskIdx) * 8))
		maskIdx = (maskIdx + 1) % len(masks)
	}

	outbytes := make([]byte, len(inbytes))
	for k, v := range inbytes {
		outbytes[k] = utils.Xorbytes(keystream[k], v)
	}

	// fmt.Printf("using keystream: %v\n", keystream)
	return outbytes
}