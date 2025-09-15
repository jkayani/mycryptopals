package md4

import (
	"fmt"
	"slices"
	"jkayani.local/mycrypto/utils"
)

const (
	Blocksize_bytes = 64
	wordsize_bytes = 4
	bit_32 = 0xFFFFFFFF
)

type word []byte

type MD4 struct {
	Debug bool
}

// https://www.ietf.org/rfc/rfc1320.txt
// Thanks to https://github.com/rpicard/py-md4/blob/master/md4-test-vectors.txt
// and https://gist.github.com/kangtastic/c3349fc4f9d659ee362b12d7d8c639b6
// for making clear the details I missed when reading the RFC

func s(val int, factor int) int {
	var n int
	for i := 0; i < int(factor); i += 1 {

		// Take first bit, and shift into the position it should go in
		t := val & 0x80000000
		t = (t >> (31 - (int(factor) - i - 1)))
		n |= t

		// Important: clamp to 32 bits since using an 64-bit wide int here
		val = (val << 1) & bit_32
	}
	return val | n
}

func h(b, c, d int) int {
	return utils.Xorbytes(utils.Xorbytes(b, c), d)
}

func g(b, c, d int) int {
	return (b & c) | (b & d) | (c & d)
}

func f(b, c, d int) int {
	return ((b & c) | (^b & d))
}

func nth_block(bytes []byte, n int) []byte {
	if Blocksize_bytes * (n + 1) > len(bytes) {
		return bytes[Blocksize_bytes * n:]
	}
	return bytes[Blocksize_bytes * n : Blocksize_bytes * (n + 1)]
}

func nth_word(block []byte, n int) int {
	w := slices.Clone(block[n * 4 : (n + 1) * 4])
	slices.Reverse(w)
	return utils.Bytes_to_int(w) >> 32
}

func blocklen(in []byte) int {
	blocklen := len(in) / Blocksize_bytes
	if len(in) % Blocksize_bytes != 0 {
		blocklen += 1
	}
	return blocklen
}

func Blocklen_n(l int) int {
	blocklen := l / Blocksize_bytes
	if l % Blocksize_bytes != 0 {
		blocklen += 1
	}
	return blocklen
}

func (md4 *MD4) pad(plainbytes []byte) []byte {
	blocks_needed := blocklen(plainbytes)
	lastblock_idx := Blocksize_bytes * (blocks_needed - 1)
	if blocks_needed == 0 {
		lastblock_idx = 0
	}

	// Append 1 bit
	var lastblock []byte
	if blocks_needed == 0 {
		lastblock = []byte{}
	} else {
		lastblock = nth_block(plainbytes, blocks_needed - 1)
	}
	new_lastblocks := slices.Clone(lastblock)
	if len(lastblock) < Blocksize_bytes {
		// The last block is not full, so append a byte with first bit set to "append 1 bit"

		new_lastblocks = append(new_lastblocks, 0x80)
	} else {
		// The last block is full, so start a new block to contain the byte with first bit set

		lastblock_idx = len(lastblock)
		new_lastblocks = []byte{0x80}
	}

	// Add 0s, accounting for the extra byte needed for the 1-bit appended, and the 8 bytes needed for length encoding
	var total_length int
	if blocks_needed == 0 {
		total_length = len(new_lastblocks) + 8
	} else {
		total_length = (blocks_needed - 1) * Blocksize_bytes + len(new_lastblocks) + 8
	}
	total_length_blocks := Blocklen_n(total_length)
	padding_needed := total_length_blocks * Blocksize_bytes - total_length
	md4.debugf("total len: %d, round to next multiple of blocksize: %d, padding: %d\n", total_length, total_length_blocks, padding_needed)
	new_lastblocks = append(new_lastblocks, make([]byte, padding_needed)...)

	// Add len of original message, in bits, as encoded into 8 bytes
	original_len := utils.Int_to_bytes(uint64(len(plainbytes) * 8))
	slices.Reverse(original_len)
	new_lastblocks = append(new_lastblocks, original_len...)

	padded := append(plainbytes[0 : lastblock_idx], new_lastblocks...)
	if l := len(padded); l % Blocksize_bytes != 0 {
		panic(fmt.Sprintf("MD4 padding of input %v failed, got %v (%d bytes)\n", plainbytes, padded, l))
	}
	return padded
}
	
type round struct {
	order []*int
	windexes []int
	factor int
}
func (md4 *MD4) process_round(rs []round, fn func(v []*int, k, factor int)) {
	var kidx int
	for i, j := 0, 0; i < 16; i, j = i + 1, (j + 1) % 4 {
		// md4.debugf("invoking round func row by row with j=%d, kidx=%d with args: %v, %v, %v\n", j, kidx, rs[j].order, rs[j].windexes[kidx], rs[j].factor)
		fn(rs[j].order, rs[j].windexes[kidx], rs[j].factor)
		if j == 3 {
			kidx += 1
		}
	}
}

func (md4 *MD4) debugf(format string, rest ...interface{}) {
	if md4.Debug {
		fmt.Printf(format, rest...)
	}
}

func (md4 *MD4) Hash(plainbytes []byte) string {
	md := []int{
		0x67452301,
		0xefcdab89,
		0x98badcfe,
		0x10325476,
	}
	return md4.run(plainbytes, md, true)
}
func (md4 *MD4) ResumeHash(plainbytes []byte, md []int, pad bool) string {
	return md4.run(plainbytes, md, pad)
}

func (md4 *MD4) run(plainbytes []byte, md []int, pad bool) string {
	// md4.debugf("input: %s\n", plainbytes)
	input := slices.Clone(plainbytes)

	if pad {
		input = md4.pad(plainbytes)
		md4.debugf("input padded: %v (%d)\n", input, len(input))
	}

	bl := blocklen(input)
	for b := range bl {
		block := nth_block(input, b)	
		md4.debugf("block: %v\n", block)

		var a, b, c, d int = md[0], md[1], md[2], md[3]
		// md4.debugf("md before rounds: %x, %x, %x, %x\n", md[0], md[1], md[2], md[3])
		// md4.debugf("buffers before rounds: %x, %x, %x, %x\n", a, b, c, d)

		var round1_f = func(v []*int, k int, factor int) {
			res := f(*(v[1]), *(v[2]), *(v[3]))
			nth := nth_word(block, k)
			ans1 := (*(v[0]) + res + nth) & bit_32
			ans := s(ans1, factor)
			// md4.debugf("%x + f(%x %x %x) => %x + %.8x(%v) = %x(%d) <<< %d => %x (%d)\n", *(v[0]), *(v[1]), *(v[2]), *(v[3]), res, nth, utils.Int_to_bytes(uint64(nth)), ans1, ans1, factor, ans, ans)
			*(v[0]) = ans
		}
		var round2_f = func(v []*int, k, factor int) {
			res := g(*(v[1]), *(v[2]), *(v[3]))
			nth := nth_word(block, k)
			ans1 := (((*(v[0]) + res + nth) + int(0x5A827999))) & bit_32
			ans := s(ans1, factor)
			// md4.debugf("%x + g(%x %x %x) => %x + %x(%v) + sqrt(2) = %x(%d) <<< %d => %x (%d)\n", *(v[0]), *(v[1]), *(v[2]), *(v[3]), res, nth, utils.Int_to_bytes(uint64(nth)), ans1, ans1, factor, ans, ans)
			*(v[0]) = ans
		}
		var round3_f = func(v []*int, k, factor int) {
			res := h(*(v[1]), *(v[2]), *(v[3]))
			ans1 := (((*(v[0]) + res + nth_word(block, k)) + 0x6ED9EBA1)) & bit_32
			ans := s(ans1, factor)
			// md4.debugf("%x + %x %x %x h=> %x + %x(%v) + sqrt(3) = %x <<< %d => %x\n", *(v[0]), *(v[1]), *(v[2]), *(v[3]), res, nth_word(block, k), utils.Int_to_bytes(uint64(nth_word(block, k))), ans1, factor, ans)
			*(v[0]) = ans
		}

		md4.debugf("Before round 1: %x, %x, %x, %x\n", a, b, c, d)
		round1 := []round {
			round{[]*int{&a, &b, &c, &d}, []int{0, 4, 8, 12}, 3},
			round{[]*int{&d, &a, &b, &c}, []int{1, 5, 9 , 13}, 7},
			round{[]*int{&c, &d, &a, &b}, []int{2, 6, 10, 14}, 11},
			round{[]*int{&b, &c, &d, &a}, []int{3, 7, 11, 15}, 19},
		}
		md4.process_round(round1, round1_f)
		md4.debugf("After round 1: %x, %x, %x, %x\n", a, b, c, d)
		md4.debugf("\n\n")
		round2 := []round {
			round{[]*int{&a, &b, &c, &d}, []int{0, 1, 2, 3}, 3},
			round{[]*int{&d, &a, &b, &c}, []int{4, 5, 6, 7}, 5},
			round{[]*int{&c, &d, &a, &b}, []int{8, 9, 10, 11}, 9},
			round{[]*int{&b, &c, &d, &a}, []int{12, 13, 14, 15}, 13},
		}
		md4.process_round(round2, round2_f)
		md4.debugf("After round 2: %x, %x, %x, %x\n", a, b, c, d)
		md4.debugf("\n\n")
		round3 := []round {
			round{[]*int{&a, &b, &c, &d}, []int{0, 2, 1, 3}, 3},
			round{[]*int{&d, &a, &b, &c}, []int{8, 10, 9, 11}, 9},
			round{[]*int{&c, &d, &a, &b}, []int{4, 6, 5, 7}, 11},
			round{[]*int{&b, &c, &d, &a}, []int{12, 14, 13, 15}, 15},
		}
		md4.process_round(round3, round3_f)
		md4.debugf("\n\n")
		md4.debugf("after rounds: %x, %x, %x, %x\n", a, b, c, d)
		md[0] += a
		md[1] += b
		md[2] += c
		md[3] += d
		for k, v := range md {
			md[k] = v & bit_32
		}
		md4.debugf("md values after block: %v\n", md)
	}

	var hash []byte
	for _, v := range md {
		bytes := utils.Int_to_bytes(uint64(v))
		slices.Reverse(bytes)
		md4.debugf("bytes: %v\n", bytes)
		hash = append(hash, bytes[0:4]...)
	}
	if len(hash) != len(md) * wordsize_bytes {
		panic(fmt.Sprintf("MD4: hash is not correct length, got:\n%v\n(%d)\n", hash, len(hash)))
	}
	md4.debugf("raw hash: %v\n", hash)
	return utils.Base16encode_bytes(hash)
}