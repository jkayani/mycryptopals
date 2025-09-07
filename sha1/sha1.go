package sha1

import (
	"fmt"
	"slices"
	"jkayani.local/mycrypto/utils"
)

const (
	Blocksize_bytes = 64
	wordsize_bytes = 4
	bit_32 = 0xFFFFFFFF
	round_count = 80
)

type word []byte

type SHA1 struct {
	Debug bool
}

// https://1hundredwire.com/how-sha-1-works-a-step-by-step-breakdown/
// https://nvlpubs.nist.gov/nistpubs/Legacy/FIPS/fipspub180-1.pdf

func s(val, factor int) int {
	var n int
	for i := 0; i < factor; i += 1 {

		// Take first bit, and shift into the position it should go in
		t := val & 0x80000000
		t = t >> (31 - (factor - i - 1))
		n |= t

		// Important: clamp to 32 bits since using an 64-bit wide int here
		val = (val << 1) & bit_32
	}
	return val | n
}

func f(round int, b, c, d int) int {
	switch true {
	case round >= 0 && round <= 19: {
		return ((b & c) | (^b & d))
	}
	case round >= 20 && round <= 39:
		fallthrough
	case round >= 60 && round <= 79:
		return utils.Xorbytes(utils.Xorbytes(b, c), d)
	case round >= 40 && round <= 59:
		return (((b & c) | (b & d)) | (c & d))
	default:
		panic(fmt.Sprintf("SHA-1: %d is not recognized round value", round))
	}
	return 0xbeef
}

func k(round int) int {
	switch true {
	case round >= 0 && round <= 19:
		return 0x5A827999
	case round >= 20 && round <= 39:
		return 0x6ED9EBA1
	case round >= 40 && round <= 59:
		return 0x8F1BBCDC
	case round >= 60 && round <= 79:
		return 0xCA62C1D6
	default:
		panic(fmt.Sprintf("SHA-1: %d is not recognized round value", round))
	}
	return -1
}

func nth_block(bytes []byte, n int) []byte {
	if Blocksize_bytes * (n + 1) > len(bytes) {
		return bytes[Blocksize_bytes * n:]
	}
	return bytes[Blocksize_bytes * n : Blocksize_bytes * (n + 1)]
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

func (sha *SHA1) pad(plainbytes []byte) []byte {
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
	sha.debugf("total len: %d, round to next multiple of blocksize: %d, padding: %d\n", total_length, total_length_blocks, padding_needed)
	new_lastblocks = append(new_lastblocks, make([]byte, padding_needed)...)

	// Add len of original message, in bits, as encoded into 8 bytes
	original_len := utils.Int_to_bytes(uint64(len(plainbytes) * 8))
	new_lastblocks = append(new_lastblocks, original_len...)

	padded := append(plainbytes[0 : lastblock_idx], new_lastblocks...)
	if l := len(padded); l % Blocksize_bytes != 0 {
		panic(fmt.Sprintf("SHA-1 padding of input %v failed, got %v (%d bytes)\n", plainbytes, padded, l))
	}
	return padded
}

func (sha *SHA1) debugf(format string, rest ...interface{}) {
	if sha.Debug {
		fmt.Printf(format, rest...)
	}
}

func (sha *SHA1) Hash(plainbytes []byte) string {
	h := []int{
		0x67452301,
		0xEFCDAB89,
		0x98BADCFE,
		0x10325476,
		0xC3D2E1F0,
	}
	return sha.run(plainbytes, h, true)
}
func (sha *SHA1) ResumeHash(plainbytes []byte, h []int, pad bool) string {
	return sha.run(plainbytes, h, pad)
}

func (sha *SHA1) run(plainbytes []byte, h []int, pad bool) string {
	sha.debugf("input: %s\n", plainbytes)
	input := slices.Clone(plainbytes)

	if pad {
		input = sha.pad(plainbytes)
		sha.debugf("input padded: %v (%d)\n", input, len(input))
	}

	bl := blocklen(input)
	for b := range bl {
		block := nth_block(input, b)	
		sha.debugf("block: %v\n", block)
		var round_words []word
		for k := 0; k < len(block); k += 4 {
			round_words = append(round_words, block[k : k + 4])
		}
		// sha.debugf("round_words: %v\n", round_words)
		for i := 16; i < round_count; i += 1 {

			// Shift right since Bytes_to_int assumes a full 8-byte slice is given
			// Output will put the 4 bytes in first 4 instead of last 4 as desired
			parts := []int{
				utils.Bytes_to_int(round_words[i - 3]) >> 32,
				utils.Bytes_to_int(round_words[i - 8]) >> 32,
				utils.Bytes_to_int(round_words[i - 14]) >> 32,
				utils.Bytes_to_int(round_words[i - 16]) >> 32,
			}
			var r int
			for _, v := range parts {
				r = utils.Xorbytes(r, v)
			}
			round_words = append(round_words, utils.Int_to_bytes(uint64(s(r, 1)))[4:])
		}
		// sha.debugf("round_words: %v\n", round_words)

		sha.debugf("h values before block: %v\n", h)
		var a, b, c, d, e int = h[0], h[1], h[2], h[3], h[4]
		for t := range round_count {
			if len(round_words[t]) != 4 {
				panic(fmt.Sprintf("SHA-1 round %d has invalid round_word %v when processing block %d", t, round_words[t], b))
			}
			// sha.debugf("\n\nround %d before: %x %x %x %x %x\n", t, a, b, c, d, e)
			tmp := (s(a, 5) + f(t, b, c, d) + e + (utils.Bytes_to_int(round_words[t]) >> 32) + k(t)) & bit_32
			e, d, c, b, a = d, c, s(b, 30), a, tmp
			// sha.debugf("\n\nround %d after: %x %x %x %x %x\n", t, a, b, c, d, e)
		}
		h[0] += a
		h[1] += b
		h[2] += c
		h[3] += d
		h[4] += e
		for k, v := range h {
			h[k] = v & bit_32
		}
		sha.debugf("h values after block: %v\n", h)
	}

	var hash []byte
	for _, v := range h {
		bytes := utils.Int_to_bytes(uint64(v))
		sha.debugf("bytes: %v\n", bytes)
		hash = append(hash, bytes[4:]...)
	}
	if len(hash) != len(h) * wordsize_bytes {
		panic(fmt.Sprintf("SHA-1: hash is not correct length, got:\n%v\n(%d)\n", hash, len(hash)))
	}
	sha.debugf("raw hash: %v\n", hash)
	return utils.Base16encode_bytes(hash)
}