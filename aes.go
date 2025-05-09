package main

import (
	"fmt"
	"slices"
)

var (

	// TODO: how on earth is this defined?
	sbox [][]byte = [][]byte {
		[]byte{0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76},
		[]byte{0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0},
		[]byte{0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15},
		[]byte{0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75},
		[]byte{0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84},
		[]byte{0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf},
		[]byte{0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8},
		[]byte{0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2},
		[]byte{0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73},
		[]byte{0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb},
		[]byte{0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79},
		[]byte{0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08},
		[]byte{0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a},
		[]byte{0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e},
		[]byte{0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf},
		[]byte{0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16},
	}
	reversebox [][]byte = [][]byte{
		[]byte{0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb},
		[]byte{0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb},
		[]byte{0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e},
		[]byte{0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25},
		[]byte{0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92},
		[]byte{0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84},
		[]byte{0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06},
		[]byte{0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b},
		[]byte{0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73},
		[]byte{0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e},
		[]byte{0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b},
		[]byte{0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4},
		[]byte{0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f},
		[]byte{0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef},
		[]byte{0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61},
		[]byte{0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d},
	}

	firstmixword []byte = []byte{2, 3, 1, 1}
 	mix [][]byte = [][]byte {
		firstmixword,
		rotateright(firstmixword, 1),
		rotateright(firstmixword, 2),
		rotateright(firstmixword, 3),
	}

	firstreversemixword []byte = []byte{14, 11, 13, 9}
	reversemix [][]byte = [][]byte {
		firstreversemixword,
		rotateright(firstreversemixword, 1),
		rotateright(firstreversemixword, 2),
		rotateright(firstreversemixword, 3),
	}

	constants = []byte{0x01 ,0x02 ,0x04 ,0x08 ,0x10 ,0x20 ,0x40 ,0x80 ,0x1B ,0x36}
)

const (
	wordlen_bytes = 4
	keylen_words = 4
	blocksize_bytes = 16
	ROUND_COUNT = 11
)

type word []byte

type AES struct {
	key []byte
	iv []word
	roundkeys [][]word
	cipherbytes []word
	debug bool
}

func rotateleft(bytes []byte, shift int) []byte {
	var nb []byte
	for i := 0; i < shift; i += 1 {
		nb = bytes[1:]
		nb = append(nb, bytes[0])
		bytes = nb
	}
	return nb
}

func rotateright(bytes []byte, shift int) []byte {
	var nb []byte
	for i := 0; i < shift; i += 1 {
		nb = bytes[0:len(bytes)- 1]
		nb = append(bytes[len(bytes) - 1:], nb...)
		bytes = nb
	}
	return nb
}

func sub(b byte, box [][]byte) byte {
	return box[(b & firstmask(4)) >> 4][b & lastmask(4)]
}

// https://en.wikipedia.org/wiki/Finite_field_arithmetic#Rijndael's_(AES)_finite_field
func multiply(a, b byte) (c byte) {
	for i := 0; i < 8; i += 1 {
		if a == 0 || b == 0 {
			break
		}

		if b & lastmask(1) > 0 {
			c = xorbytes(c, a)
		}
		b >>= 1
		carry := a & firstmask(1)
		a <<= 1
		if carry > 0 {
			a = xorbytes(a, 0x1b)
		}
	}
	return c
}

func matrixmul(col word, matrix [][]byte) (w word) {
	w = make(word, len(col))
	for k, row := range matrix {
		for colidx, elm := range row {
			pairwisexor := multiply(col[colidx], elm)
			w[k] = xorbytes(w[k], pairwisexor)
		}
	}
	return
}

func wordstobytes(words []word) []byte {
	r := []byte{}
	for _, w := range words {
		for _, b := range w {
			r = append(r, b)
		}
	}
	return r
}

func bytestowords(bytes []byte) []word {
	words := []word{}
	w := word{}
	for _, nbyte := range bytes {
		if len(w) == wordlen_bytes {
			words = append(words, w)
			w = word{nbyte}
		} else {
			w = append(w, nbyte)
		}
	}
	words = append(words, w)
	return words
}

func transpose(w []word) []word {
	new := []word{}
	for colidx, _ := range w[0] {
		newrow := word{}
		for _, row := range w {
			newrow = append(newrow, row[colidx])
		}
		new = append(new, newrow)
	}
	return new
}

func (a *AES) debugf(format string, args ...any) {
	if a.debug {
		fmt.Printf(format, args...)
	}
}

func (a *AES) makeroundkeys(direction bool) {
	// First round key will be the 4 words of the original key
	a.roundkeys = [][]word{bytestowords(a.key)}

	// Subsequent round keys will depend on previous round key
	wnum := keylen_words
	roundkey := []word{}
	round := 1
	for round < ROUND_COUNT {
		if len(roundkey) == keylen_words {
			a.roundkeys = append(a.roundkeys, roundkey)
			a.debugf("expandroundkey: generated round key: %v for round %d\n", roundkey, round)
			roundkey = []word{}
			round += 1
		} else {
			prevround := a.roundkeys[round - 1]
			fourbefore := slices.Clone(prevround[wnum % keylen_words])

			// Previous word may come from previous round key 
			// if the current round key has 0 words generated so far
			var prevword word	
			if len(roundkey) == 0 {
				prevword = slices.Clone(prevround[len(prevround) - 1])
			} else {
				prevword = slices.Clone(roundkey[len(roundkey) - 1])
			}

			// 3 possible branches in piece-wise: https://en.wikipedia.org/wiki/AES_key_schedule#The_key_schedule
			// Our input key is always 4 words so N > 6, wnum % 6 == 4 branch is ignored
			if wnum % keylen_words == 0 {
				middle := rotateleft(prevword, 1)
				for k, b := range middle {
					middle[k] = sub(b, sbox)
				}
				nextword := fixedxor(fourbefore, middle)
				nextword = fixedxor(nextword, []byte{constants[wnum / keylen_words - 1], 0, 0, 0})
				roundkey = append(roundkey, nextword)
			} else {
				nextword := fixedxor(fourbefore, prevword)
				roundkey = append(roundkey, nextword)
			}
			wnum += 1
		}
	}

	// The round keys have to be applied in REVERSE order to decrypt
	if direction {
		slices.Reverse(a.roundkeys)
	}
}

// Iterator to go through each 4x4 block and write results into correct offsets
// direction is false for encrypt, true for decrypt
func (a *AES) blockiterator(round int, direction bool, op func (round int, direction bool, state []word) []word) {
	for i := 0; i < len(a.cipherbytes) - 3; i += 4 {
		state := op(round, direction, a.cipherbytes[i:i + 4])	
		for k := i; k < i + 4; k += 1 {
			a.cipherbytes[k] = state[k % 4]
		}
	}
}

func (a *AES) addroundkey(round int) {
	a.debugf("addroundkey: cipherbytes BEFORE adding round key from round %d: %v\n", round, a.cipherbytes)
	a.blockiterator(round, false, func(r int, d bool, state []word) []word {
		a.debugf("addroundkey: operating on block %v\n", state)

		// The bytes of the round key correspond to the cipher bytes in order they appear
		// Thus, skip transpose - data is aleady in the right order
		for j, word := range state {
			state[j] = fixedxor(word, a.roundkeys[round][j])
		}
		return state
	})
	a.debugf("addroundkey: cipherbytes AFTER adding round key from round %d: %v\n", round, a.cipherbytes)
}

func (a *AES) shiftrows(round int, direction bool) {
	a.debugf("shiftrows: cipherbytes BEFORE %t shift on round %d: %v\n", direction, round, a.cipherbytes)
	a.blockiterator(round, direction, func(r int, d bool, state []word) []word {
		s := transpose(state)
		a.debugf("shiftrows: operating on block %v; transpose => %v\n", state, s)

		// Shift all but first row/word left by j
		for j := 1; j < len(s); j += 1 {
			f := rotateleft
			if d {
				f = rotateright
			}
			s[j] = f(s[j], j)
		}
		return transpose(s)
	})
	a.debugf("cipherbytes AFTER %t shift on round %d: %v\n", direction, round, a.cipherbytes)
}

func (a *AES) substitute(round int, direction bool) {
	a.debugf("substitute: cipherbytes BEFORE %t substitute on round %d: %v\n", direction, round, a.cipherbytes)
	a.blockiterator(round, direction, func(r int, d bool, state []word) []word {
		s := transpose(state)
		a.debugf("substitute: operating on block %v; transpose => %v\n", state, s)

		// For each word in the s, substitute each byte of each word
		for wnum := 0; wnum < len(s); wnum += 1 {
			b := sbox
			if direction {
				b = reversebox
			}
			for k, nbyte := range s[wnum] {
				s[wnum][k] = sub(nbyte, b)
			}
		}
		return transpose(s)
	})
	a.debugf("substitute: cipherbytes AFTER %t substitute on round %d: %v\n", direction, round, a.cipherbytes)
}

func (a *AES) mixcols(round int, direction bool) {
	a.debugf("mixcols: cipherbytes BEFORE %t mix columns on round %d: %v\n", direction, round, a.cipherbytes)
	a.blockiterator(round, direction, func(r int, d bool, state []word) []word {
		a.debugf("mixcols: operating on block %v\n", state)
		
		matrix := mix
		if direction {
			matrix = reversemix
		}

		// Since each col of the state needs to be multiplied, skip the transpose
		// the rows of cipherbytes are the columns of the state
		for j, row := range state {
			state[j] = matrixmul(row, matrix)	
		}
		return state
	})
	a.debugf("mixcols: cipherbytes AFTER %t mix columns on round %d: %v\n", direction, round, a.cipherbytes)
}

func (a *AES) Decrypt_ECB(cipherbytes, key []byte) []byte {
	a.cipherbytes = bytestowords(cipherbytes)
	a.key = key
	a.makeroundkeys(true)
	result := a.decrypt_ecb()

	fmt.Printf("AES ECB decrypt complete: %s\n", string(result))
	a.debugf("raw bytes: %v\n\n", result)

	return result
}

func (a *AES) DecryptFile_ECB(filename, key string) []byte {
	s := read(filename)
	rawbytes := []byte{}
	for s.Scan() {
		rawbytes = append(rawbytes, base64decode(s.Text())...)
	}

	a.cipherbytes = bytestowords(rawbytes)
	a.key = []byte(key)
	a.makeroundkeys(true)
	result := a.decrypt_ecb()

	fmt.Printf("AES ECB decrypt complete: %s\n", string(result))
	a.debugf("raw bytes: %v\n\n", result)

	return result
}

func (a *AES) decrypt_ecb() []byte {
	round := 0

	a.addroundkey(round)
	a.shiftrows(round, true)
	a.substitute(round, true)
	round += 1

	for round < ROUND_COUNT - 1 {
		a.addroundkey(round)
		a.mixcols(round, true)
		a.shiftrows(round, true)
		a.substitute(round, true)
		round += 1
	}
	a.addroundkey(round)

	return wordstobytes(a.cipherbytes)
}

func (a *AES) encrypt_ecb() []byte {
	round := 0

	a.addroundkey(round)
	round += 1

	for round < ROUND_COUNT - 1 {
		a.substitute(round, false)
		a.shiftrows(round, false)
		a.mixcols(round, false)
		a.addroundkey(round)
		round += 1
	}
	a.substitute(round, false)
	a.shiftrows(round, false)
	a.addroundkey(round)

	return wordstobytes(a.cipherbytes)
}

func (a *AES) Encrypt_ECB(cipherbytes, key []byte) []byte {
	a.cipherbytes = bytestowords(cipherbytes)
	a.key = key
	a.makeroundkeys(false)
	result := a.encrypt_ecb()
	// b16 := base16encode_bytes(result)

	// fmt.Printf("AES ECB encrypt complete: %s\n", b16)
	a.debugf("raw bytes: %v\n\n", result)

	return result
}

func (a *AES) decrypt_cbc(fullcipherbytes []byte) []byte {
	words := bytestowords(fullcipherbytes)

	// The cipher core assumes all cipher blocks are operated on in-parallel
	// Thus, end result is normally all decryped blocks
	// For CBC, each block must be decrypted individually and XORed with still fully-encrypted previous block
	// So, feed blocks individually to cipher core instead of all at once
	for i := len(words); i >= 4; i -= 4 {
		firstblock := words[i - 4 : i]
		secondblock := a.iv
		if i != 4 {
			secondblock = words[i - 8 : i - 4]
		}
		a.debugf("decrypt_cbc: first block: %v; second block: %v\n", firstblock, secondblock)
	
		a.cipherbytes = firstblock
		a.decrypt_ecb()
		a.debugf("decrypt_cbc: pre-XOR, decryption of block %d: %v\n", i / 4, a.cipherbytes)
		firstblock = a.cipherbytes

		for k, w := range firstblock {
			firstblock[k] = fixedxor(w, secondblock[k])
		}
		a.debugf("decrypt_cbc: post-XOR, decryption of block %d: %v\n", i / 4, firstblock)

		for k, w := range firstblock {
			words[i - 4 + k] = w
		}
	}

	return wordstobytes(words)
}

func (a *AES) Decrypt_CBC(cipherbytes, key, iv []byte) []byte {
	a.key = key
	a.iv = bytestowords(iv)
	a.makeroundkeys(true)
	result := a.decrypt_cbc(cipherbytes)

	a.debugf("AES CBC decrypt complete: %s\nraw bytes: %v\n\n", string(result), result)

	return result
}

func (a *AES) DecryptFile_CBC(filename, key string, iv []byte) []byte {
	s := read(filename)
	rawbytes := []byte{}
	for s.Scan() {
		rawbytes = append(rawbytes, base64decode(s.Text())...)
	}

	a.key = []byte(key)
	a.iv = bytestowords(iv)
	a.makeroundkeys(true)
	result := a.decrypt_cbc(rawbytes)

	a.debugf("AES CBC decrypt complete: %s\nraw bytes: %v\n\n", string(result), result)

	return result
}

func (a *AES) encrypt_cbc(fullcipherbytes []byte) []byte {
	words := bytestowords(fullcipherbytes)

	// The cipher core assumes all cipher blocks are operated on in-parallel
	// Thus, end result is normally all decryped blocks
	// For CBC, each block must be XORed with decrypted next block and encrypted individually
	// So, feed blocks individually to cipher core instead of all at once
	for i := 0; i <= len(words) - 4; i += 4 {
		firstblock := words[i : i + 4]
		secondblock := a.iv
		if i > 0 {
			secondblock = words[i - 4 : i]
		}
		a.debugf("encrypt_cbc: block num: %d; first block: %v; second block: %v \n", i, firstblock, secondblock)

		for k, w := range firstblock {
			firstblock[k] = fixedxor(w, secondblock[k])
		}
		a.debugf("encrypt_cbc: post-XOR of block %d: %v\n", i / 4, firstblock)
	
		a.cipherbytes = firstblock
		a.encrypt_ecb()
		a.debugf("encrypt_cbc: post-encrypt of block %d: %v\n", i / 4, a.cipherbytes)

		for k, w := range a.cipherbytes {
			words[i + k] = w
		}
	}

	return wordstobytes(words)
}

func (a *AES) Encrypt_CBC(cipherbytes, key, iv []byte) []byte {
	a.key = key
	a.iv = bytestowords(iv)
	a.makeroundkeys(false)
	result := a.encrypt_cbc(cipherbytes)
	b16 := base16encode_bytes(result)

	fmt.Printf("AES CBC encrypt complete: %s\n", b16)
	a.debugf("raw bytes: %v\n\n", result)

	return result
}

// Break out an 8-byte (uint64) int into it's individual 8 bytes
func int_to_bytes(input uint64) []byte {
	result := []byte{}
	shift_len := 16 - 2
	for i := 0; i < 8; i += 1 {
		r := (input & (0xff << (shift_len * 4))) >> (shift_len * 4)
		// fmt.Printf("iteration: %d, input: %d, shift_len: %d, result: %d\n", i, input, shift_len, r)

		result = append(result, byte(r))
		shift_len -= 2
	}
	// fmt.Printf("result: %v\n", result)
	return result
}

func (a *AES) process_ctr(inbytes, key, nonce []byte, counter_init uint64) []byte {
	var counter uint64 = 0
	result := []byte{}

	for i := 0; i < blocklen(inbytes); i += 1 {
		counter_bytes := int_to_bytes(counter)

		// The counter has to be in little-endian
		slices.Reverse(counter_bytes)

		payload := append(slices.Clone(nonce), counter_bytes...)
		cipherbytes := a.Encrypt_ECB(payload, key)
		a.debugf("block %d: using counter value %d (%v), payload: %v\nCTR ciphertext: %v\n", i, counter, counter_bytes, payload, cipherbytes)

		curr_block := nth_block(inbytes, i)

		// Only use as much ciphertext as there is input data left to work with
		r := fixedxor(curr_block, cipherbytes[0: len(curr_block)])
		result = append(result, r...)
		a.debugf("\nblock %d\nbefor: %v\nafter: %v\n\n", i, curr_block, r)

		counter += 1
	}

	return result
}