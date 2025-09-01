package utils

import (
	"fmt"
	"slices"
	"math"
	"math/rand"
	"strconv"
	"os"
	"bufio"
)

const (
	blocksize_bytes = 16
	Bit_32 = 0xFFFFFFFF
)

func Read(file string) *bufio.Scanner {
	f, err := os.Open(file)
	if err != nil {
		panic(fmt.Sprintf("cannot read %s: %s", file, err))
	}

	return bufio.NewScanner(f)
}

func Bits(n, padding int) []int {
	bits := make([]int, 0)

	// Calculate bits (in reverse order)
	k := n
	for k > 1 {
		bits = append(bits, k % 2)
		k /= 2
	}

	// Pad
	bits = append(bits, k)
	for k = len(bits); k < padding; k += 1 {
		bits = append(bits, 0)
	}

	slices.Reverse(bits)
	return bits
}

func Bitval(bits []int) int {
	var sum int

	// Compute decimal value of given bits
	// for bit := 0; bit < len(bits); bit += 1 {
	// 	sum += int(math.Pow(float64(2), float64(len(bits) - bit - 1))) * bits[bit]
	// }

	for k, v := range bits {
		sum |= v << (len(bits) - k - 1)
	}
	return sum
}

func Bitstream_bytes(bits []int) []byte {
	res := make([]byte, 0)

	for i := 0; i < len(bits); i += 8 {
		b := bits[i:]
		if i + 8 < len(bits) {
			b = bits[i : i + 8]
		}
		res = append(res, byte(Bitval(b)))
	}

	return res
}

func Bytes_to_int(b []byte) int {
	if len(b) > 8 {
		panic(fmt.Sprintf("Bytes_to_int: cannot fit %d bytes into 64-bit int", len(b)))
	}
	var result int
	for k, v := range b {
		result |= int(v) << (64 - 8 * (k + 1))
	}
	return result
}

func Tobase64(val int) (ascii int) {
	if val == 62 {

		// maps to +
		ascii = 43
	} else if val == 63 {

		// maps to /
		ascii = 47
	} else if val > 51 {

		// values that map to digits
		ascii = val - (52 - 48)
	} else if val > 25{

		// values that map to lower-case
		ascii = val + (97 - 26)
	} else {

		// values that map to upper-case
		ascii = 65 + val
	}
	return 
}

func Tobase16(val int) (ascii int) {
	if val >= 10 {
		return 87 + val
	}
	return 48 + val
}

// TODO: replace with strconv.ParseInt
func Frombase16char_tovalue(digit byte) (val int) {
	var modifier int
	if int(digit) >= 97 {
		modifier = 87
	} else if int(digit) >= 65 {
		modifier = 55
	} else {
		modifier = 48
	}
	return int(digit) - modifier
}

func Frombase64char_tovalue(digit byte) (val byte) {
	if digit == 43 {

		// maps to +
		val = 62
	} else if digit == 47 {

		// maps to /
		val = 63
	} else if digit >= 48 && digit <= 57 {

		// values that map to digits
		val = (digit - 48) + 52
	} else if digit >= 97 && digit <= 122 {

		// values that map to lower-case
		val = (digit - 97) + 26
	} else {

		// values that map to upper-case
		val = digit - 65
	}

	return val
}

func hex2base64_naive(hex string) string {
	bitstream := make([]int, 0)

	for k := 0; k < len(hex); k += 1 {

		// hex to binary, resolving hex digits to decimal values
		order := Bits(Frombase16char_tovalue(hex[k]), 4)

		// fmt.Printf("\nconvert %c as %d => %v", hex[k], int(hex[k]) - modifier, order)
		bitstream = append(bitstream, order...)
	}

	// fmt.Printf("\n%v (%s)", bitstream, hex)

	var result string

	// in base64 each char holds 6 bits
	for k := 0; k < len(bitstream); k += 6 {

		if (k + 5 >= len(bitstream)) {
			// if < 6 bits left, pad with 0
			v := bitstream[k:len(bitstream)]
			for i := len(v); i < 6; i += 1 {
				v = append(v, 0)
			}

			// convert result
			a := Tobase64(Bitval(v))
			// fmt.Printf("\nend: %d => (%c) (%d)", Bitval(v), a, a)
			result += fmt.Sprintf("%c", a)
			break
		}

		nextbits := bitstream[k:k + 6]
		val := Bitval(nextbits)
	
		ascii := Tobase64(val)
		char := fmt.Sprintf("%c", ascii)
		result += char

		// fmt.Printf("\n6 bits: %v, %d, base64: %s (%d)", nextbits, val, char, ascii)
	}

	return result
}

func Firstmask(firstkbits int) byte {
	switch firstkbits {
	case 1:
		return 0x80
	case 2:
		return 0xc0
	case 3:
		return 0xe0
	case 4:
		return 0xf0
	case 5:
		return 0xf8
	case 6:
		return 0xfc
	case 7:
		return 0xfe
	case 8:
		return 0xff
	}
	return 0x0
}

func Lastmask(lastkbits int) byte {
	switch lastkbits {
	case 1:
		return 0x1;
	case 2:
		return 0x3;
	case 3:
		return 0x7;
	case 4:
		return 0xf;
	}
	return 0x0;
}

func Hex2base64_bitwise(hex string) (result string) {
	currbitcnt, leftoverbitcnt := 0, 0
	var currbits, leftoverbits byte
	requiredbits := 6

	sixbits := make([]byte, 0)
	for i, _ := range(hex) {
		hexdigit := hex[i]

		// Find bitwise value of hexdigit and place in first 4 bits
		val := byte(Frombase16char_tovalue(hexdigit))
		nibble := val << 4

		bitwise := Bits(int(nibble), 8)
		fmt.Printf("\n%c has value %d. Shifted over to yield %d (%v)", hexdigit, val, nibble, bitwise)
		fmt.Printf("\ncurrent bit count: %d, required bits to yield 6: %d", currbitcnt, requiredbits)

		if requiredbits > currbitcnt {
			// Use entirety of hexdigit's bits

			// Shift the bits over so they don't overlap with already obtained bits
			currbits |= (nibble >> currbitcnt)
			currbitcnt += 4
			requiredbits -= 4
			currbits_bitwise := Bits(int(currbits), 8)
			fmt.Printf("\nconsumed val %d to yield currbits %d (%v), current bit count: %d, required bits to yield 6: %d", val, currbits, currbits_bitwise, currbitcnt, requiredbits)
		}	else {
			// Only part of the hexdigit's bits are needed

			// Extract first kth bits, shifting them over to not overlap with already obtained bits
			mask := Firstmask(requiredbits)
			nextbits := ((nibble & mask) >> currbitcnt)

			nextbits_bitwise := Bits(int(nextbits), 8)
			fmt.Printf("\napplied mask 0x%x to %d (%v) obtain bits %d (%v)", mask, nibble, bitwise, nextbits, nextbits_bitwise)

			// Add the extracted bits to current collection
			currbits |= nextbits
			currbits_bitwise := Bits(int(currbits), 8)
			currbitcnt += requiredbits
			fmt.Printf("\ncurrent bits: %d (%v)", currbits, currbits_bitwise)

			// The remaining bits are as follows:
			// Take the hex digit as originally found (where sig. bits are in last 4)
			// Take the last 2 bits from that
			// Shift those bits to top of byte
			leftoverbitcnt = 4 - requiredbits
			leftoverbits = (val & Lastmask(leftoverbitcnt)) << (8 - leftoverbitcnt)
			leftoverbits_bitwise := Bits(int(leftoverbits), 8)
			fmt.Printf("\nleft-over bits: %d (%v), left-over count: %d", leftoverbits, leftoverbits_bitwise, leftoverbitcnt)
		}

		// Desired bit count obtained, store collected value and reset state
		if currbitcnt == 6 {

			// Collected value must be shifted into correct pos to be read correctly
			currbits >>= 2
			currbits_bitwise := Bits(int(currbits), 8)
			sixbits = append(sixbits, currbits)
			fmt.Printf("\n6 bit value obtained, shifted left: %d (%v), 6 bit values thus far: %v", currbits, currbits_bitwise, sixbits)

			// If any left over bits, use them toward next collection
			currbits = leftoverbits
			currbitcnt = leftoverbitcnt
			requiredbits = 6 - leftoverbitcnt

			leftoverbits = 0
			leftoverbitcnt =0
		}
	}

	for _, val := range(sixbits) {
		result += fmt.Sprintf("%c", Tobase64(int(val)))
	}

	return result
}

func Hexdecode(hex string) (bytes []byte) {
	var i int
	for i = 0; i < len(hex) - 1; i += 2 {
		hexv, _ := (strconv.ParseUint(hex[i:i + 2], 16, 8))
		bytes = append(bytes, byte(hexv))
	}
	if i != len(hex) {
		hexv, _ := (strconv.ParseUint(hex[i:i + 1] + "0", 16, 8))
		bytes = append(bytes, byte(hexv))
	}
	return
}

func Base64decode(base64 string) (bytes []byte) {
	bytes = []byte{}

	bitstaken := 0
	bitsleft := 6
	c := 0
	var bits, value byte = 0, Frombase64char_tovalue(base64[c]) << 2
	for {
		// fmt.Printf("Bits taken: %d, bits left: %d\n", bitstaken, bitsleft)

		if bitstaken == 8 {
			// fmt.Printf("byte: %d\n", bits)
			bytes = append(bytes, bits)
			bits, bitstaken = 0, 0
		}

		if bitsleft == 0 {
			c += 1 

			// Consider padding chars as end of availible bits
			if c == len(base64) || base64[c] == 61 {
				break
			}
			value = Frombase64char_tovalue(base64[c]) << 2
			// fmt.Printf("No bits left, increment to byte %d, next value %d. Byte so far %d\n", c, value, bits)
			bitsleft = 6
		}

		needed := 8 - bitstaken
		var mask int
		if needed <= bitsleft {
			mask = needed
		} else {
			mask = bitsleft
		}

		bits |= (value & Firstmask(mask)) >> bitstaken
		value <<= mask
		bitsleft -= mask
		bitstaken += mask
		// fmt.Printf("Byte now: %d, bitstaken: %d, value left %d\n", bits, bitstaken, value)
	}

	// TODO; why are the leftover bits discarded?
	// if bitstaken == 8 {
	// 	fmt.Printf("%d bits were taken but no more to fill byte, append %d\n", bitstaken, bits)
	// 	bytes = append(bytes, bits)
	// }

	return
}

func Hex2base64_bytes(bytes []byte) []byte {

	// Byte being used in byte stream
	bindex := 0

	// Number of bits toward 6
	bitstaken := 0

	// Number of bits left in bytes[bindex]
	bitsleft := 8

	// hextet built
	b64_val := byte(0)

	// bytes of base64 values
	result := make([]byte, 0)

	for bindex < len(bytes) {
		if bitstaken == 6 {

			// The hextet must have its 6 bits shifted to the end to be interpeted correctly
			b64_val >>= 2
			result = append(result, b64_val)

			fmt.Printf("result: %d => %s\n", b64_val, Base64encode_bytes(result))

			bitstaken = 0
			b64_val = 0
		} else {

			// Move on to next byte
			// There might not be another, so stop and re-evaluate loop condition
			if bitsleft == 0 {
				bindex += 1
				bitsleft = 8
				continue
			}

			// There may not be enough bits left in the current byte to fill the hextet
			// Take whatever we can, or everything we need, depending on what's there
			var mask int
			bitsneeded := 6 - bitstaken
			if bitsleft > bitsneeded {
				mask = bitsneeded
			} else {
				mask = bitsleft
			}

			// Take the bits, shifting them right so they don't collide with pre-existing bits in hextet
			// Remove taken bits from current byte by left shift
			bits := (bytes[bindex] & Firstmask(mask))
			bytes[bindex] <<= mask
			bits >>= bitstaken

			bitstaken += mask
			bitsleft -= mask
		
			b64_val |= bits
		}
	}

	// Add any left-over bits
	if bitstaken > 0 {
			b64_val >>= 2
			result = append(result, b64_val)
			fmt.Printf("result: %d => %s\n", b64_val, Base64encode_bytes(result))
	}

	return result
}

func Base64encode_bytes(bytes []byte) (result string) {
	for _, b := range(bytes) {
		result += fmt.Sprintf("%c", Tobase64(int(b)))
	}
	return
}

func Base16encode_bytes(bytes []byte) (result string) {
	for _, b := range(bytes) {
		result += fmt.Sprintf("%c%c", Tobase16(int((b & Firstmask(4)) >> 4)), Tobase16(int(b & Lastmask(4))))
	}
	return
}

func Fixedxor(hex1, hex2 []byte) (result []byte) {
	result = make([]byte, 0)
	for i := 0; i < len(hex1); i +=1 {
		result = append(result, Xorbytes(hex1[i], hex2[i]))
	}
	return result
}

func Hamming(onebytes, twobytes []byte) int {
	xorbytes := Fixedxor(onebytes, twobytes)
	var set, bindex int
	for i := 0; i < len(xorbytes) * 8; i += 1 {
		if i > 0 && i % 8 == 0 {
			bindex += 1
		}

		if xorbytes[bindex] & Firstmask(1) > 0 {
			set += 1
		}
		xorbytes[bindex] <<= 1
	}
	return set
}

func Xorbytes[T int | byte](val1, val2 T) (T) {
	// or the bits to determine where at least 1 is set
	// and the bits to determine where both are set
	// -> negate above to determine where either only 1 is set, or neither
	// -> -> and above negation with the or to find where exactly 1 is set
	return ((val1 | val2) & ^(val1 & val2))
}

func Decodebase64_file(file string) []byte {
	bytes := []byte{}
	s := Read(file)
	for s.Scan() {
		bytes = append(bytes, Base64decode(s.Text())...)
	}
	return bytes
}

func Pkcs7pad(ascii string, length_bytes int) string {
	n := length_bytes - len(ascii)
	b := []byte(ascii)
	for i := 0; i < n; i += 1 {
		b = append(b, byte(n))
	}
	return Base16encode_bytes(b)
}

func Pkcs7pad_bytes(b []byte, length_bytes int) []byte {
	n := length_bytes - len(b)
	for i := 0; i < n; i += 1 {
		b = append(b, byte(n))
	}
	return b
}

func Randombyte(min, max byte) byte {
	return byte(math.Round((rand.Float64() * float64(max - min)) + float64(min)))
}

func Parse_kv(input []byte, mapchar, delimitter, escape byte) (pairs map[string]string) {
	pairs = make(map[string]string)
	var key, value []byte
	inkey, escaped := true, false

	// With cbc_bitflip, it's possible for one of the bytes from the scrambled cipherblock to
	// yield the escape char which ruins the attack
	// Only consider it as escape if used correctly (opening and closing quotes)
	escapecnt := 0
	for _, v := range input {
		if v == escape {
			escapecnt += 1
		}
	}
	for _, v := range input {
		if v == escape && escapecnt % 2 == 0 {
			escaped = !escaped
		}
		if v == delimitter && ! escaped {
			inkey = true
			pairs[string(key)] = string(value)
			key, value = []byte{}, []byte{}
			continue
		} else if v == mapchar && ! escaped {
			inkey = false
			continue
		}

		if inkey {
			key = append(key, v)
		} else {
			value = append(value, v)
		}
	}
	pairs[string(key)] = string(value)
	return
}

func Blocklen(in []byte) int {
	blocklen := len(in) / blocksize_bytes
	if len(in) % blocksize_bytes != 0 {
		blocklen += 1
	}
	return blocklen
}

func Validatepkcs7padding(data []byte) ([]byte, error) {
	count := int(data[len(data) - 1])
	if count == 0 {
		return nil, fmt.Errorf("error: last byte has value %d which is invalid padding\n", count)
	}
	for i, j := 0, len(data) - 1; i < count; i, j = i + 1, j - 1 {
		if data[j] != byte(count) {
			return nil, fmt.Errorf("error: byte %d has value %v, not %d as expected\n", j, data[j], count)
		}
	}
	return data[0:len(data) - count], nil
}

func Nth_block(bytes []byte, n int) []byte {
	// For CTR mode, input isn't padded to multiple of blocklen
	// If insufficient data left for a whole block, return what's there
	if blocksize_bytes * (n + 1) > len(bytes) {
		return bytes[blocksize_bytes * n:]
	}
	return bytes[blocksize_bytes * n : blocksize_bytes * (n + 1)]
}

// Break out an 8-byte (uint64) int into it's individual 8 bytes
func Int_to_bytes(input uint64) []byte {
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

func Check_ascii(in []byte) (int, error) {
	for k, v := range in {
		if v > 127 {
			return k, fmt.Errorf("invalid ASCII byte: %d at %d", v, k)
		}
	}
	return -1, nil
}