package main

import (
	"fmt"
	"slices"
	"math"
	"math/rand"
	"strconv"
	"os"
	"bufio"
	"strings"
	"regexp"

	"golang.org/x/exp/constraints"
)

func main() {
	fmt.Println("nothing")
}

func read(file string) *bufio.Scanner {
	f, err := os.Open(file)
	if err != nil {
		fmt.Printf("cannot read %s: %s", file, err)
	}

	return bufio.NewScanner(f)
}

func bits(n, padding int) []int {
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

func bitval(bits []int) int {
	var sum int

	// Compute decimal value of given bits
	for bit := 0; bit < len(bits); bit += 1 {
		sum += int(math.Pow(float64(2), float64(len(bits) - bit - 1))) * bits[bit]
	}
	return sum
}

func tobase64(val int) (ascii int) {
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

func tobase16(val int) (ascii int) {
	if val >= 10 {
		return 87 + val
	}
	return 48 + val
}

// TODO: replace with strconv.ParseInt
func frombase16char_tovalue(digit byte) (val int) {
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

func frombase64char_tovalue(digit byte) (val byte) {
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
		order := bits(frombase16char_tovalue(hex[k]), 4)

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
			a := tobase64(bitval(v))
			// fmt.Printf("\nend: %d => (%c) (%d)", bitval(v), a, a)
			result += fmt.Sprintf("%c", a)
			break
		}

		nextbits := bitstream[k:k + 6]
		val := bitval(nextbits)
	
		ascii := tobase64(val)
		char := fmt.Sprintf("%c", ascii)
		result += char

		// fmt.Printf("\n6 bits: %v, %d, base64: %s (%d)", nextbits, val, char, ascii)
	}

	return result
}

func firstmask(firstkbits int) byte {
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

func lastmask(lastkbits int) byte {
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

func hex2base64_bitwise(hex string) (result string) {
	currbitcnt, leftoverbitcnt := 0, 0
	var currbits, leftoverbits byte
	requiredbits := 6

	sixbits := make([]byte, 0)
	for i, _ := range(hex) {
		hexdigit := hex[i]

		// Find bitwise value of hexdigit and place in first 4 bits
		val := byte(frombase16char_tovalue(hexdigit))
		nibble := val << 4

		bitwise := bits(int(nibble), 8)
		fmt.Printf("\n%c has value %d. Shifted over to yield %d (%v)", hexdigit, val, nibble, bitwise)
		fmt.Printf("\ncurrent bit count: %d, required bits to yield 6: %d", currbitcnt, requiredbits)

		if requiredbits > currbitcnt {
			// Use entirety of hexdigit's bits

			// Shift the bits over so they don't overlap with already obtained bits
			currbits |= (nibble >> currbitcnt)
			currbitcnt += 4
			requiredbits -= 4
			currbits_bitwise := bits(int(currbits), 8)
			fmt.Printf("\nconsumed val %d to yield currbits %d (%v), current bit count: %d, required bits to yield 6: %d", val, currbits, currbits_bitwise, currbitcnt, requiredbits)
		}	else {
			// Only part of the hexdigit's bits are needed

			// Extract first kth bits, shifting them over to not overlap with already obtained bits
			mask := firstmask(requiredbits)
			nextbits := ((nibble & mask) >> currbitcnt)

			nextbits_bitwise := bits(int(nextbits), 8)
			fmt.Printf("\napplied mask 0x%x to %d (%v) obtain bits %d (%v)", mask, nibble, bitwise, nextbits, nextbits_bitwise)

			// Add the extracted bits to current collection
			currbits |= nextbits
			currbits_bitwise := bits(int(currbits), 8)
			currbitcnt += requiredbits
			fmt.Printf("\ncurrent bits: %d (%v)", currbits, currbits_bitwise)

			// The remaining bits are as follows:
			// Take the hex digit as originally found (where sig. bits are in last 4)
			// Take the last 2 bits from that
			// Shift those bits to top of byte
			leftoverbitcnt = 4 - requiredbits
			leftoverbits = (val & lastmask(leftoverbitcnt)) << (8 - leftoverbitcnt)
			leftoverbits_bitwise := bits(int(leftoverbits), 8)
			fmt.Printf("\nleft-over bits: %d (%v), left-over count: %d", leftoverbits, leftoverbits_bitwise, leftoverbitcnt)
		}

		// Desired bit count obtained, store collected value and reset state
		if currbitcnt == 6 {

			// Collected value must be shifted into correct pos to be read correctly
			currbits >>= 2
			currbits_bitwise := bits(int(currbits), 8)
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
		result += fmt.Sprintf("%c", tobase64(int(val)))
	}

	return result
}

func hexdecode(hex string) (bytes []byte) {
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

func base64decode(base64 string) (bytes []byte) {
	bytes = []byte{}

	bitstaken := 0
	bitsleft := 6
	c := 0
	var bits, value byte = 0, frombase64char_tovalue(base64[c]) << 2
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
			value = frombase64char_tovalue(base64[c]) << 2
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

		bits |= (value & firstmask(mask)) >> bitstaken
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

func hex2base64_bytes(bytes []byte) []byte {

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

			fmt.Printf("result: %d => %s\n", b64_val, base64encode_bytes(result))

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
			bits := (bytes[bindex] & firstmask(mask))
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
			fmt.Printf("result: %d => %s\n", b64_val, base64encode_bytes(result))
	}

	return result
}

func base64encode_bytes(bytes []byte) (result string) {
	for _, b := range(bytes) {
		result += fmt.Sprintf("%c", tobase64(int(b)))
	}
	return
}

func base16encode_bytes(bytes []byte) (result string) {
	for _, b := range(bytes) {
		result += fmt.Sprintf("%c%c", tobase16(int((b & firstmask(4)) >> 4)), tobase16(int(b & lastmask(4))))
	}
	return
}

func fixedxor(hex1, hex2 []byte) (result []byte) {
	result = make([]byte, 0)
	for i := 0; i < len(hex1); i +=1 {
		result = append(result, xorbytes(hex1[i], hex2[i]))
	}
	return result
}

func xorbytes[T constraints.Unsigned | byte](val1, val2 T) (T) {
	// or the bits to determine where at least 1 is set
	// and the bits to determine where both are set
	// -> negate above to determine where either only 1 is set, or neither
	// -> -> and above negation with the or to find where exactly 1 is set
	return ((val1 | val2) & ^(val1 & val2))
}

func rankplaintext(bytes []byte) (score float64) {
	vowels := []byte{65, 69, 73, 79, 85, 97, 101, 105, 111, 117}
	var v, space, alphanum, weird float64
	for _, b := range(bytes) {
		if b == 0x20 {
			space += 1
		}

		if (b >= 48 && b <= 57) || (b >= 65 && b <= 90) || (b >= 97 && b <= 122) {
			alphanum += 1
			for _, v := range(vowels) {
				if b == v {
					v += 1
					break
				}
			}
		} else if (b >= 91 && b <= 96) || b >= 123 || (b < 32 && b != 10) {
			weird += 1
		}
	}

	// Obviously not English plaintext
	if weird > 0 {
		return -1
	}

	// Rank result bytes as follows:
	// 70% for alphanum chars
	// 20% for spaces
	// 10% for vowels
	return (alphanum * float64(0.7)) + (space * float64(0.2)) + (v * float64(0.1))
}

// This works b/c (a XOR b) XOR b = a
// Bit is set whenever exactly 1 of the 2 bits is set
// => 1st operand = 1, 2nd operand = 0 => 1st bit is 1
// => 1st operand = 1, 2nd operand = 1 => 1st bit is 0
// => 1st operand = 0, 2nd operand = 1 => 1st bit is 1
// => 1st operand = 0, 2nd operand = 0 => 1st bit is 0
func xordecrypt(bytes []byte) () {
	type r struct {
		bytes []byte
		ascii string
		score float64
	}
	results := map[byte]r{}

	var i byte
	for i = 32; i < 123; i += 1 {
		ascii := ""
		rbytes := []byte{}
		for _, b := range(bytes) {
			xor := fixedxor([]byte{b}, []byte{i})
			rbytes = append(rbytes, xor[0])
			ascii += string(xor)
		}
		results[i] = r{rbytes, ascii, rankplaintext(rbytes)}
	}

	xorchar, maxscore := byte(0), float64(0)
	for k, result := range(results) {
		if result.score > maxscore {
			maxscore = result.score
			xorchar = k
		}
		// fmt.Printf("%d (%c), score: %f => %s\n", k, k, result.score, result.ascii)
	}

	fmt.Printf("best score: %f from %d (%c) => %s\n", maxscore, xorchar, xorchar, results[xorchar].ascii)
}

func findxoredstring() {
	type result struct {
		cipherbytes []byte
		plainbytes []byte
		xorv byte
		score float64
	}
	data := map[string]result{}

	s := read("1_4.txt")
	for s.Scan() {
		t := s.Text()
		data[t] = result{
			cipherbytes: hexdecode(t),
		}
	}

	for ciphertext, r := range(data) {
		bestscore := float64(0)
		bestxor := byte(0)
		bestbytes := []byte{}
		var i byte
		for i = 32; i < 123; i +=1 {
			plainbytes := []byte{}
			for _, b := range(r.cipherbytes) {
				plainbytes = append(plainbytes, fixedxor([]byte{b}, []byte{i})[0])
			}
			rank := rankplaintext(plainbytes)
			if rank > bestscore {
				// fmt.Printf("%s appears to be closer to plaintext with score %f, generated from %s XOR %d\n", frombytes_ascii(plainbytes), rank, ciphertext, i)
				bestscore = rank
				bestxor = i
				bestbytes = plainbytes
			}
		}

		if bestscore > 0 {
			d := data[ciphertext]
			d.plainbytes = bestbytes
			d.score = bestscore
			d.xorv = bestxor
			data[ciphertext] = d
			// fmt.Printf("%s is most likely candidate with score %f, generated from %s XOR %d\n", string(bestbytes), bestscore, ciphertext, bestxor)
		}
	}

	finalchoice := ""
	for ciphertext, r := range(data) {
		if r.score > data[finalchoice].score {
			finalchoice = ciphertext
		}
	}

	final := data[finalchoice]
	fmt.Printf("ciphertext was %s which decodes to %s when XORed with %d (score %f)\n", finalchoice, string(final.plainbytes), final.xorv, final.score)
}

func repeatingxor(bytes []byte, key string) string {
	keybytes := []byte(key)
	k := 0
	result := []byte{}
	for _, b := range bytes {
		result = append(result, fixedxor([]byte{b}, []byte{keybytes[k]})[0])
		k = (k + 1) % len(keybytes)
	}

	hex := base16encode_bytes(result)
	// fmt.Printf("encrypt %v with %s => %s\n", bytes, key, hex)
	return hex
}

func hamming(onebytes, twobytes []byte) int {
	xorbytes := fixedxor(onebytes, twobytes)
	var set, bindex int
	for i := 0; i < len(xorbytes) * 8; i += 1 {
		if i > 0 && i % 8 == 0 {
			bindex += 1
		}

		if xorbytes[bindex] & firstmask(1) > 0 {
			set += 1
		}
		xorbytes[bindex] <<= 1
	}
	return set
}

func decodebase64_file(file string) []byte {
	bytes := []byte{}
	s := read(file)
	for s.Scan() {
		bytes = append(bytes, base64decode(s.Text())...)
	}
	return bytes
}

// Take K samples (K must be even) and average the pair-wise hamming dist
// Vary the sample length from lb to ub bytes
func evalkeysize(bytes []byte, lb, ub, samplesize int) int {
	lowestdist := float64(len(bytes))
	keysize := 0

	if ub * samplesize > len(bytes) {
		fmt.Printf("error: Not enough data to collect %d samples of size %d bytes\n", samplesize, ub)
		return -1
	}

	for i := lb; i < ub; i += 1 {
		samples := [][]byte{}
		for j := 0; j < samplesize; j += 1 {
			samples = append(samples, bytes[i * j:i * (j + 1)])
		}

		var avg float64
		for j := 0; j < samplesize - 1; j += 2 {
			avg += float64(hamming(samples[j], samples[j + 1])) / float64(i)
		}
		avg /= float64(samplesize / 2)

		if avg < lowestdist {
			// fmt.Printf("key size of %d yields lower hamming %f than key size of %d\n", i, avg, keysize)
			keysize = i
			lowestdist = avg
		} else {
			// fmt.Printf("try key size %d => %f\n", i, avg)
		}
	}
	// fmt.Printf("keysize that yields lowest hamming: %d\n", keysize)
	return keysize
}

func findkeysize(bytes []byte, lb, ub, uppersamplesize int) int {
	freqs := map[int]int{}

	// As sample size increases, the keysize with best pair-wise hamming dist is converged on?
	// So test all key sizes at increasing sample sizes and take the overall best performing keysize
	for i := 2; i < uppersamplesize; i += 2 {
		f := evalkeysize(bytes, lb, ub, i)
		if f == -1 {
			fmt.Printf("invalid attempt, stopping at sample size %d\n", i - 2)
			break
		}
		freqs[f] += 1
	}
	best, freq := 0, 0
	for k, v := range freqs {
		if v > freq {
			best = k
			freq = v
		}
	}
	fmt.Printf("keysize of %d occurs as best most often (%d times given %d rounds). All data: %v\n", best, freq, uppersamplesize / 2, freqs)
	return best
}

func decryptrepeatedxor(bytes []byte, keysize int) {

	// Split byte slices by index (up to keysize) into fixedxor byte slices
	// i.e, take each 1st byte into slice, each 2nd byte, etc
	chunks := make([][]byte, keysize)
	i := 0
	for _, b := range bytes {
		chunks[i] = append(chunks[i], b)
		i = (i + 1) % keysize 
	}

	keybytes := make([]byte, keysize)
	plainbytes := make([][]byte, keysize)
	for cnum, c := range chunks {
		bestscore := float64(0)
		var i byte
		for i = 32; i < 123; i += 1 {
			xoredbytes := []byte{}
			for _, b := range c {
				xoredbytes = append(xoredbytes, fixedxor([]byte{b}, []byte{i})[0])
			}
			r := rankplaintext(xoredbytes)
			// fmt.Printf("XORed %dth bytes from each %d block against %d => ?, rank %f\n", cnum, keysize, i, r)
			if r > bestscore {
				keybytes[cnum] = i
				bestscore = r
				plainbytes[cnum] = xoredbytes
			}
		}
		// fmt.Printf("Best XOR key for %dth bytes: %d (%s) => %s, rank %f\n", cnum, keybytes[cnum], string([]byte{keybytes[cnum]}), plainbytes[cnum], bestscore)
	}

	// Interleave the now decrypted plainbytes back together
	i = 0
	var msg string
	for true {
		added := false
		for _, p := range plainbytes {
			if i < len(p) {
				msg += string(p[i])
				added = true
			}
		}
		if !added {
			break
		}
		i += 1
	}

	fmt.Printf("key: [%s] => decrypted message: \n%s\n", string(keybytes), msg)
}

func findaesecb(hex string) bool {
	wordlen_hexchar := 32
	table := map[string]int{}
	if len(hex) % wordlen_hexchar != 0 {
		fmt.Printf("%s cannot be AES 128 since length isn't multiple of 16 bytes\n", hex)
		return false
	}
	for i := 0; i < len(hex); i += wordlen_hexchar {
		s := hex[i : i + wordlen_hexchar]
		if table[s] > 0 {
			fmt.Printf("substring %s repeats at index %d, current count: %d\n", s, i, table[s])
			return true
		}
		table[s] += 1
	}
	return false
}

func detectaes_ecb(file string) string {
	s := read(file)
	for s.Scan() {
		t := s.Text()
		if findaesecb(t) {
			fmt.Printf("AES-128 in ECB mode line: %s\n", t)
			return t
		}
	}
	return ""
}

func pkcs7pad(ascii string, length_bytes int) string {
	n := length_bytes - len(ascii)
	b := []byte(ascii)
	for i := 0; i < n; i += 1 {
		b = append(b, byte(n))
	}
	return base16encode_bytes(b)
}

func pkcs7pad_bytes(b []byte, length_bytes int) []byte {
	n := length_bytes - len(b)
	for i := 0; i < n; i += 1 {
		b = append(b, byte(n))
	}
	return b
}

func randombyte(min, max byte) byte {
	return byte(math.Round((rand.Float64() * float64(max - min)) + float64(min)))
}

func randomAESkey() []byte {
	b := make([]byte, 16)
	minbyte := byte(32)
	maxbyte := byte(126)
	for k, _ := range b {
		b[k] = randombyte(minbyte, maxbyte)
	}
	return b
}

func randomencrypt(data []byte) ([]byte, string) {
	minbyte := byte(32)
	maxbyte := byte(126)

	plainbytes := []byte(data)
	hlen := int(math.Round((rand.Float64() * 5) + 5))
	flen := int(math.Round((rand.Float64() * 5) + 5))
	header := make([]byte, hlen)
	footer := make([]byte, flen)
	for k, _ := range header {
		header[k] = randombyte(minbyte, maxbyte)
	}
	for k, _ := range footer {
		footer[k] = randombyte(minbyte, maxbyte)
	}
	plainbytes = append(header, plainbytes...)
	plainbytes = append(plainbytes, footer...)
	padlen := int(math.Ceil(float64(len(plainbytes)) / float64(keylen_words * wordlen_bytes))) * 16
	plainbytes = pkcs7pad_bytes(plainbytes, padlen)
	fmt.Printf("random header of size %d: %v\nrandom footer of size: %d: %v\nall data (padded to %d len): %v\n\n", hlen, header, flen, footer, padlen, plainbytes)

	a := AES{}
	var cipherbytes []byte
	mode := int(math.Round(rand.Float64()))
	modestr := ""
	if mode == 0 {
		cipherbytes = a.Encrypt_ECB(plainbytes, randomAESkey())
		modestr = "ECB"
	} else {
		cipherbytes = a.Encrypt_CBC(plainbytes, randomAESkey(), randomAESkey())
		modestr = "CBC"
	}
	fmt.Printf("random mode: %d (%s), data => %v\n", mode, modestr, cipherbytes)

	return cipherbytes, modestr
}

func detectaes_cbc_ecb(data []byte) bool {
	// This is meant to be a problem about selecting the right _plaintext_
	// such that it can be fed to a mystery algorithm
	// and based on output, determine if ECB or not
	// Thanks to https://crypto.stackexchange.com/questions/53274/cryptopals-challenge-2-11-distinguish-ecb-and-cbc-encryption?rq=1 for clarification
	c, expectedmode := randomencrypt([]byte(data))
	chex := base16encode_bytes(c)

	// EBC is easily distinguished via repeated blocks. If not obviously ECB, assume CBC
	foundmode := "CBC"
	if findaesecb(chex) {
		foundmode = "ECB"
	}
	fmt.Printf("\n%s\nappears to be AES in %s mode\nactual result: %s\n", chex, foundmode, expectedmode)

	return foundmode == expectedmode
}

func decryptecb_oneblock(mystery []byte) []byte {
	a := AES{}

	// This value is unknown to us
	key := randomAESkey()

	// Determine cipher block size by counting bytes of ciphertext
	// We "don't know" what the padding length is
	blocksize_bytes := len(pkcs7pad_bytes(a.Encrypt_ECB([]byte{0}, key), blocksize_bytes))
	fmt.Printf("determined that 'mystery algorithm' has block size %d bytes\n", blocksize_bytes)

	knownword := "josh"
	fullknownblock := knownword + knownword + knownword + knownword

	// Verify cipher is operating in ECB mode
	// We "don't know" which mode the cipher is using
	if findaesecb(base16encode_bytes(a.Encrypt_ECB([]byte(fullknownblock + fullknownblock), key))) {
		fmt.Printf("verified that 'mystery algorithm' uses ECB mode\n")
	}

	foundblocks := []word{word{}}
	blockidx := 0

	// If the mystery data's length isn't block-multiple, pretend there's an extra block
	mysteryblockcount := len(mystery) / blocksize_bytes
	if len(mystery) % blocksize_bytes > 0 {
		mysteryblockcount = len(mystery) / blocksize_bytes + 1
	}

	// How is this a useful attack?
	// It relies on forcing the mystery plaintext to bleed into the known block
	// When would that happen in a practical scenario?
	// After all, the mystery plaintext must be known to do this...
	for i := 0; i < (blocksize_bytes * mysteryblockcount); i += blocksize_bytes {

		// If the last block isn't full, just take what's there
		var mysteryblock []byte
		if len(mystery) - i < blocksize_bytes {
			mysteryblock = mystery[i:]
		} else {
			mysteryblock = mystery[i : i + blocksize_bytes]
		}

		for k := 0; k < len(mysteryblock); k += 1 {
			end := len(fullknownblock)
			if len(foundblocks[blockidx]) > 0 {
				end -= len(foundblocks[blockidx]) + 1
			} else {
				end -= 1
			}
			knownblock := []byte(fullknownblock[0 : end])
			payload := pkcs7pad_bytes(append(knownblock, mysteryblock...), 2 * blocksize_bytes)
			// fmt.Printf("%d bytes of block %d found so far, using knownblock: %s for payload of size %d\n", len(foundblocks[blockidx]), blockidx, knownblock, len(payload))
			result := a.Encrypt_ECB(payload, key)[0 : blocksize_bytes]

			for j := 0; j < 255; j += 1 {
				guesspayload := append(knownblock, foundblocks[blockidx]...)
				guesspayload = append(guesspayload, byte(j))
				guesspayload = pkcs7pad_bytes(guesspayload, 2 * blocksize_bytes)
				// fmt.Printf("guessing byte %d (%c) as last byte in payload: %s\n", j, j, string(guesspayload))

				r := a.Encrypt_ECB(guesspayload, key)[0 : blocksize_bytes]
				if slices.Equal(r, result) {
					// fmt.Printf("%dth byte of block %d is: %d (%c)\n", k, blockidx, j, byte(j))
					foundblocks[blockidx] = append(foundblocks[blockidx], byte(j))
					break
				}
			}
		}

		// Last block may not be a full block, and that's OK
		// Every other block should have blocksize_bytes at this point
		if len(foundblocks[blockidx]) < blocksize_bytes && blockidx < mysteryblockcount - 1 {
			panic(fmt.Sprintf("16 bytes of mystery data should have been found, got %d => %v\n", len(foundblocks[blockidx]), foundblocks[blockidx]))
		}
		blockidx += 1
		foundblocks = append(foundblocks, word{})
	}

	final := wordstobytes(foundblocks)
	fmt.Printf("mystery value: %s\n", final)
	return final
}

func parse_kv(input []byte, mapchar, delimitter, escape byte) (pairs map[string]string) {
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

// Make a function that returns an encrypted profile string given an email address: email=e&role=user
// Determine how to mutate a ciphertext such after decryption (simulated login), it yields: email=e&role=admin
func ecb_cutpaste() string {
	profile_for := func(email string) string {
		return fmt.Sprintf("email=%s&role=user", strings.ReplaceAll(strings.ReplaceAll(email, "&", ""), "=", ""))
	}
	parse_profile := func(profile string) map[string]string {
		return parse_kv([]byte(profile), 0x3d, 0x26, 0x00)
	}
	key := randomAESkey()
	a := AES{}
	oracle := func(email string) []byte {
		in := []byte(profile_for(email))
		plen := len(in) / blocksize_bytes
		if len(in) % blocksize_bytes != 0 {
			plen += 1
		}
		in = pkcs7pad_bytes(in, plen * blocksize_bytes)
		fmt.Printf("padded input to len: %d\n", len(in))
		return a.Encrypt_ECB(in, key)
	}
	login := func(profilenc []byte) string {
		d := (a.Decrypt_ECB(profilenc, key))
		
		// Is this intended? This part is crucial to the attack
		// It removes any padding bytes from decrypted data
		// Should this be part of the Decrypt_ECB func?
		last := d[len(d) - 1]
		plen := 0
		for i := len(d) - 1; i >= len(d) - int(last); i -= 1 {
			if d[i] != last {
				plen = 0
				break
			}
			plen += 1
		}
		fmt.Printf("detected %d padding bytes of %d\n", plen, last)
		return string(d[0:len(d) - plen])
	}

	// Outline of attack:
	// Use a long enough email adddress to force resulting ciphertext to have the role value in a separate block
	// The first 2 blocks of resulting ciphertext will be useful (email=??&role=)
	// Then, construct a long email address to force the word admin to be in the 2nd block
	// Pad the block containing "admin" with appropriate padding char that will be stripped off during decryption
	// Combine the first 2 blocks from before with the 2nd block of above to yield target ciphertext
	// This will decrypt to an encoded profile with role=admin

	// Assumptions:
	// email does not have to be valid (no @domain.com)
	// Padding bytes are removed after decryption and before a profile's role value

	emaillen := len("email=") 
	rolelen := len("&role=")
	padlen := (blocksize_bytes - emaillen) + (blocksize_bytes - rolelen)
	roleownblock := ""
	for i := 0; i < padlen; i += 1 {
		roleownblock += "a"
	}
	// fmt.Printf("pad to len %d to force role to be in separate block => %s\n", padlen, roleownblock)
	roleownblockcipher := oracle(roleownblock)
	// fmt.Printf("%v\n", roleownblockcipher)

	headerlen := blocksize_bytes - emaillen
	adminlen := len("admin")
	footerlen := blocksize_bytes - adminlen
	adminownblock := ""
	for i := 0; i < headerlen; i += 1 {
		adminownblock += "z"
	}
	adminownblock += "admin"
	for i := 0; i < footerlen; i += 1 {
		adminownblock += fmt.Sprintf("%c", blocksize_bytes - adminlen)
	}
	// fmt.Printf("pad to len %d to force admin to be in 2nd block => %s\n", headerlen + adminlen + footerlen, adminownblock)
	adminownblockcipher := oracle(adminownblock)
	// fmt.Printf("%v\n", adminownblockcipher)

	targetciphertext := append(roleownblockcipher[0 : blocksize_bytes * 2], adminownblockcipher[blocksize_bytes : blocksize_bytes * 2]...)
	// fmt.Printf("target cipher bytes:\n%v\n", targetciphertext)

	result := login(targetciphertext)
	fmt.Printf("login attempt: %s\n", result)
	return parse_profile(result)["role"]
}

func blocklen(in []byte) int {
	blocklen := len(in) / blocksize_bytes
	if len(in) % blocksize_bytes != 0 {
		blocklen += 1
	}
	return blocklen
}

// One byte at a time, determine contents of mystery data
// Oracle will prefix plaintext with fixed len random data each time
// ASSUMPTION: oracle uses the same fixed len random data for all calls, unclear from problem statement

// before: <known-string>m<ysery-text>
// 				 [..............][..........]
// guess every value for m comparing 1st block of each ciphertext until same ciphertext is returned

// now: <rand><known-string>m<ystery-text>
// 			[..............][..........]
func decryptecb_random(mystery []byte) []byte {
	// Server starts here

	randomprefixlen := rand.Intn(16)
	randomprefix := []byte{}
	fmt.Printf("generating %d random bytes of data\n", randomprefixlen)
	for i := 0; i < randomprefixlen; i += 1 {
		randomprefix = append(randomprefix, randombyte(0, 255))
	}
	key := randomAESkey()
	a := AES{}

	// Just like before, it's not clear to me how this attack is useful
	// In order to "bleed" blocks of mystery data beyond the first one into the "known block", 
	// block-level access to mystery data (via oracle) is required
	// blockidx is the param to specify which block of mystery data to use for oracle output
	// -1 means use all the mystery data
	oracle := func(input []byte, blockidx int) []byte {
		var in []byte
		if blockidx == -1 {
			in = append(append(randomprefix, input...), mystery...)
		} else {
			s := blocksize_bytes * blockidx
			in = append(append(randomprefix, input...), mystery[s:s + blocksize_bytes]...)
		}
		return a.Encrypt_ECB(pkcs7pad_bytes(in, blocklen(in) * blocksize_bytes), key)
	}

	// Attack starts here

	// Since the known block + full len of mystery data is known to attacker (ASSUMPTION), 
	// determine how many padding slots there would be of ECB encrypted known block + mystery
	knownstring := "josh"
	knownblock := []byte(knownstring + knownstring + knownstring + knownstring)
	attackerinput_blocks := blocklen(mystery) + 1
	paddingcnt_attacker := ((attackerinput_blocks) * 16) - (len(mystery) + blocksize_bytes)
	// fmt.Printf("calculated mystery data and known block to be %d blocks and have %d bytes of padding\n", attackerinput_blocks, paddingcnt_attacker)

	// Core idea is to determine how much random data the oracle is prefixing
	// Do this by watching the length of ciphertext returned for ever-increasing input lengths
	// There will be 3 distinct cases depending on how much random data there is:

	res_attacker := oracle(knownblock, -1)
	res_blocklen := blocklen(res_attacker)
	target_blocklen := res_blocklen + 1
	random_len_attacker := 0

	// case 3:
	// random bytes > padding slots => add 0 bytes, and will overflow into additional blocks
	// => add 1 byte until overflow into another additional block (X)
	// => random len = padding slots + ((block_diff - 1)) * 16) + (16 - X)
	if res_blocklen > attackerinput_blocks {
		// fmt.Printf("oracle output has %d blocks of ciphertext, mystery data with known block has %d: random data > padding slots\n", res_blocklen, attackerinput_blocks)
		random_len_attacker = paddingcnt_attacker + (res_blocklen - attackerinput_blocks - 1) * blocksize_bytes
		paddingcnt_attacker = blocksize_bytes
	}

	input_attacker := append(knownblock, byte(0))
	extrabytes_attacker := 1
	for {
		out := oracle(input_attacker, -1)
		// fmt.Printf("adding %d extra bytes\n", extrabytes_attacker)

		// case 1
		// random bytes < padding slots => add 1 byte until overflow into additional block (X)
		// => random len = padding slots - X
		// case 2	
		// random bytes == padding slots => will overflow immediately after adding 1 byte (X)
		// => random len = padding slots
		if blocklen(out) == target_blocklen {
			// fmt.Printf("after adding %d bytes, cipherlen changed from %d to %d blocks\n", extrabytes_attacker, res_blocklen, target_blocklen)
			random_len_attacker += paddingcnt_attacker - (extrabytes_attacker - 1)
			break
		}
		input_attacker = append(input_attacker, byte(0))
		extrabytes_attacker += 1
	}
	fmt.Printf("attacker has determined that oracle server is prepending %d bytes of random data\n", random_len_attacker)

	// Now that length of random data is known, mitigate by adding null bytes
	// to fill up to N blocks exactly
	// That will let us be sure the following block contains the <known-block> combined with mystery data for the attack
	padding_attacker := []byte{}
	for i := 0; i < blocksize_bytes - (random_len_attacker % blocksize_bytes); i += 1 {
		padding_attacker = append(padding_attacker, byte(0))
	}

	// Conceptually, the target_block is the one _after_ the last one with random data and its padding
	// That would be the random len in blocks, + 1. But then subtract 1 since blocks are 0-indexed
	target_blockidx := random_len_attacker / blocksize_bytes

	// If the random data bleeds beyond a "full" block, use the one after the block with partially random data
	if len(padding_attacker) > 0 {
		target_blockidx += 1
	}
	// fmt.Printf("calls to oracle prefixed with %d bytes of padding; target block is %d\n", len(padding_attacker), target_blockidx)

	// Repeat attack as last time
	foundblocks := []word{[]byte{}}
	blockidx := 0
	mysterylen_blocks := blocklen(mystery)
	for i := 0; i < (blocksize_bytes * mysterylen_blocks); i += blocksize_bytes {

		// If the last block isn't full, just take what's there
		var mysteryblock []byte
		if len(mystery) - i < blocksize_bytes {
			mysteryblock = mystery[i:]
		} else {
			mysteryblock = mystery[i : i + blocksize_bytes]
		}

		for k := 0; k < len(mysteryblock); k += 1 {
			end := len(knownblock)
			if len(foundblocks[blockidx]) > 0 {
				end -= len(foundblocks[blockidx]) + 1
			} else {
				end -= 1
			}
			input := append(padding_attacker, knownblock[0 : end]...)
			s := blocksize_bytes * target_blockidx
			result := oracle(input, blockidx)[s:s + blocksize_bytes]

			for j := 0; j < 255; j += 1 {
				guesspayload := append(append(input, foundblocks[blockidx]...), byte(j))
				// fmt.Printf("guessing byte %d (%c) as last byte in payload: %s\n", j, j, string(guesspayload))

				r := oracle(guesspayload, blockidx)[s:s + blocksize_bytes]
				if slices.Equal(r, result) {
					// fmt.Printf("%dth byte of block %d of %d is: %d (%c)\n", k, blockidx, mysterylen_blocks, j, byte(j))
					foundblocks[blockidx] = append(foundblocks[blockidx], byte(j))
					break
				}
			}
		}

		// Last block may not be a full block, and that's OK
		// Every other block should have blocksize_bytes at this point
		if len(foundblocks[blockidx]) < blocksize_bytes && blockidx < mysterylen_blocks - 1 {
			panic(fmt.Sprintf("16 bytes of mystery data should have been found, got %d => %v\n", len(foundblocks[blockidx]), foundblocks[blockidx]))
		}
		blockidx += 1
		foundblocks = append(foundblocks, word{})
	}

	final := wordstobytes(foundblocks)
	fmt.Printf("mystery value: %s\n", final)
	return final
}

func validatepkcs7padding(data []byte) ([]byte, error) {
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

func cbc_bitflip() bool {
	a := AES{debug: false}
	key, iv := randomAESkey(), randomAESkey()
	to_prepend := "comment1=cooking%20MCs;userdata="
	to_append := ";comment2=%20like%20a%20pound%20of%20bacon"
	oracle := func(input string) []byte {
		escaped_bytes := []byte{}
		for k, _ := range input {
			b := input[k]
			a := []byte{b}
			if b == 0x3b || b == 0x3d {
				a = []byte{0x22, b, 0x22}
			}
			escaped_bytes = append(escaped_bytes, a...)
		}
		plainbytes := append([]byte(to_prepend), escaped_bytes...)
		plainbytes = append(plainbytes, []byte(to_append)...)
		// fmt.Printf("blocklen: %s: %d => %d\n", string(plainbytes), len(plainbytes), blocklen(plainbytes))
		plainbytes_padded := pkcs7pad_bytes(plainbytes, blocklen(plainbytes) * blocksize_bytes)

		return a.Encrypt_CBC(plainbytes_padded, key, iv)
	}
	check := func(cipherbytes []byte) bool {
		res := a.Decrypt_CBC(cipherbytes, key, iv)
		fmt.Printf("cbc_bitflip check decrypted result: %s\n%v\n", res, res)
		pairs := parse_kv(res, 0x3d, 0x3b, 0x22)
		fmt.Printf("cbc_bitflip: parsed k/v pairs: \n%v\n", pairs)

		p, ok := pairs["admin"]
		return ok && p == "true"
	}

	// Attack starts here

	// Z = EBC_Encrypt(X xor Y)
	// X = ;comment2=%20like%20a%20pound%20of%20bacon
	// A = ;admin=true
	// Y = ciphertext block prior to CBC_Encrypt(to_prepend + input + X)

	// ECB_Decrypt(Z) XOR Y = X (by defn of CBC_Decrypt)
	// => ECB_Decrypt(Z) = X xor Y
	// (X xor Y) xor A => bits to flip => Y'
	// ECB_Decrypt(Z) xor Y' = (X xor Y) xor Y' = A

	att_goal := ";admin=true;"
	// Since to_prepend is 32 bytes exactly (2 blocks), attacker doesn't need to supply an input at all
	att_cipherbytes := oracle("") 
	// fmt.Printf("cbc_bitflip: attacker is given ciphertext:\n%v\n", att_cipherbytes)
	preceding_blocks := 1
	att_second_cipherblock := att_cipherbytes[blocksize_bytes * preceding_blocks:blocksize_bytes * (preceding_blocks + 1)]
	att_third_cipherblock := att_cipherbytes[blocksize_bytes * (preceding_blocks + 1):]

	// => ECB_Decrypt(Z) = X xor Y
	// XOR the last block of plaintext with the preceding ciphertext block
	// This yields the input to the EBC_Encrypt func, aka what ECB_Decrypt would give
	att_lhs := fixedxor([]byte(to_append)[0:blocksize_bytes], att_second_cipherblock)
	// fmt.Printf("cbc_bitflip: ECB decrypt result of %v\n%v\n\n", att_second_cipherblock, att_lhs)

	// (X xor Y) xor A => bits to flip => Y'
	// XOR the above with the desired string to give the bytes needed to replace the preceding cipherbytes block
	// XOR will set the bits whenever a bit needs to be flipped to yield our desired string, exactly what we want
	att_modified_second_cipherblock := fixedxor(att_lhs, pkcs7pad_bytes([]byte(att_goal), blocksize_bytes))
	// fmt.Printf("cbc_bitflip: modified second block: %v\n\n", att_modified_second_cipherblock)

	// Put the modified cipherblock together with the untouched third cipherblock
	// ECB_Decrypt will be called on the third cipherblock
	// It will be XORed with our modified preceding cipherblock and yield the desired string
	return check(append(att_modified_second_cipherblock, att_third_cipherblock...))
}

func nth_block(bytes []byte, n int) []byte {
	// For CTR mode, input isn't padded to multiple of blocklen
	// If insufficient data left for a whole block, return what's there
	if blocksize_bytes * (n + 1) > len(bytes) {
		return bytes[blocksize_bytes * n:]
	}
	return bytes[blocksize_bytes * n : blocksize_bytes * (n + 1)]
}

func cbc_padding_oracle(plaintext string) (string, error) {
	key, iv := randomAESkey(), randomAESkey()
	first := func() (cipherbytes, used_iv []byte) {
		a := AES{debug: false}
		pad_len := blocklen([]byte(plaintext)) * blocksize_bytes
		padded := pkcs7pad_bytes([]byte(plaintext),  pad_len)

		// Add extra padding as explained in https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7
		// This resolves ambiguity about how to interpret last byte
		if len(plaintext) % blocksize_bytes == 0 {
			padded = pkcs7pad_bytes([]byte(plaintext),  len(plaintext) + blocksize_bytes)
		}

		return a.Encrypt_CBC(padded, key, iv), iv
	}
	second := func(a *AES, cipherbytes []byte) bool {
		_, e := validatepkcs7padding(a.Decrypt_CBC(cipherbytes, key, iv))
		return e == nil
	}

	// Attack starts here
	// See README for overall explanation
	att_cipherbytes, att_iv := first()
	att_blocklen := blocklen(att_cipherbytes)
	att_full_plainbytes := []byte{}

	type att_block_result struct {
		blockidx int
		plainbytes []byte
	}
	att_decrypted_block_chan := make(chan att_block_result)
	att_all_blocks := map[int][]byte{}
	for att_target_block := att_blocklen - 1; att_target_block >= 0; att_target_block -= 1 {
		go func(att_target_block int) {
			a := AES{}
			var original_firstblock []byte
			if att_target_block == 0 {
				original_firstblock = att_iv
			} else {
				original_firstblock = nth_block(att_cipherbytes, att_target_block - 1)
			}
			secondblock := nth_block(att_cipherbytes, att_target_block)
			// fmt.Printf("target block: %d, cipherblocks: %v\n%v\n", att_target_block, original_firstblock, secondblock)

			att_plainbytes := []byte{}
			for i := blocksize_bytes - 1; i >= 0; i -= 1 {
				att_goal_padding := blocksize_bytes - i
				// fmt.Printf("att goal is to make oracle pass with padding: %d\n", att_goal_padding)
				firstblock := slices.Clone(original_firstblock)
				// fmt.Printf("firstblock before modify: %v\n", firstblock)

				// Use CBC bitflip to ensure the known plainbytes decrypt to the goal_padding (P')
				for k, j := len(att_plainbytes) - 1, i + 1; j < blocksize_bytes; k, j = k - 1, j + 1{
					firstblock[j] = xorbytes(byte(att_goal_padding), xorbytes(att_plainbytes[k], original_firstblock[j]))
				}
				// fmt.Printf("firstblock after modify: %v\n", firstblock)

				// Set C' by substituting each possible byte value
				// Do this until the oracle passes (ECB_Decrypt(T) xor C' = P')
				options := []byte{}
				for k := 0; k < 256; k += 1 {
					firstblock[i] = byte(k)
					if second(&a, append(firstblock, secondblock...)) {
						options = append(options, firstblock[i])
					}
				}

				// Attack is to find a C' for attacker goal padding P' such that oracle passes => ECB_Decrypt(T) xor C' = P'
				// The oracle will pass if T (our target byte) decrypts to P' (starts at 0x01) OR T decrypts to the "actual" padding (P)
				// On every iteration after P'=1, the other padding bytes are guaranteed to equal P'
				// Therefore on those iterations, oracle will ONLY pass in the situation we desire (T decrypts to P')
				// BUT on iteration 1, since we cannot set any bytes after the last byte to affect things,
				// the oracle can pass in either case:

				// T decrypts to P' (desired, since we know the value of P')
				// T decrypts to P (not desired since we don't actually know P), which is guaranteed to happen when C'=C

				// Thus if multiple mutations pass the oracle, choose the one where C' != C
				// Note that for length-15 plaintexts where P=1, oracle will only pass for P'=1 when C'=C
				// In that case, only one mutation will pass the oracle so everything will work BAU
				if len(options) > 0 {
					opt := options[0]
					if len(options) > 1 {
						for _, o := range options {
							if o != original_firstblock[i] {
								opt = o
								break
							}
						}
					}
					// fmt.Printf("using byte value %d (compared to %d) causes oracle to pass\n", opt, original_firstblock[i])
					att_result := xorbytes(xorbytes(byte(att_goal_padding), opt), original_firstblock[i])
					// fmt.Printf("target_block: %d plaintext at pos %d: %d (%c)\n", att_target_block, i, att_result, att_result)
					att_plainbytes = append(att_plainbytes, att_result)
				} else {
					panic("attack failed since no byte could be used to pass the oracle\n")
				}
			}

			// Each block is decrypted backwards
			slices.Reverse(att_plainbytes)
			att_decrypted_block_chan <- att_block_result{att_target_block, att_plainbytes}
		}(att_target_block)
	}

	for i := att_blocklen - 1; i >= 0; i -= 1 {
		r := <- att_decrypted_block_chan
		att_all_blocks[r.blockidx] = r.plainbytes
	}
	for i := 0; i < len(att_all_blocks); i += 1 {
		att_full_plainbytes = append(att_full_plainbytes, att_all_blocks[i]...)
	}

	att_string, err := validatepkcs7padding(att_full_plainbytes)
	fmt.Printf("att plaintext: %v\n%s\n%s\n", att_full_plainbytes, att_string, base64decode(string(att_string)))
	return string(att_string), err
}

func ctr_fixed_nonce(shortest bool) ([]byte, []byte) {
	// plaintexts := []string {
	// 	"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
	// 	"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
	// 	"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
	// 	"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
	// 	"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
	// 	"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
	// 	"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
	// 	"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
	// 	"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
	// 	"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
	// 	"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
	// 	"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
	// 	"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
	// 	"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
	// 	"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
	// 	"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
	// 	"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
	// 	"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
	// 	"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
	// 	"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
	// 	"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
	// 	"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
	// 	"U2hlIHJvZGUgdG8gaGFycmllcnM/",
	// 	"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
	// 	"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
	// 	"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
	// 	"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
	// 	"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
	// 	"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
	// 	"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
	// 	"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
	// 	"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
	// 	"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
	// 	"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
	// 	"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
	// 	"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
	// 	"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
	// 	"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
	// 	"VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
	// 	"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
	// }
	sc := read("3_20.txt")
	plaintexts := []string{}
	for sc.Scan() {
		plaintexts = append(plaintexts, sc.Text())
	}

	key := randomAESkey()
	a := AES{}
	ctr_encrypt := func(input string) (cipherbytes []byte, keystream []byte) {
		return a.process_ctr(base64decode(input), key, int_to_bytes(uint64(0)), 0)
	}

	ciphertexts := make([][]byte, len(plaintexts))
	keystreams := make([][]byte, len(plaintexts))
	var longest_len, longest_idx int
	var shortest_len int = len(plaintexts[0])
	for k, v := range plaintexts {
		ciphertexts[k], keystreams[k] = ctr_encrypt(v)
		if len(ciphertexts[k]) > longest_len {
			longest_len = len(ciphertexts[k])
			longest_idx = k
		}
		if len(ciphertexts[k]) < shortest_len {
			shortest_len = len(ciphertexts[k])
		}
	}

	// Idea here is that the resulting plaintext needs to be valid English
	// letters, punctuation, spaces
	accept_regexp := regexp.MustCompile(`[a-zA-Z0-9]|[:;"/',!?.-]|\s`)

	// These rules have to be tuned for each plaintext
	reject_regexps := []*regexp.Regexp{

		// No sequence of punctuation chars
		regexp.MustCompile(`[:;"'/]{2}`),

		// No more than 1 space
		// regexp.MustCompile(`[\s]{2,}`),

		// H shouldn't be followed by a char that isn't these (vowels, punctuation, some consonants)
		regexp.MustCompile(`(H|h|x)[^aeiouwmbytr\s:;',!?.-]`),
		
		// These chars shouldn't be followed by certain chars (mostly consonant combinations)
		// regexp.MustCompile(`((n)[h])|t[gfdzv]|d[v]|b[j]|x[r]|r[f]|z[zg]|q[w]|i[uq]`),

		// Capital letters should be preceded by spaces since they mark a new sentence
		// except for first letter of each plaintext, but that's handled in the loop
		// regexp.MustCompile(`[^\s][A-Z]`),

		// Apostrophe must be followed by a lowercase char
		// regexp.MustCompile(`['][^a-z]`),
	}
	att_keystream := []byte{}
	att_plaintexts := make([][]byte, len(ciphertexts))

	ranker := func (plaintext []byte) float64 {
		letters := 0
		re := regexp.MustCompile(`[a-z]|\s`)
		for k, _ := range plaintext {
			if re.Find(plaintext[k: k + 1]) != nil {
				letters += 1
			}
		}
		return float64(letters) / float64(len(plaintext))
	}

	type ranking struct {
		plaintext []byte
		rank float64
	}

	// This will not correctly decrypt all the ciphertexts but it will get most of each
	// This works well in the beginning since all ciphertexts have a 0th char, 1th char, etc
	// Each kth char in a ciphertext was XORed with the same keystream byte, so there are more chances
	// to "check" a guess of a keystream byte and see if it passes/fails the above rules
	// As the end of the ciphertexts near, there are fewer chances to check, and thus bad guesses cannot be weeded out
	ending_pos := shortest_len
	if ! shortest {
		ending_pos = longest_len
	}
	for goal_pos := 0; goal_pos < ending_pos; goal_pos += 1 {
		keystream_ranks := map[byte]ranking{}
		for kval := 0; kval <= 255; kval += 1 {
			keystream_byte := byte(kval)
			plaintext_to_rank := []byte{}
			discard := false
			// fmt.Printf("testing keystream byte %v for pos %d\n", keystream_byte, goal_pos)
			for k, ciphertext := range ciphertexts {
				if goal_pos < len(ciphertext) {
					next_plainbyte := xorbytes(keystream_byte, ciphertext[goal_pos])
					s := []byte{next_plainbyte}
					plaintext_to_rank = append(plaintext_to_rank, next_plainbyte)
					if accept_regexp.Find(s) == nil	{
						// fmt.Printf("DISCARD keystream byte %v for pos %d due to failing test: %s (%d)\n", keystream_byte, goal_pos, append(slices.Clone(att_plaintexts[k]), s...), next_plainbyte)
						discard = true
						break
					}
					if ! discard && goal_pos > 0 {
						s = append(slices.Clone(att_plaintexts[k]), s...)
						for _, re := range reject_regexps {
							if o := re.Find(s); o != nil {
								// fmt.Printf("DISCARD keystream byte %v for pos %d due to passing test %v: %s (%d)\n", keystream_byte, goal_pos, re, s, next_plainbyte)
								discard = true
								break
							}
						}
					}
				}
				if discard {
					// fmt.Printf("keystream byte %v does not work at all\n", keystream_byte)
					break
				}
			}
			if ! discard {
				keystream_ranks[keystream_byte] = ranking{plaintext_to_rank, ranker(plaintext_to_rank)}
			}
		}
		if len(keystream_ranks) == 0 {
			for k, v := range att_plaintexts {
				fmt.Printf("%d %s\n", k, v)
			}
			panic(fmt.Sprintf("no keystream byte found for pos %d\n", goal_pos))
		} else {
			var best_keystream_byte byte
			for k, v := range keystream_ranks {
				t := keystream_ranks[best_keystream_byte]
				if len(t.plaintext) == 0 || v.rank > t.rank {
					best_keystream_byte = k
				}
			}
			// fmt.Printf("best keystream byte for pos %d is: %v => %s\n", goal_pos, best_keystream_byte, keystream_ranks[best_keystream_byte].plaintext)
			// fmt.Printf("all potential keystream bytes for pos %d\n", goal_pos)
			// for k, v := range keystream_ranks {
			// 	fmt.Printf("%v => %s (%v)\n", k, v.plaintext, v.rank)
			// }
			for k, ciphertext := range ciphertexts {
				if goal_pos < len(ciphertext) {
					att_plaintexts[k] = append(att_plaintexts[k], xorbytes(best_keystream_byte, ciphertext[goal_pos]))
				}
			}
			att_keystream = append(att_keystream, best_keystream_byte)
		}
	}
	for k, v := range att_plaintexts {
		fmt.Printf("%d %s\n", k, v)
	}
	return att_keystream[0:ending_pos], keystreams[longest_idx][0:ending_pos]
}