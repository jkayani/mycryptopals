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

func xorbytes(byte1, byte2 byte) (byte) {
	// or the bits to determine where at least 1 is set
	// and the bits to determine where both are set
	// -> negate above to determine where either only 1 is set, or neither
	// -> -> and above negation with the or to find where exactly 1 is set
	return ((byte1 | byte2) & ^(byte1 & byte2))
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

// Make a function that returns an encrypted profile string given an email address: email=e&role=user
// Determine how to mutate a ciphertext such after decryption (simulated login), it yields: email=e&role=admin
func ecb_cutpaste() string {
	profile_for := func(email string) string {
		return fmt.Sprintf("email=%s&role=user", strings.ReplaceAll(strings.ReplaceAll(email, "&", ""), "=", ""))
	}
	parse_profile := func(profile string) map[string]string {
		pairs := map[string]string{}
		inkey := true
		var key, value string
		for i := 0; i < len(profile); i += 1 {
			s := profile[i:i + 1]
			if s == "&" {
				inkey = true
				pairs[key] = value
				key, value = "", ""
			} else if s == "=" {
				inkey = false
			} else {
				if inkey {
					key += s
				} else {
					value += s
				}
			}
		}
		pairs[key] = value
		return pairs
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