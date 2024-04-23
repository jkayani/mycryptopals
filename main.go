package main

import (
	"fmt"
	"slices"
	"math"
)

func main() {
	fmt.Println("nothing")
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

func frombase16(digit byte) (val int) {
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
func tobase16(val int) (digit byte) {
	if val >= 10 {
		return byte(87 + val)
	}
	return byte(48 + val)
}

func hex2base64(hex string) string {
	bitstream := make([]int, 0)

	for k := 0; k < len(hex); k += 1 {

		// hex to binary, resolving hex digits to decimal values
		order := bits(frombase16(hex[k]), 4)

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
		val := byte(frombase16(hexdigit))
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

func fixedxor(hex1, hex2 string) (result string) {
	for i := 0; i < len(hex1); i +=1 {
		val1, val2 := frombase16(hex1[i]), frombase16(hex2[i])

		// or the bits to determine where at least 1 is set
		// and the bits to determine where both are set
		// -> negate above to determine where either only 1 is set, or neither
		// -> -> and above negation with the or to find where exactly 1 is set
		r := ((val1 | val2) & ^(val1 & val2))
		result += fmt.Sprintf("%c", tobase16(r))

		// fmt.Printf("val1: %d (%v), val2: %d (%v) => XOR: %d (%v)", val1 , bits(val1, 4), val2, bits(val2, 4), r, bits(r, 4))
	}

	return result
}