package main

import (
	t "testing"
	"slices"
	"fmt"
)

func TestBits(tt *t.T) {
	cases := map[int][]int{
		1: []int{0, 0, 0, 1},
		2: []int{0, 0, 1, 0},
		12: []int{1, 1, 0, 0},
	}

	for input, expected := range(cases) {
		if out := bits(input, len(expected)); !slices.Equal(out, expected) {
			tt.Fatalf("expected %v, got %v for bits(%d)", expected, out, input)
		}
	}
}

func TestToBase64(tt *t.T) {
	cases := map[int]string{
		0: "A",
		26: "a",
		51: "z",
		52: "0",
		62: "+",
		63: "/",
	}

	for input, expected := range(cases) {
		if out := fmt.Sprintf("%c", tobase64(input)); out != expected {
			tt.Fatalf("expected %s, got %s for tobase64(%d)", expected, out, input)
		}
	}
}

func TestMask(tt *t.T) {
	type input struct {
		number byte
		kbits int
	}
	firstcases := map[input]byte{
		input{1 << 4, 4}: 16,
		input{12 << 4, 2}: 192,
	}
	for input, expected := range(firstcases) {
		if out := input.number & firstmask(input.kbits); out != expected {
			bitwise := bits(int(out), 8)
			tt.Fatalf("expected %d, got %d (%v) for first %d bits of (%d)", expected, out, bitwise, input.kbits, input.number)
		}
	}

	lastcases := map[input]byte{
		input{1, 4}: 1,
		input{3, 2}: 3,
	}
	for input, expected := range(lastcases) {
		if out := input.number & lastmask(input.kbits); out != expected {
			bitwise := bits(int(out), 8)
			tt.Fatalf("expected %d, got %d (%v) for last %d bits of (%d)", expected, out, bitwise, input.kbits, input.number)
		}
	}
}

func TestToBytes(tt *t.T) {
	cases := map[string][]byte{
		"4": []byte{64},
		"49": []byte{73},
		"492": []byte{73, 32},
		"82": []byte{130},
		"23": []byte{35},
	}
	for input, expected := range(cases) {
		if out := tobytes(input); !slices.Equal(expected, out) {
			tt.Fatalf("expected %v, got %v bytes of hex %s", expected, out, input)
		}
	}
}

func TestHextobase64(tt *t.T) {
	cases := map[string]string{
		"23": "Iw",
		"82bcf2": "grzy",
		"49276d20":"SSdtIA",
		"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d":"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
	}
	for input, expected := range(cases) {
		if out := base64encode_bytes(hex2base64_bytes(tobytes(input))); out != expected {
			tt.Fatalf("expected %s, got %s base64 encoding of %s", expected, out, input)
		}
	}
}

func TestFixedXor(tt *t.T) {
	type input struct {
		s1 string
		s2 string
	}
	cases := map[input]string {
		input{"1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965"}: "746865206b696420646f6e277420706c6179",
	}
	for input, expected := range(cases) {
		if out := base16encode_bytes(fixedxor(tobytes(input.s1), tobytes(input.s2))); out != expected {
			tt.Fatalf("expected %s, got %s fixedxor b/w %s and %s", expected, out, input.s1, input.s2)
		}
	}
}

func TestXorByteCipher(tt *t.T) {
	cases := []string {
		"1b373733",
		"1b37373331363f78151b7f2b",
		"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
	}
	for _, input := range(cases) {
		xordecrypt(tobytes(input))
	}
}

func TestFindXoredString(tt *t.T) {
	findxoredstring()
}

func TestRepeatingXor(tt *t.T) {
	type i struct {
		plainbytes string
		key string
	}
	cases := map[i]string {
		i{"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "ICE"}: "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
	}
	for input, expected := range(cases) {
		if out := repeatingxor(tobytes_ascii(input.plainbytes), input.key); out != expected {
			tt.Fatalf("expected %s, got %s repeatingxor of  %s key %s", expected, out, input.plainbytes, input.key)
		}
	}
}