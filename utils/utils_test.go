package utils

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
		if out := Bits(input, len(expected)); !slices.Equal(out, expected) {
			tt.Fatalf("expected %v, got %v for bits(%d)", expected, out, input)
		}
	}
}

func Test_Bitstream_Bytes(tt *t.T) {
	in := []int{0,0,1,1,0,0,0,1,0,1,0,0,1,0,0,0,0,1,1,1,0,1,0,1,0,1,1,0,1,1,1,0,0,1,1,0,0,1,0,0,0,1,1,1,0,0,1,0,0,1,1,0,0,1,0,1,0,1,1,0,0,1,0,0,0,1,1,1,0,1,1,1,0,1,1,0,1,0,0,1,0,1,1,1,0,0,1,0,0,1,1,0,0,1,0,1}
	e := Hexdecode("3148756e6472656477697265")
	if a := Bitstream_bytes(in); ! slices.Equal(e, a) {
		tt.Fatalf("expected %v for byte-slice encoding of %v, got: %v", e, in, a)
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
		if out := fmt.Sprintf("%c", Tobase64(input)); out != expected {
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
		if out := input.number & Firstmask(input.kbits); out != expected {
			bitwise := Bits(int(out), 8)
			tt.Fatalf("expected %d, got %d (%v) for first %d bits of (%d)", expected, out, bitwise, input.kbits, input.number)
		}
	}

	lastcases := map[input]byte{
		input{1, 4}: 1,
		input{3, 2}: 3,
	}
	for input, expected := range(lastcases) {
		if out := input.number & Lastmask(input.kbits); out != expected {
			bitwise := Bits(int(out), 8)
			tt.Fatalf("expected %d, got %d (%v) for last %d bits of (%d)", expected, out, bitwise, input.kbits, input.number)
		}
	}
}

func TestHexdecode(tt *t.T) {
	cases := map[string][]byte{
		"4": []byte{64},
		"49": []byte{73},
		"492": []byte{73, 32},
		"82": []byte{130},
		"23": []byte{35},
	}
	for input, expected := range(cases) {
		if out := Hexdecode(input); !slices.Equal(expected, out) {
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
		if out := Base64encode_bytes(Hex2base64_bytes(Hexdecode(input))); out != expected {
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
		if out := Base16encode_bytes(Fixedxor(Hexdecode(input.s1), Hexdecode(input.s2))); out != expected {
			tt.Fatalf("expected %s, got %s fixedxor b/w %s and %s", expected, out, input.s1, input.s2)
		}
	}
}

// A -> 0100 0001
// B -> 0100 0010
func TestHamming(tt *t.T) {
	type i [][]byte
	inputs := [][][]byte{
		i{[]byte("A"), []byte("B")},
		i{[]byte("A"), []byte("A")},
		i{[]byte("this is a test"), []byte("wokka wokka!!!")},
		i{[]byte{0x0b}, []byte{0x27}},
		i{[]byte{0x36}, []byte{0x2a}},
		i{[]byte{0x37}, []byte{0x2b}},
		i{[]byte{0x0b, 0x36, 0x37}, []byte{0x27, 0x2a, 0x2b}},
	}
	expected := []int{2, 0, 37, 3, 3, 3, 9}
	for i, args := range(inputs) {
		if out := Hamming(args[0], args[1]); out != expected[i] {
			tt.Fatalf("expected %d, got %d hamming b/w %v and %v", expected[i], out, args[0], args[1])
		}
	}
}

func TestBase64Decode(tt *t.T) {
	charcases := map[string]byte {
		"A": 0,
		"Z": 25,
		"a": 26,
		"z": 51,
		"0": 52,
		"9": 61,
		"+": 62,
		"/": 63,
	}
	for input, expected := range(charcases) {
		if out := Frombase64char_tovalue(input[0]); out != expected {
			tt.Fatalf("expected %v, got %v for base64 decode of %s", expected, out, input)
		}
	}

	cases := map[string][]byte {
		"A": []byte{},
		"ASS": []byte{1, 36},
		"ASS/": []byte{1, 36, 0xbf},
		"F6": []byte{0x17},
		"F6581fj": []byte{0x17, 0xae, 0x7c, 0xd5, 0xf8},
		"F658b1": []byte{0x17, 0xae, 0x7c, 0x6f},
		"dGhpcyBpcyBhIGNvbXBsaWNhdGVkIHRlc3QK": []byte("this is a complicated test\n"),
		"dGhpcyBpcyBhIGNvbXBsaWNhdGVkIHRlc3Q=": []byte("this is a complicated test"),
		"dGhpcyBpcyBhIGNvbXBsaWNhdGVkIHRlcw==": []byte("this is a complicated tes"),
	}
	for input, expected := range(cases) {
		if out := Base64decode(input); !slices.Equal(out, expected) {
			tt.Fatalf("expected %v, got %v for %s to bytes", expected, out, input)
		}
	}

	first45 := Decodebase64_file("../1_6.txt")[0:45]
	if !(first45[0] == 0x1d && first45[1] == 0x42 && first45[44] == 0x52) {
		tt.Fatalf("decoded base64 file wrong\n")
	}
}

func TestPKCS7Pad(tt *t.T) {
	input := "YELLOW SUBMARINE"
	e := Base16encode_bytes([]byte(input)) + "04040404"
	if out := Pkcs7pad(input, 20); out != e {
		tt.Fatalf("expected %s for PKCS7 pad of %s to len %d, got %s\n", e, input, 20, out)
	}
}

func Test_ValidatePKCS7Padding(tt *t.T) {
	type s struct {
		input []byte
		expected []byte
	}
	expected := []byte("ICE ICE BABY")

	cases := []s{
		s{
			[]byte("ICE ICE BABY\x04\x04\x04\x04"),
			expected,
		},
		s{
			[]byte("ICE ICE BABY\x04\x04\x04"),
			nil,
		},
		s{
			[]byte("ICE ICE BABY\x05\x05\x05\x05"),
			nil,
		},
		s{
			[]byte("ICE ICE BABY\x01\x02\x03\x04"),
			nil,
		},
		s{
			[]byte("ICE ICE BABY\x04\x04\x04\x04\x04"),
			append(expected, byte(4)),
		},
	}

	for _, c := range cases {
		if out, _ := Validatepkcs7padding(c.input); !slices.Equal(out, c.expected) {
			tt.Fatalf("expected %v for removed padding off %v, got: %v\n", c.expected, c.input, out)
		}
	}
}