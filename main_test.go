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

func Testhexdecode(tt *t.T) {
	cases := map[string][]byte{
		"4": []byte{64},
		"49": []byte{73},
		"492": []byte{73, 32},
		"82": []byte{130},
		"23": []byte{35},
	}
	for input, expected := range(cases) {
		if out := hexdecode(input); !slices.Equal(expected, out) {
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
		if out := base64encode_bytes(hex2base64_bytes(hexdecode(input))); out != expected {
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
		if out := base16encode_bytes(fixedxor(hexdecode(input.s1), hexdecode(input.s2))); out != expected {
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
		xordecrypt(hexdecode(input))
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
		if out := repeatingxor([]byte(input.plainbytes), input.key); out != expected {
			tt.Fatalf("expected %s, got %s repeatingxor of  %s key %s", expected, out, input.plainbytes, input.key)
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
		if out := hamming(args[0], args[1]); out != expected[i] {
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
		if out := frombase64char_tovalue(input[0]); out != expected {
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
		if out := base64decode(input); !slices.Equal(out, expected) {
			tt.Fatalf("expected %v, got %v for %s to bytes", expected, out, input)
		}
	}

	first45 := decodebase64_file("1_6.txt")[0:45]
	if !(first45[0] == 0x1d && first45[1] == 0x42 && first45[44] == 0x52) {
		tt.Fatalf("decoded base64 file wrong\n")
	}
}

func TestFindKeySize(tt *t.T) {
	// knowncipherbytes := hexdecode("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
	// findkeysize(knowncipherbytes, 3, 5, 64)

	cipherbytes := decodebase64_file("1_6.txt")
	findkeysize(cipherbytes, 2, 40, 4)
	findkeysize(cipherbytes, 2, 40, 16)
	findkeysize(cipherbytes, 2, 40, 64)
}

func TestDecryptRepeatedXor(tt *t.T) {
	// 0b 36 37 | 27 2a 2b | 2e 63 62 | 2c | 2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
	// knowncipherbytes := hexdecode("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
	// findkey(knowncipherbytes, 3)

	cipherbytes := decodebase64_file("1_6.txt")
	decryptrepeatedxor(cipherbytes, findkeysize(cipherbytes, 2, 40, 64))
}

func TestDetectAES_ECB(tt *t.T) {
	input := "201e802f7b6ace6f6cd0a743ba78aead201e802f7b6ace6f6cd0a743ba78aead"
	if !findaesecb(input) {
		tt.Fatalf("failed to detect AES-128 ECB in %s\n", input)
	}

	detectaes_ecb("1_8.txt")
	// a := AES{}
	// a.Decrypt_ECB(hexdecode(detectaes_ecb("1_8.txt")), []byte("YELLOW SUBMARINE"))
}

func TestPKCS7Pad(tt *t.T) {
	input := "YELLOW SUBMARINE"
	e := base16encode_bytes([]byte(input)) + "04040404"
	if out := pkcs7pad(input, 20); out != e {
		tt.Fatalf("expected %s for PKCS7 pad of %s to len %d, got %s\n", e, input, 20, out)
	}
}

func TestOracle(tt *t.T) {
	trials := 100
	for i := 0; i < trials; i += 1 {
		oneblock := "namenamenamename"
		if ! detectaes_cbc_ecb([]byte(oneblock + oneblock + oneblock)) {
			tt.Fatalf("failed to guess AES encryption mode on trial: %d\n", i)
		}
	}
}

func TestDecryptECB_OneBlock(tt *t.T) {
	mystery := base64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")

	if out := decryptecb_oneblock(mystery); string(out) != string(mystery) {
		tt.Fatalf("failed to decrypt apended mystery text in ECB mode, expected: %v\n, got: %v\n", mystery, out)
	}
}

func TestECB_CutPaste(tt *t.T) {
	if role := ecb_cutpaste(); role != "admin" {
		tt.Fatalf("failed to set role=admin via ECB ciphertext, got role=%s\n", role)
	}
}