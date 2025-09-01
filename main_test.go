package main

import (
	t "testing"
	"slices"

	"jkayani.local/mycrypto/utils"
	"jkayani.local/mycrypto/aes"
)

func TestXorByteCipher(tt *t.T) {
	cases := []string {
		"1b373733",
		"1b37373331363f78151b7f2b",
		"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
	}
	for _, input := range(cases) {
		xordecrypt(utils.Hexdecode(input))
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

func TestFindKeySize(tt *t.T) {
	// knowncipherbytes := utils.Hexdecode("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
	// findkeysize(knowncipherbytes, 3, 5, 64)

	cipherbytes := utils.Decodebase64_file("1_6.txt")
	findkeysize(cipherbytes, 2, 40, 4)
	findkeysize(cipherbytes, 2, 40, 16)
	findkeysize(cipherbytes, 2, 40, 64)
}

func TestDecryptRepeatedXor(tt *t.T) {
	// 0b 36 37 | 27 2a 2b | 2e 63 62 | 2c | 2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
	// knowncipherbytes := utils.Hexdecode("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
	// findkey(knowncipherbytes, 3)

	cipherbytes := utils.Decodebase64_file("1_6.txt")
	decryptrepeatedxor(cipherbytes, findkeysize(cipherbytes, 2, 40, 64))
}

func TestDetectAES_ECB(tt *t.T) {
	input := "201e802f7b6ace6f6cd0a743ba78aead201e802f7b6ace6f6cd0a743ba78aead"
	if !findaesecb(input) {
		tt.Fatalf("failed to detect AES-128 ECB in %s\n", input)
	}

	detectaes_ecb("1_8.txt")
	// a := AES{}
	// a.Decrypt_ECB(utils.Hexdecode(detectaes_ecb("1_8.txt")), []byte("YELLOW SUBMARINE"))
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
	mystery := utils.Base64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")

	if out := decryptecb_oneblock(mystery); string(out) != string(mystery) {
		tt.Fatalf("failed to decrypt apended mystery text in ECB mode, expected: %v\n, got: %v\n", mystery, out)
	}
}

func TestECB_CutPaste(tt *t.T) {
	if role := ecb_cutpaste(); role != "admin" {
		tt.Fatalf("failed to set role=admin via ECB ciphertext, got role=%s\n", role)
	}
}

func TestECB_DecryptRandom(tt *t.T) {
	mystery := utils.Base64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")

	if out := decryptecb_random(mystery); string(out) != string(mystery) {
		tt.Fatalf("failed to decrypt apended mystery text in ECB mode, expected: %v\n, got: %v\n", mystery, out)
	}
}

func Test_CBC_Bitflip(tt *t.T) {
	if ! cbc_bitflip() {
		tt.Fatalf("expected true, got false\n")
	}
}

func Test_CBC_Padding_Oracle(tt *t.T) {
	plaintexts := []string{
	"0123456789abcde",
	"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
	"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
	"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
	"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
	"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
	"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
	"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
	"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
	"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
	"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
	}
	for _, p := range plaintexts {
		if actual, err := cbc_padding_oracle(p); err != nil || p != actual {
			tt.Fatalf("expected: %s\ngot: %s\n\nerr: %s\n", p, actual, err)
		}
	}
}

func Test_CTR_Fixed_Nonce(tt *t.T) {
	test := func(v bool) {
		actual, expected := ctr_fixed_nonce(v)
		if len(actual) != len(expected) {
			tt.Fatalf("expected len: %d, got len: %d\n", len(expected), len(actual))
		}
		idx := -1
		for k, _ := range expected {
			if expected[k] == actual[k] {
				idx += 1
			}
		}
		tt.Logf("idx right: %d / %d\npercent accuracy of guessing CTR fixed nonce keystream: %v\nexpected: %v\nactual: %v\n", idx + 1, len(actual), 100 * (float64(idx + 1) / float64(len(actual))), expected, actual)
		if v {
			if idx + 1 != len(expected) {
				tt.Fatalf("CTR mode keystream was not correctly deduced: expected: %v\ngot: %v\n", expected, actual)
			}
		}
	}
	test(true)
	test(false)
}

func Test_Crack_MT_Seed(tt *t.T) {
	e, a := mt_seed_crack()
	if e != a {
		tt.Fatalf("Crack MT19937 seed failed: actual: %d, expected: %d\n", a, e)
	}
}

func Test_Clone_MT(tt *t.T) {
	gen, att_gen := mt_clone()
	limit := 10
	for i := 0; i < limit; i += 1 {
		expected := gen.Gen()
		actual := att_gen.Gen()
		if expected != actual {
			tt.Fatalf("actual: %d, expected: %d\n", actual, expected)
		}
	}
}

func Test_Break_MT_Stream(tt *t.T) {
	e, a := mt_stream_break()
	if e != a {
		tt.Fatalf("Crack MT19937 seed from stream cipher failed: actual: %d, expected: %d\n", a, e)
	}
}
func BenchmarkBreak_MT_Stream(tt *t.B) {
	for range tt.N {
		e, a := mt_stream_break()
		if e != a {
			tt.Fatalf("Crack MT19937 seed from stream cipher failed: actual: %d, expected: %d\n", a, e)
		}
	}
}

func Test_Break_CTR_Seek_Edit(tt *t.T) {
	e, a := break_ctr_seek_edit()
	if !slices.Equal(e, a) {
		tt.Fatalf("Break AES-CTR via random (seek) edit failed: actual: %d, expected: %d\n", a, e)
	}
}

func Test_CTR_Bitflip(tt *t.T) {
	if ! ctr_bitflip() {
		tt.Fatalf("CTR bit flip failed")
	}
}

func Test_CBC_Key_as_IV(tt *t.T) {
	e, a := cbc_key_as_iv()
	if !slices.Equal(e, a) {
		tt.Fatalf("Recover AES-CBC key when key=IV failed: actual: %v, expected: %v\n", a, e)
	}
}

func Fuzz_SHA1_Keyed_MAC(tf *t.F) {
	test_input := "josh"
	key := aes.RandomAESkey()
	expected := sha1_keyed_mac(key, []byte(test_input))
	tf.Fuzz(func(tt *t.T, input []byte) {
		out := sha1_keyed_mac(key, input)
		if out == expected && !slices.Equal(input, []byte(test_input)) {
			tt.Fatalf("generated matching MAC with input: %v unlike test case: %v", input, test_input)
		}
	})
}