package sha1

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	t "testing"
	"slices"
	"jkayani.local/mycrypto/utils"
)

func Test_SHA1_s(tt *t.T) {
	type tcase struct {
		input, factor int
	}
	cases := map[tcase]int {
		tcase{2 << 30, 1}: 1,
		tcase{2 << 30, 2}: 2,
		tcase{bit_32 - 1, 1}: bit_32 - 2,
		tcase{0x67452301, 5}: 0xE8A4602C,
		tcase{-9223372026700110976, 5}: 2826727435,
		tcase{10154664832, 5}: 2826727435,
	}
	for k, v := range cases {
		if o := s(k.input, k.factor); o != v {
			tt.Fatalf("Failed on SHA-1 s func: expected %x for s(%x, %x) got: %x\n", v, k.input, k.factor, o)
		}
	}
}

func Test_SHA1_f(tt *t.T) {
	type tcase struct {
		round, b, c, d, ans int
	}
	cases := []tcase {
		tcase{0, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0x98badcfe},
	}
	for _, k := range cases {
		if o := f(k.round, k.b, k.c, k.d); o != k.ans {
			tt.Fatalf("Failed on SHA-1 s func: expected %x for f, got: %x", k.ans, o)
		}
	}
}

func Test_SHA1_pad(tt *t.T) {
	s := SHA1{}
	type tcase struct {
		input, expected []byte
	}
	cases := []tcase {
		tcase{[]byte("1Hundredwire"), utils.Hexdecode("3148756e647265647769726580000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000060")},
		tcase{[]byte{97, 98, 99, 100, 101},utils.Hexdecode("61626364658000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028")},
	}
	for _, k := range cases {
		o := s.pad(k.input)
		if !slices.Equal(o, k.expected) {
			tt.Fatalf("Failed on SHA-1 input padding: expected %d for %v got: %v\n", k.expected, k.input, o)
		}
	}
}

func Fuzz_Hash(tf *t.F) {
	s := SHA1{}

	cases := map[string]string {
		"1Hundredwire": "56027592bcf72da97f115276251e9c30a428e3da",
		"abc": strings.ToLower("A9993E364706816ABA3E25717850C26C9CD0D89D"),
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq": strings.ToLower("84983E441C3BD26EBAAE4AA1F95129E5E54670F1"),
		"josh": "c028c213ed5efcf30c3f4fc7361dbde0c893c5b7",
	}
	for k, _ := range cases {
		tf.Add(k)
	}

	path := "./fuzz_hash/"
	cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf("mkdir -p %s", path))
	cmd.Run()
	tf.Fuzz(func(tt *t.T, k string) {

		// Use output files to store testdata to easily pass to sha1sum (no shell escaping)
		// Use unique file for each input to avoid parallel test run clobbering
		infile := path + s.Hash([]byte(k))

		cli_base := fmt.Sprintf("sha1sum < %s | awk '{print $1}';", infile)
		// cli_base := fmt.Sprintf("openssl sha1 - < %s | awk '{print $2}';", infile)
		f, err := os.Create(infile)
		if err != nil {
			tt.Fatalf("err: %s", err)
		}
		_, err = f.Write([]byte(k))
		if err != nil {
			tt.Fatalf("err: %s", err)
		}
		f.Close()

		cmd := exec.Command("/bin/sh", "-c", cli_base)
		tt.Logf("input: %v (%s)\nexpected value generated via %s\n", []byte(k), k, cmd)
		v, err := cmd.Output()
		v = v[0 : len(v) - 1]
		if err != nil {
			tt.Fatalf("Failed to generate expected value for SHA-1 hash test for: %s", k)
		}

		if o := s.Hash([]byte(k)); o != string(v) {
			tt.Fatalf("Failed on SHA-1 hash: expected %v (%s) for hash of %v (%s) got: %v (%s)\n", []byte(v), v, []byte(k), k, []byte(o), o)
		}
	})
	tf.Cleanup(func() {
		cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf("rm -rf %s", path))
		cmd.Run()
	})
}