package md4

import (
	"fmt"
	"os"
	"os/exec"
	t "testing"
	"slices"
	"jkayani.local/mycrypto/utils"
)

func Test_MD4_pad(tt *t.T) {
	s := MD4{}
	type tcase struct {
		input, expected []byte
	}
	cases := []tcase {
		tcase{[]byte("1Hundredwire"), utils.Hexdecode("3148756e647265647769726580000000000000000000000000000000000000000000000000000000000000000000000000000000000000006000000000000000")},
	}
	for _, k := range cases {
		o := s.pad(k.input)
		if !slices.Equal(o, k.expected) {
			tt.Fatalf("Failed on MD4 input padding: expected %d for %v got: %v\n", k.expected, k.input, o)
		}
	}
}

func Fuzz_Hash(tf *t.F) {
	s := MD4{Debug: false}

	cases := map[string]string {
		"": "31d6cfe0d16ae931b73c59d7e0c089c0",
		"a": "bde52cb31de33e46245e05fbdbd6fb24",
		"abc": "a448017aaf21d8525fc10ae87aa6729d",
		"message digest": "d9130a8164549fe818874806e1c7014b",
		"abcdefghijklmnopqrstuvwxyz": "d79e1c308aa5bbcdeea8ed63df412da9",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789": "043f8582f241db351ce627e153e7f0e4",
		"12345678901234567890123456789012345678901234567890123456789012345678901234567890": "e33b4ddc9c38f2199c3e7b164fcc0536",
	}
	for k, _ := range cases {
		tf.Add(k)
	}

	path := "./fuzz_hash/"
	cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf("mkdir -p %s", path))
	cmd.Run()
	tf.Fuzz(func(tt *t.T, k string) {

		// Use output files to store testdata to easily pass to openssl (no shell escaping)
		// Use unique file for each input to avoid parallel test run clobbering
		infile := path + s.Hash([]byte(k))

		cli_base := fmt.Sprintf("openssl dgst -md4 -provider legacy < %s | awk '{print $2}';", infile)
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
			tt.Fatalf("Failed to generate expected value for MD4 hash test for: %s", k)
		}

		if o := s.Hash([]byte(k)); o != string(v) {
			tt.Fatalf("Failed on MD4 hash: expected %v (%s) for hash of %v (%s) got: %v (%s)\n", []byte(v), v, []byte(k), k, []byte(o), o)
		}
	})
	tf.Cleanup(func() {
		cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf("rm -rf %s", path))
		cmd.Run()
	})
}