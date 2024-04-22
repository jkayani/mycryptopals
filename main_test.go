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

func TestHextobase64(tt *t.T) {
	cases := map[string]string{
		"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d":"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
	}
	for input, expected := range(cases) {
		if out := hex2base64_bitwise(input); out != expected {
			tt.Fatalf("expected %s, got %s base64 encoding of %s", expected, out, input)
		}
	}
}