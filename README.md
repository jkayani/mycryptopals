## Notes

### Basics

- Base16 is 4 bits per char. Base64 is 6 bits per char

- XOR is basically "at least one AND not both"
- XOR can count Hamming distance (i.e, where are bits different)
- XOR can be inverted via XORing against the same argument

- Repeating-key ciphers decompose to single-key ciphers once key size is known

### Block ciphers

- AES blocks are 4 words long, each word is 4 bytes - 16 bytes, 32 hex chars. Block is internally a col-major matrix where each word (of 4 consecutive bytes) forms a column. 
- AES "round key" is 1 block in size. Each row of the round key is paired with each _col_ of each AES block

- ECB is basic AES, applied block by block. Repeated blocks of plaintext will appear as repeated blocks of ciphertext since the AES algorithm is stateless (output is purely a function of the input). This is readily apparent in base16 encoded strings (repeated substrings of 32 chars)

- CBC is "chained" between blocks, XORing each plaintext block with previous ciphertext block or IV. Unlike ECB mode, this means encryption cannot be done on all blocks in parallel: must be done serially to feed output into next input

#### ECB/CBC oracle

By supplying a plaintext where a known string with length = 1 block is embedded, a mystery algorithm using either ECB or CBC can be differentiated due to the flaw of ECB above:

```
<random-data><known-string><more-random-data>
```

Depending on how much random data there is, the length of `<known-string>` may need to be expanded to _guarantee_ that at least 2 blocks of `<known-string>` will be in the plaintext:

```
In bytes:
<random-data><known-string><known-string>...<more-random-data>

In blocks:
<block1><block2><block3><block4>
```

If block size is `SIZE`:

```
block 1: first SIZE bytes of <random-data>
block 2: next SIZE bytes of <random-data>
...
block k: all remaining M bytes of <random-data> + (SIZE - M) bytes of <known-string>
block k + 1: M bytes of <known-string> + (SIZE - M) bytes of <known-string>
block k + 2: M bytes of <known-string> + (SIZE - M) bytes of <known-string>
block k + 3: M bytes of <known-string> + (SIZE - M) bytes of remaining data
...
all remaining data split into SIZE blocks

M = len(<random-data>) % SIZE
```

This requires a min of 3 blocks of `<known-string>` to guarantee a repeated block, which can be used as above to identify if the resulting ciphertext was made with ECB or CBC mode.

#### ECB one byte at a time

Above technique can be extended to reveal mystery plaintexts, if the plaintext can be accessed in a way that it can be fed to an ECB mode oracle that operates under a fixed key

- Prepare a `<known-string>` with length = 1 block
- Append `<mystery-string>` (of length 1 block) to `<known-string> - last byte` to make a string `<apended>`
- Encrypt `<apended>`: the last block will be the encryption of `<known-string> + first byte of <mystery-string>`
- Try encrypting all possibilties for the last byte of `<known-string> - last byte + mystery byte` until the result is the same encrypted value as seen previously
  - Note: after the first mystery byte is found, the guesses remain narrowed by using the previously found byte as part of the guess
  - e.g, if first byte is found to be X, make sure to use `<known-string> - 2 + X + <guess-value>` on each guess
- Repeat for the rest of the block, re-constructing `<apended>` by subtracting last 2 bytes of `<known-string>`...
- Repeat for any more blocks of the arbitrary string

```
block 1: SIZE - 1 bytes of <known-string> + 1st byte of <mystery-string>
block 2: SIZE - 1 bytes of <mystery-string>
...

block 1: SIZE - 2 bytes of <known-string> + 1st 2 bytes of <mystery-string>
block 2: SIZE - 2 bytes of <mystery-string>
...

block 1: 0 bytes of <known-string> + all SIZE bytes of <mystery-string>
```

This works because of the stateless nature of ECB and because the range of possibilities to guess is narrowed significantly by only varying the last byte of the last block

#### CBC bitflip

CBC works as follows:

- XOR plaintext block with preceding ciphertext block (or IV)
- ECB_Encrypt the result

In a situation with an N-block ciphertext where:

- Attacker controls the block boundaries via their input (e.g, spill data into an adjacent block)
- Attacker knows the _plaintext_ of block N
- There is no validation of the ciphertext (e.g, no hashing or other integrity control)
- There is no harm from scrambling any given block of the ciphertext (e.g, it's OK for block N - 1 to decrypt into garbage)

The attacker can modify the ciphertext so that when decrypted, block N decrypts into a desired string. This is because CBC will XOR the result of `EBC_Decrypt`ing block N with the block N - 1 ciphertext. The block N - 1 ciphertext can be replaced so that when XORed with `EBC_Decrypt(block N)` the desired string is generated

#### CBC padding oracle

My original approach was:

- Find the padding value, by starting from end of preceding cipherblock, and modifying each byte until the oracle passes. The byte position at which the oracle stops failing and starts passing implies where the padding stops, thus revealing the padding. If this condition is never met, padding is 0

- (Assuming there is padding > 0), set the target padding to padding + 1, and starting from end - 1 of preceding cipherblock, modify the byte in that position (subsitute each possible byte) until the oracle passes. This information indirectly reveals the EBC_Decrypt of the target byte, which can XOR'ed with unmodified corresponding byte from preceding cipherblock to reveal plaintext

- Repeat above for the remainder of the last block

<details>
<pre>
	// Now that padding byte is known to be N
	// Replace padding bytes with N + 1. Goal is to get byte k at pos len - N
	// Replace kth byte of preceding ciphertext until the oracle passes (B')
	// This means: ECB_Decrypt(cipher)_k xor B' = N + 1
	// ECB_Decrypt(cipher)_k = (N + 1) xor B'
	// plain_k = ECB_Decrypt(cipher)_k xor cipher_prev_k
	// = (N + 1) xor B' xor cipher_prev_k

	// TODO: how to extend this attack beyond the last cipherblock?
	// After the last cipherblock is decrypted, the attack fails
	// since there is no way to set padding >= 16 without overwriting the current target block 

	// In other words: this attack fails if no there is padding

	att_plainbytes := make([]byte, att_padding_len)
	for i := 0; i < att_padding_len; i += 1 {
		att_plainbytes[i] = byte(att_padding_len)
	}
	target_block := att_blocklen - 1
	for j := len(att_cipherbytes) - att_padding_len - 1; j >= 48; j -= 1 {
		att_goal_pos := j
		att_goal_pos_in_block := att_goal_pos - (blocksize_bytes * (att_goal_pos / blocksize_bytes))
		att_new_padding_byte := byte(att_padding_len) + byte(blocksize_bytes - att_padding_len - att_goal_pos_in_block)
		fmt.Printf("original padding: %d; abs goal pos: %d; relative goal pos: %d; new padding: %d\n", att_padding_len, att_goal_pos, att_goal_pos_in_block, att_new_padding_byte)

		if len(att_plainbytes) > 0 && len(att_plainbytes) % blocksize_bytes == 0 {
			target_block -= 1
		}
		var att_modified_preceding_block []byte
		if target_block == 0 {
			att_modified_preceding_block = slices.Clone(att_iv)
		} else {
			att_modified_preceding_block = slices.Clone(nth_block(att_cipherbytes, target_block - 1))
		}
		fmt.Printf("target block: %d: %v\n", target_block, att_modified_preceding_block)

		for i, k := att_goal_pos + 1, att_goal_pos_in_block + 1; i < len(att_cipherbytes); i, k = i + 1, k + 1 {
			// Apply the CBC bitfip attack to guarantee the "new" padding bytes are Y=N + 1
			// ? xor X = N
			// ? = N xor X
			// ? xor X = Y
			// X' = Y xor ?
			// X' = Y xor (N xor X)
			att_known_plainbyte := att_plainbytes[len(att_plainbytes) - (i - att_goal_pos)]
			fmt.Printf("modifying byte %d in preceding cipherblock knowing corresponding plainbyte in next block is: %d (%c)\n", i, att_known_plainbyte, att_known_plainbyte)
			att_modified_preceding_block[k] = xorbytes(att_new_padding_byte, xorbytes(att_known_plainbyte, att_modified_preceding_block[k]))
		}
		fmt.Printf("modified cipherblock: %v\n", att_modified_preceding_block)
		var result byte
		found := false
		for i := 0; i < 256; i += 1 {
			att_modified_preceding_block[att_goal_pos_in_block] = byte(i)

			att_modified_cipherbytes := append(slices.Clone(att_cipherbytes[0:blocksize_bytes * (target_block - 1)]), att_modified_preceding_block...)
			att_modified_cipherbytes = append(att_modified_cipherbytes, att_cipherbytes[blocksize_bytes * target_block:]...)

			// fmt.Printf("old: %v\nnew: %v\n", att_cipherbytes, att_modified_cipherbytes)

			if second(att_modified_cipherbytes) {
				fmt.Printf("using byte value %v causes oracle to pass\n", i)
				result = byte(i)
				found = true
				break
			}
		}
		if !found {
			panic("no byte value caused oracle to pass\n")
		}
		att_plain_byte := xorbytes(att_new_padding_byte, xorbytes(result, nth_block(att_cipherbytes, target_block - 1)[att_goal_pos_in_block]))
		fmt.Printf("attacker determined plain text byte is: %v (%c), real answer: %v (%c)\n", att_plain_byte, att_plain_byte, plaintexts[n][att_goal_pos], plaintexts[n][att_goal_pos])
		if att_plain_byte != plaintexts[n][att_goal_pos] {
			panic("attack failed\n")
		}
		att_plainbytes = append(att_plainbytes, att_plain_byte)
	}
	slices.Reverse(att_plainbytes)
	fmt.Printf("actual: %s\nattacker: %s\n", plaintexts[n], att_plainbytes[0:len(att_plainbytes) - att_padding_len])
</pre>
</details>

This worked to decrypt the _last_ block, but then I was stuck trying to decrypt all blocks before it - since there is no way to set a padding > 16 without overwriting the bytes in the block I'm targeting.

New approach that doesn't rely on the presence of any padding at all:

Credits to <https://grymoire.wordpress.com/2014/12/05/cbc-padding-oracle-attacks-simplified-key-concepts-and-pitfalls/> for making it "click":

- Attempt to make the oracle pass with padding byte of 1. That requires causing the target byte (last byte of target block of ciphertext), when XOR'ed with corresponding byte from previous cipherblock, to equal 1. Modify the corresponding cipherbyte from previous block (substitute each possible byte) until this condition is met. This provides the following:

```
T=target byte
C=corresponding byte in previous block of ciphertext
C'=modified corresponding byte in previous block of ciphertext

ECB_D(T) xor C' = 1
ECB_D(T) = 1 xor C'
T = ECB_D(T) xor C (from definition of CBC Decrypt)
T =(1 xor C') xor C (from definition of CBC Decrypt)
```

- Repeat the above, but with a goal of making oracle pass with padding byte of 2. When modifying the bytes of preceding cipherblock that correspond to _known_ plaintext bytes, use the known information to guarantee the bytes will equal the desired padding. Repeat for that block, and start over for the preceding block

This approach is similar to my original idea (incrementing the attacker "target" padding byte with each byte from the end to decrypt) but just relies on finding the first plaintext byte and using that to find the rest

There is an extra caveat to this approach detailed in the code (for special case of goal padding = 1)

### Stream ciphers and RNG

#### CTR and the nonce

CTR mode works like this:

- Generate a keystream (stream of bytes with length exactly equal to the length of plaintext). Each segment of keystream is 16 bytes long: first 8 bytes are a fixed-value (nonce), second 8 bytes are a little-endian counter (0, 1, 2 ...). Encrypt these (with AES)

- XOR the keystream against the plaintext to generate the ciphertext

If the same AES key and same nonce are used to encrypt multiple plaintexts, the resulting ciphertexts can be used to deduce the keystream and decrypt the ciphertexts. The nth byte of each resulting ciphertext would be XORed with the same keystream byte. By guessing values of the keystream byte, "bad" guesses can be eliminated based on expected properties of the plaintext (non-ASCII chars, etc), and with enough ciphertext samples, enough bad guesses can be eliminated to yield the right answer. It's the same idea as repeating-key XOR

This works less and less effectively the more the keystream is deduced, since there becomes fewer and fewer ciphertext samples to use (assuming the ciphertexts are of variable-length)

The usage of XOR here also means any situation where a combination of plaintext and ciphertext (under constant key) is known, is vulernable to modifications of ciphertext to yield arbitrary plaintexts. This is because the keystream can be easily derived from XOR'ing plaintext and ciphertext which in turn can be used to encrypt desired plaintexts

#### Mersenne Twister

<https://en.wikipedia.org/wiki/Mersenne_Twister>


After 624 RNG outputs, state array is completely full of those untempered RNG outputs, and they are used for all future generation. Tempered outputs can be reversed to give un-tempered outputs easily. So w/o knowing the seed, the RNG can be cloned and predicted

Un-tempering can be done bit by bit given the tempering "result": 

- Call the desired value A, and the variant of A shifted by a factor into a direction B
- Identify the shift factor and direction
- Note that all bits to the left/right of the shift factor (depending on shift direction) will be 0
- Use the corresponding bit of the "result" and the known 0 bits of B to calculate the A bits from 0 to shift factor. Bit masking won't matter here since the B bits are guaranteed to be 0
- Note that the A bit at position shift factor +/- 1 is the B bit at the shift factor due to definition of shift. Account for any bit masking here
- Repeat above to find A bit at position shift factor, and continue for all bits of A


My attempt to "reverse" the seed was:

- Seed the RNG with unknown seed
- Generate 1 RNG output, the k=0 RNG output. This was generated using the seed, k=1 value from state array, and k=397 value from state array
- Generate 397 more RNG outputs, keeping note of the RNG outputs for k=169 and k=396. These are important since the RNG output when k=396 is generated using k=396 value from state, k=397 from state, and k=((396 + 397) % 624 = 169) from state
- k=169 from state array will be known after generating all those RNG outputs, as it will be the un-tempered k=169 RNG output
- Since k=169 value from state array is known, possibilities for k=397 from state array can be generated. There are 8 possibilities due to the unknowns of:
	- Reversing the "twist" (multiply by `A` matrix) since reversing this operation requires knowing what the last bit of it's input was to reverse the `xor` (either 0 or 1, so 2 options)
	- Knowing what the last bit of un-doing above would give, for un-doing the `<< 1` (either 0 or 1, again 2 options)
	- The 0th bit for k=397 value from state array, since above 4 options are all based on the last _31_ bits of the k=397, and there are 2 choices for the 0th bit
	- 2 * 2 * 2 = 8. One of these will be k=397 from state array
- For each of these 8 options, apply the same technique against k=0 RNG output to identify 8*8=64 possibilities for k=1 value from state array. One of these will be k=1 from state array
- Reverse the state initialization for each candidate k=1 value, and use the result as a fresh seed into RNG, and return when that generator's first RNG output matches the original k=0 RNG output

This idea worked up until the last step: reversing the state initialization is seemingly impossible, since the result of the operation in the "forward" direction truncates the result to fit 32 bit-length. So to reverse it, the truncation must be reversed by "expanding"the candidate k=1 value from state array, reversing that algebra, and then un-tempering the result to yield the seed. Since there is no way to know (?) how to expand the k=1 value from state array, this idea fails

<details>
<pre>
func mt_seed_crack() {
	seed := 5489
	mt := MTrng{}
	mt.mt_init(seed)

	n := mt.mt_gen()
	rng_out := n

	reverse_temper := func(n, len, shift, mask int, dir bool) int {
		nbits := bits(n, len)
		a := bits(0, len)
		maskbits := bits(mask, len)

		if dir {
			// B bits [0, shift) are 0 AND corresponding bit of the mask
			// First bit of A is corresponding bit of B xor first bit of n
			for i := 0; i < shift; i += 1 {
				a[i] = xorbytes(0 & maskbits[i], nbits[i])
			}
			// b[i] = a[i - shift] which in turn yields a[i]
			for i := shift; i < len; i += 1 {
				a[i] = xorbytes(a[i - shift] & maskbits[i], nbits[i])
			}
		} else {
			// B bits [len - 1, shift) are 0 AND mask
			// Last bit of A is corresponding bit of B xor last bit of n 
			for i := len - 1; i > len - 1 - shift; i -= 1 {
				a[i] = xorbytes(0 & maskbits[i], nbits[i])
			}
			// b[i] = a[i - shift] which in turn yields a[i]
			for i := len - 1 - shift; i >= 0; i = i - 1 {
				a[i] = xorbytes(a[i + shift] & maskbits[i], nbits[i])
			}
		}
		r := bitval(a)
		// fmt.Printf("nbits: %v\na: %v (%v)\n", nbits, a, r)
		return r
	}
	reverse_all_temper := func(n int) int {
		n = reverse_temper(n, mt_w, mt_l, bit_32, true)
		n = reverse_temper(n, mt_w, mt_t, mt_c, false)
		n = reverse_temper(n, mt_w, mt_s, mt_b, false)
		return reverse_temper(n, mt_w, mt_u, mt_d, true)
	}

	n = reverse_all_temper(n)
	fmt.Printf("reversed temper of RNG 1 and RNG 2: %d\n", n)

	// New idea:
	// Find x_397 from original state array to narrow down x_1 to 8 choices and reverse each to find seed
	// To find x_397, analyze k=396
	// x_396 = x_((397 + 396) % 624 = 169 = reverse_temper(RNG_169)) xor (something with x_397 lower 31 bits in it)
	// x_396 = reverse_temper(RNG_396)
	// => narrow down x_397 to 8 different choices
	// => narrow down x_1 to 64 (8 choices for x_397 * 8 choices for x_1) different choices
	// => choose the one that after reversing state init, works?

	var n396, n169 int
	for i := 1; i < 397; i += 1 {
		if i == 396 {
			n396 = mt.mt_gen()
		} else if i == 169 {
			n169 = mt.mt_gen()
		} else {
			mt.mt_gen()
		}
	}
	n169, n396 = reverse_all_temper(n169), reverse_all_temper(n396)
	// correct 169=1541376461, 396=1161613179
	fmt.Printf("reversed temper of n169: %d, n396: %d\n", n169, n396)

	rhs_396 := xorbytes(n396, n169)
	fmt.Printf("RHS of RNG_396: %d\n", rhs_396)

	find_k_one := func(rhs int) []int {
		rhs_without_a_even := []int{(rhs << 1) & bit_32, ((rhs << 1) & bit_32) | 1}
		rhs_without_a_odd := []int{(xorbytes(rhs, mt_a) << 1) & bit_32, ((xorbytes(rhs, mt_a) << 1) & bit_32) | 1}

		var possible_k_one []int
		for _, v := range slices.Concat(rhs_without_a_even, rhs_without_a_odd) {
			fmt.Printf("analyzing RHS after reversing multiply by A: %d\n", v)
			t := v & 0x7FFFFFFF
			t2 := (1 << (mt_w - 1)) | t
			possible_k_one = append(possible_k_one, t, t2)
		}
		fmt.Printf("calculated possible k + 1 values: %v\n", possible_k_one)
		return possible_k_one
	}

	var state1 []int
	for _, v := range find_k_one(rhs_396) {
		fmt.Printf("computing k + 1 values given x_397 = %d\n", v)
		rhs_1 := xorbytes(n, v)
		state1 = append(state1, find_k_one(rhs_1)...)
	}
	fmt.Printf("calculated possible k + 1 values for k=0: %v (%d)\n", state1, len(state1))

	// Use each option for state1 to calculate possible options for state0 == seed
	// NOTE: mt_f itself requires 31 bits to represent - multiplying by that and adding 1 can extend beyond 32 bits
	// Unf, those extra bits are lost with truncation
	// So how do we go from state1 => seed?
	var att_seed int
	var seed_found bool
	for _, v := range state1 {
	// reverse_temper := func(n, len, shift, mask int, dir bool) int {
		possible_seed := reverse_temper((v - 1) >> 18, mt_w, mt_w - 2, bit_32, true)
		if v == 1301868182 {
			fmt.Printf("calculated possible seed: %v from state_1 = %d, %d\n", possible_seed, v, (v - 1) / mt_f)
		}
		m := MTrng{}
		m.mt_init(possible_seed);
		if m.mt_gen() == rng_out {
			att_seed = possible_seed
			seed_found = true
			break
		}
	}
	if !seed_found {
		panic(fmt.Sprintf("seed not found for RNG output: %d with actual seed: %d\n", rng_out, 5489))
	} else {
		fmt.Printf("found MT19937 seed %d (actual: %d) from RNG output %d\n", att_seed, seed, rng_out)
	}
}
</pre>
</details>

It turns out, the point of the exercise in cracking the seed was to demonstrate how easily guessed the RNG seed is when sample RNG outputs are known, since it's easy to check guesses and it's also easy to make guesses if the seed is based on something like a timestamp. I definitely over-thought this one.