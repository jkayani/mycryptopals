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
