## Notes

- Base16 is 4 bits per char. Base64 is 6 bits per char

- XOR is basically "at least one AND not both"
- XOR can count Hamming distance (i.e, where are bits different)
- XOR can be inverted via XORing against the same argument

- Repeating-key ciphers decompose to single-key ciphers once key size is known

- ECB is basic AES, applied block by block. Repeated blocks of plaintext will appear as repeated blocks of ciphertext. This is readily apparent in base16 encoded strings.
- AES blocks are 4 words long, each word is 4 bytes - 16 bytes, 32 hex chars. Block is internally a col-major matrix where each word (of 4 consecutive bytes) forms a column. 
- AES "round key" is 1 block in size. Each row of the round key is paired with each _col_ of each AES block
- CBC is "chained" between blocks, XORing each plaintext block with previous ciphertext block or IV. Unlike ECB mode, this means encryption cannot be done on all blocks in parallel: must be done serially to feed output into next input