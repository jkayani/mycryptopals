package main

import (
	"context"
	"fmt"
	"slices"
	"math"
	"math/rand"
	"strings"
	"regexp"
	"time"

	"jkayani.local/mycrypto/utils"
	"jkayani.local/mycrypto/aes"
	"jkayani.local/mycrypto/rng"
	"jkayani.local/mycrypto/sha1"
	"jkayani.local/mycrypto/md4"
)

type Hash interface {
	Hash ([]byte) string
}

func main() {
	fmt.Println("nothing")
}

func rankplaintext(bytes []byte) (score float64) {
	vowels := []byte{65, 69, 73, 79, 85, 97, 101, 105, 111, 117}
	var v, space, alphanum, weird float64
	for _, b := range(bytes) {
		if b == 0x20 {
			space += 1
		}

		if (b >= 48 && b <= 57) || (b >= 65 && b <= 90) || (b >= 97 && b <= 122) {
			alphanum += 1
			for _, v := range(vowels) {
				if b == v {
					v += 1
					break
				}
			}
		} else if (b >= 91 && b <= 96) || b >= 123 || (b < 32 && b != 10) {
			weird += 1
		}
	}

	// Obviously not English plaintext
	if weird > 0 {
		return -1
	}

	// Rank result bytes as follows:
	// 70% for alphanum chars
	// 20% for spaces
	// 10% for vowels
	return (alphanum * float64(0.7)) + (space * float64(0.2)) + (v * float64(0.1))
}

// This works b/c (a XOR b) XOR b = a
// Bit is set whenever exactly 1 of the 2 bits is set
// => 1st operand = 1, 2nd operand = 0 => 1st bit is 1
// => 1st operand = 1, 2nd operand = 1 => 1st bit is 0
// => 1st operand = 0, 2nd operand = 1 => 1st bit is 1
// => 1st operand = 0, 2nd operand = 0 => 1st bit is 0
func xordecrypt(bytes []byte) () {
	type r struct {
		bytes []byte
		ascii string
		score float64
	}
	results := map[byte]r{}

	var i byte
	for i = 32; i < 123; i += 1 {
		ascii := ""
		rbytes := []byte{}
		for _, b := range(bytes) {
			xor := utils.Fixedxor([]byte{b}, []byte{i})
			rbytes = append(rbytes, xor[0])
			ascii += string(xor)
		}
		results[i] = r{rbytes, ascii, rankplaintext(rbytes)}
	}

	xorchar, maxscore := byte(0), float64(0)
	for k, result := range(results) {
		if result.score > maxscore {
			maxscore = result.score
			xorchar = k
		}
		// fmt.Printf("%d (%c), score: %f => %s\n", k, k, result.score, result.ascii)
	}

	fmt.Printf("best score: %f from %d (%c) => %s\n", maxscore, xorchar, xorchar, results[xorchar].ascii)
}

func findxoredstring() {
	type result struct {
		cipherbytes []byte
		plainbytes []byte
		xorv byte
		score float64
	}
	data := map[string]result{}

	s := utils.Read("1_4.txt")
	for s.Scan() {
		t := s.Text()
		data[t] = result{
			cipherbytes: utils.Hexdecode(t),
		}
	}

	for ciphertext, r := range(data) {
		bestscore := float64(0)
		bestxor := byte(0)
		bestbytes := []byte{}
		var i byte
		for i = 32; i < 123; i +=1 {
			plainbytes := []byte{}
			for _, b := range(r.cipherbytes) {
				plainbytes = append(plainbytes, utils.Fixedxor([]byte{b}, []byte{i})[0])
			}
			rank := rankplaintext(plainbytes)
			if rank > bestscore {
				// fmt.Printf("%s appears to be closer to plaintext with score %f, generated from %s XOR %d\n", frombytes_ascii(plainbytes), rank, ciphertext, i)
				bestscore = rank
				bestxor = i
				bestbytes = plainbytes
			}
		}

		if bestscore > 0 {
			d := data[ciphertext]
			d.plainbytes = bestbytes
			d.score = bestscore
			d.xorv = bestxor
			data[ciphertext] = d
			// fmt.Printf("%s is most likely candidate with score %f, generated from %s XOR %d\n", string(bestbytes), bestscore, ciphertext, bestxor)
		}
	}

	finalchoice := ""
	for ciphertext, r := range(data) {
		if r.score > data[finalchoice].score {
			finalchoice = ciphertext
		}
	}

	final := data[finalchoice]
	fmt.Printf("ciphertext was %s which decodes to %s when XORed with %d (score %f)\n", finalchoice, string(final.plainbytes), final.xorv, final.score)
}

func repeatingxor(bytes []byte, key string) string {
	keybytes := []byte(key)
	k := 0
	result := []byte{}
	for _, b := range bytes {
		result = append(result, utils.Fixedxor([]byte{b}, []byte{keybytes[k]})[0])
		k = (k + 1) % len(keybytes)
	}

	hex := utils.Base16encode_bytes(result)
	// fmt.Printf("encrypt %v with %s => %s\n", bytes, key, hex)
	return hex
}

// Take K samples (K must be even) and average the pair-wise hamming dist
// Vary the sample length from lb to ub bytes
func evalkeysize(bytes []byte, lb, ub, samplesize int) int {
	lowestdist := float64(len(bytes))
	keysize := 0

	if ub * samplesize > len(bytes) {
		fmt.Printf("error: Not enough data to collect %d samples of size %d bytes\n", samplesize, ub)
		return -1
	}

	for i := lb; i < ub; i += 1 {
		samples := [][]byte{}
		for j := 0; j < samplesize; j += 1 {
			samples = append(samples, bytes[i * j:i * (j + 1)])
		}

		var avg float64
		for j := 0; j < samplesize - 1; j += 2 {
			avg += float64(utils.Hamming(samples[j], samples[j + 1])) / float64(i)
		}
		avg /= float64(samplesize / 2)

		if avg < lowestdist {
			// fmt.Printf("key size of %d yields lower hamming %f than key size of %d\n", i, avg, keysize)
			keysize = i
			lowestdist = avg
		} else {
			// fmt.Printf("try key size %d => %f\n", i, avg)
		}
	}
	// fmt.Printf("keysize that yields lowest hamming: %d\n", keysize)
	return keysize
}

func findkeysize(bytes []byte, lb, ub, uppersamplesize int) int {
	freqs := map[int]int{}

	// As sample size increases, the keysize with best pair-wise hamming dist is converged on?
	// So test all key sizes at increasing sample sizes and take the overall best performing keysize
	for i := 2; i < uppersamplesize; i += 2 {
		f := evalkeysize(bytes, lb, ub, i)
		if f == -1 {
			fmt.Printf("invalid attempt, stopping at sample size %d\n", i - 2)
			break
		}
		freqs[f] += 1
	}
	best, freq := 0, 0
	for k, v := range freqs {
		if v > freq {
			best = k
			freq = v
		}
	}
	fmt.Printf("keysize of %d occurs as best most often (%d times given %d rounds). All data: %v\n", best, freq, uppersamplesize / 2, freqs)
	return best
}

func decryptrepeatedxor(bytes []byte, keysize int) {

	// Split byte slices by index (up to keysize) into utils.Fixedxor byte slices
	// i.e, take each 1st byte into slice, each 2nd byte, etc
	chunks := make([][]byte, keysize)
	i := 0
	for _, b := range bytes {
		chunks[i] = append(chunks[i], b)
		i = (i + 1) % keysize 
	}

	keybytes := make([]byte, keysize)
	plainbytes := make([][]byte, keysize)
	for cnum, c := range chunks {
		bestscore := float64(0)
		var i byte
		for i = 32; i < 123; i += 1 {
			xoredbytes := []byte{}
			for _, b := range c {
				xoredbytes = append(xoredbytes, utils.Fixedxor([]byte{b}, []byte{i})[0])
			}
			r := rankplaintext(xoredbytes)
			// fmt.Printf("XORed %dth bytes from each %d block against %d => ?, rank %f\n", cnum, keysize, i, r)
			if r > bestscore {
				keybytes[cnum] = i
				bestscore = r
				plainbytes[cnum] = xoredbytes
			}
		}
		// fmt.Printf("Best XOR key for %dth bytes: %d (%s) => %s, rank %f\n", cnum, keybytes[cnum], string([]byte{keybytes[cnum]}), plainbytes[cnum], bestscore)
	}

	// Interleave the now decrypted plainbytes back together
	i = 0
	var msg string
	for true {
		added := false
		for _, p := range plainbytes {
			if i < len(p) {
				msg += string(p[i])
				added = true
			}
		}
		if !added {
			break
		}
		i += 1
	}

	fmt.Printf("key: [%s] => decrypted message: \n%s\n", string(keybytes), msg)
}

func findaesecb(hex string) bool {
	wordlen_hexchar := 32
	table := map[string]int{}
	if len(hex) % wordlen_hexchar != 0 {
		fmt.Printf("%s cannot be aes.AES 128 since length isn't multiple of 16 bytes\n", hex)
		return false
	}
	for i := 0; i < len(hex); i += wordlen_hexchar {
		s := hex[i : i + wordlen_hexchar]
		if table[s] > 0 {
			fmt.Printf("substring %s repeats at index %d, current count: %d\n", s, i, table[s])
			return true
		}
		table[s] += 1
	}
	return false
}

func detectaes_ecb(file string) string {
	s := utils.Read(file)
	for s.Scan() {
		t := s.Text()
		if findaesecb(t) {
			fmt.Printf("aes.AES-128 in ECB mode line: %s\n", t)
			return t
		}
	}
	return ""
}

func randomencrypt(data []byte) ([]byte, string) {
	minbyte := byte(32)
	maxbyte := byte(126)

	plainbytes := []byte(data)
	hlen := int(math.Round((rand.Float64() * 5) + 5))
	flen := int(math.Round((rand.Float64() * 5) + 5))
	header := make([]byte, hlen)
	footer := make([]byte, flen)
	for k, _ := range header {
		header[k] = utils.Randombyte(minbyte, maxbyte)
	}
	for k, _ := range footer {
		footer[k] = utils.Randombyte(minbyte, maxbyte)
	}
	plainbytes = append(header, plainbytes...)
	plainbytes = append(plainbytes, footer...)
	padlen := int(math.Ceil(float64(len(plainbytes)) / float64(aes.Keylen_words * aes.Wordlen_bytes))) * 16
	plainbytes = utils.Pkcs7pad_bytes(plainbytes, padlen)
	fmt.Printf("random header of size %d: %v\nrandom footer of size: %d: %v\nall data (padded to %d len): %v\n\n", hlen, header, flen, footer, padlen, plainbytes)

	a := aes.AES{}
	var cipherbytes []byte
	mode := int(math.Round(rand.Float64()))
	modestr := ""
	if mode == 0 {
		cipherbytes = a.Encrypt_ECB(plainbytes, aes.RandomAESkey())
		modestr = "ECB"
	} else {
		cipherbytes = a.Encrypt_CBC(plainbytes, aes.RandomAESkey(), aes.RandomAESkey())
		modestr = "CBC"
	}
	fmt.Printf("random mode: %d (%s), data => %v\n", mode, modestr, cipherbytes)

	return cipherbytes, modestr
}

func detectaes_cbc_ecb(data []byte) bool {
	// This is meant to be a problem about selecting the right _plaintext_
	// such that it can be fed to a mystery algorithm
	// and based on output, determine if ECB or not
	// Thanks to https://crypto.stackexchange.com/questions/53274/cryptopals-challenge-2-11-distinguish-ecb-and-cbc-encryption?rq=1 for clarification
	c, expectedmode := randomencrypt([]byte(data))
	chex := utils.Base16encode_bytes(c)

	// EBC is easily distinguished via repeated blocks. If not obviously ECB, assume CBC
	foundmode := "CBC"
	if findaesecb(chex) {
		foundmode = "ECB"
	}
	fmt.Printf("\n%s\nappears to be aes.AES in %s mode\nactual result: %s\n", chex, foundmode, expectedmode)

	return foundmode == expectedmode
}

func decryptecb_oneblock(mystery []byte) []byte {
	a := aes.AES{}

	// This value is unknown to us
	key := aes.RandomAESkey()

	// Determine cipher block size by counting bytes of ciphertext
	// We "don't know" what the padding length is
	blocksize_bytes := len(utils.Pkcs7pad_bytes(a.Encrypt_ECB([]byte{0}, key), aes.Blocksize_bytes))
	fmt.Printf("determined that 'mystery algorithm' has block size %d bytes\n", blocksize_bytes)

	knownword := "josh"
	fullknownblock := knownword + knownword + knownword + knownword

	// Verify cipher is operating in ECB mode
	// We "don't know" which mode the cipher is using
	if findaesecb(utils.Base16encode_bytes(a.Encrypt_ECB([]byte(fullknownblock + fullknownblock), key))) {
		fmt.Printf("verified that 'mystery algorithm' uses ECB mode\n")
	}

	foundblocks := []aes.Word{aes.Word{}}
	blockidx := 0

	// If the mystery data's length isn't block-multiple, pretend there's an extra block
	mysteryblockcount := len(mystery) / blocksize_bytes
	if len(mystery) % blocksize_bytes > 0 {
		mysteryblockcount = len(mystery) / blocksize_bytes + 1
	}

	// How is this a useful attack?
	// It relies on forcing the mystery plaintext to bleed into the known block
	// When would that happen in a practical scenario?
	// After all, the mystery plaintext must be known to do this...
	for i := 0; i < (blocksize_bytes * mysteryblockcount); i += blocksize_bytes {

		// If the last block isn't full, just take what's there
		var mysteryblock []byte
		if len(mystery) - i < blocksize_bytes {
			mysteryblock = mystery[i:]
		} else {
			mysteryblock = mystery[i : i + blocksize_bytes]
		}

		for k := 0; k < len(mysteryblock); k += 1 {
			end := len(fullknownblock)
			if len(foundblocks[blockidx]) > 0 {
				end -= len(foundblocks[blockidx]) + 1
			} else {
				end -= 1
			}
			knownblock := []byte(fullknownblock[0 : end])
			payload := utils.Pkcs7pad_bytes(append(knownblock, mysteryblock...), 2 * blocksize_bytes)
			// fmt.Printf("%d bytes of block %d found so far, using knownblock: %s for payload of size %d\n", len(foundblocks[blockidx]), blockidx, knownblock, len(payload))
			result := a.Encrypt_ECB(payload, key)[0 : blocksize_bytes]

			for j := 0; j < 255; j += 1 {
				guesspayload := append(knownblock, foundblocks[blockidx]...)
				guesspayload = append(guesspayload, byte(j))
				guesspayload = utils.Pkcs7pad_bytes(guesspayload, 2 * blocksize_bytes)
				// fmt.Printf("guessing byte %d (%c) as last byte in payload: %s\n", j, j, string(guesspayload))

				r := a.Encrypt_ECB(guesspayload, key)[0 : blocksize_bytes]
				if slices.Equal(r, result) {
					// fmt.Printf("%dth byte of block %d is: %d (%c)\n", k, blockidx, j, byte(j))
					foundblocks[blockidx] = append(foundblocks[blockidx], byte(j))
					break
				}
			}
		}

		// Last block may not be a full block, and that's OK
		// Every other block should have blocksize_bytes at this point
		if len(foundblocks[blockidx]) < blocksize_bytes && blockidx < mysteryblockcount - 1 {
			panic(fmt.Sprintf("16 bytes of mystery data should have been found, got %d => %v\n", len(foundblocks[blockidx]), foundblocks[blockidx]))
		}
		blockidx += 1
		foundblocks = append(foundblocks, aes.Word{})
	}

	final := aes.Wordstobytes(foundblocks)
	fmt.Printf("mystery value: %s\n", final)
	return final
}

// Make a function that returns an encrypted profile string given an email address: email=e&role=user
// Determine how to mutate a ciphertext such after decryption (simulated login), it yields: email=e&role=admin
func ecb_cutpaste() string {
	profile_for := func(email string) string {
		return fmt.Sprintf("email=%s&role=user", strings.ReplaceAll(strings.ReplaceAll(email, "&", ""), "=", ""))
	}
	parse_profile := func(profile string) map[string]string {
		return utils.Parse_kv([]byte(profile), 0x3d, 0x26, 0x00)
	}
	key := aes.RandomAESkey()
	a := aes.AES{}
	oracle := func(email string) []byte {
		in := []byte(profile_for(email))
		plen := len(in) / aes.Blocksize_bytes
		if len(in) % aes.Blocksize_bytes != 0 {
			plen += 1
		}
		in = utils.Pkcs7pad_bytes(in, plen * aes.Blocksize_bytes)
		fmt.Printf("padded input to len: %d\n", len(in))
		return a.Encrypt_ECB(in, key)
	}
	login := func(profilenc []byte) string {
		d := (a.Decrypt_ECB(profilenc, key))
		
		// Is this intended? This part is crucial to the attack
		// It removes any padding bytes from decrypted data
		// Should this be part of the Decrypt_ECB func?
		last := d[len(d) - 1]
		plen := 0
		for i := len(d) - 1; i >= len(d) - int(last); i -= 1 {
			if d[i] != last {
				plen = 0
				break
			}
			plen += 1
		}
		fmt.Printf("detected %d padding bytes of %d\n", plen, last)
		return string(d[0:len(d) - plen])
	}

	// Outline of attack:
	// Use a long enough email adddress to force resulting ciphertext to have the role value in a separate block
	// The first 2 blocks of resulting ciphertext will be useful (email=??&role=)
	// Then, construct a long email address to force the word admin to be in the 2nd block
	// Pad the block containing "admin" with appropriate padding char that will be stripped off during decryption
	// Combine the first 2 blocks from before with the 2nd block of above to yield target ciphertext
	// This will decrypt to an encoded profile with role=admin

	// Assumptions:
	// email does not have to be valid (no @domain.com)
	// Padding bytes are removed after decryption and before a profile's role value

	emaillen := len("email=") 
	rolelen := len("&role=")
	padlen := (aes.Blocksize_bytes - emaillen) + (aes.Blocksize_bytes - rolelen)
	roleownblock := ""
	for i := 0; i < padlen; i += 1 {
		roleownblock += "a"
	}
	// fmt.Printf("pad to len %d to force role to be in separate block => %s\n", padlen, roleownblock)
	roleownblockcipher := oracle(roleownblock)
	// fmt.Printf("%v\n", roleownblockcipher)

	headerlen := aes.Blocksize_bytes - emaillen
	adminlen := len("admin")
	footerlen := aes.Blocksize_bytes - adminlen
	adminownblock := ""
	for i := 0; i < headerlen; i += 1 {
		adminownblock += "z"
	}
	adminownblock += "admin"
	for i := 0; i < footerlen; i += 1 {
		adminownblock += fmt.Sprintf("%c", aes.Blocksize_bytes - adminlen)
	}
	// fmt.Printf("pad to len %d to force admin to be in 2nd block => %s\n", headerlen + adminlen + footerlen, adminownblock)
	adminownblockcipher := oracle(adminownblock)
	// fmt.Printf("%v\n", adminownblockcipher)

	targetciphertext := append(roleownblockcipher[0 : aes.Blocksize_bytes * 2], adminownblockcipher[aes.Blocksize_bytes : aes.Blocksize_bytes * 2]...)
	// fmt.Printf("target cipher bytes:\n%v\n", targetciphertext)

	result := login(targetciphertext)
	fmt.Printf("login attempt: %s\n", result)
	return parse_profile(result)["role"]
}

// One byte at a time, determine contents of mystery data
// Oracle will prefix plaintext with fixed len random data each time
// ASSUMPTION: oracle uses the same fixed len random data for all calls, unclear from problem statement

// before: <known-string>m<ysery-text>
// 				 [..............][..........]
// guess every value for m comparing 1st block of each ciphertext until same ciphertext is returned

// now: <rand><known-string>m<ystery-text>
// 			[..............][..........]
func decryptecb_random(mystery []byte) []byte {
	// Server starts here

	randomprefixlen := rand.Intn(16)
	randomprefix := []byte{}
	fmt.Printf("generating %d random bytes of data\n", randomprefixlen)
	for i := 0; i < randomprefixlen; i += 1 {
		randomprefix = append(randomprefix, utils.Randombyte(0, 255))
	}
	key := aes.RandomAESkey()
	a := aes.AES{}

	// Just like before, it's not clear to me how this attack is useful
	// In order to "bleed" blocks of mystery data beyond the first one into the "known block", 
	// block-level access to mystery data (via oracle) is required
	// blockidx is the param to specify which block of mystery data to use for oracle output
	// -1 means use all the mystery data
	oracle := func(input []byte, blockidx int) []byte {
		var in []byte
		if blockidx == -1 {
			in = append(append(randomprefix, input...), mystery...)
		} else {
			s := aes.Blocksize_bytes * blockidx
			in = append(append(randomprefix, input...), mystery[s:s + aes.Blocksize_bytes]...)
		}
		return a.Encrypt_ECB(utils.Pkcs7pad_bytes(in, utils.Blocklen(in) * aes.Blocksize_bytes), key)
	}

	// Attack starts here

	// Since the known block + full len of mystery data is known to attacker (ASSUMPTION), 
	// determine how many padding slots there would be of ECB encrypted known block + mystery
	knownstring := "josh"
	knownblock := []byte(knownstring + knownstring + knownstring + knownstring)
	attackerinput_blocks := utils.Blocklen(mystery) + 1
	paddingcnt_attacker := ((attackerinput_blocks) * 16) - (len(mystery) + aes.Blocksize_bytes)
	// fmt.Printf("calculated mystery data and known block to be %d blocks and have %d bytes of padding\n", attackerinput_blocks, paddingcnt_attacker)

	// Core idea is to determine how much random data the oracle is prefixing
	// Do this by watching the length of ciphertext returned for ever-increasing input lengths
	// There will be 3 distinct cases depending on how much random data there is:

	res_attacker := oracle(knownblock, -1)
	res_blocklen := utils.Blocklen(res_attacker)
	target_blocklen := res_blocklen + 1
	random_len_attacker := 0

	// case 3:
	// random bytes > padding slots => add 0 bytes, and will overflow into additional blocks
	// => add 1 byte until overflow into another additional block (X)
	// => random len = padding slots + ((block_diff - 1)) * 16) + (16 - X)
	if res_blocklen > attackerinput_blocks {
		// fmt.Printf("oracle output has %d blocks of ciphertext, mystery data with known block has %d: random data > padding slots\n", res_blocklen, attackerinput_blocks)
		random_len_attacker = paddingcnt_attacker + (res_blocklen - attackerinput_blocks - 1) * aes.Blocksize_bytes
		paddingcnt_attacker = aes.Blocksize_bytes
	}

	input_attacker := append(knownblock, byte(0))
	extrabytes_attacker := 1
	for {
		out := oracle(input_attacker, -1)
		// fmt.Printf("adding %d extra bytes\n", extrabytes_attacker)

		// case 1
		// random bytes < padding slots => add 1 byte until overflow into additional block (X)
		// => random len = padding slots - X
		// case 2	
		// random bytes == padding slots => will overflow immediately after adding 1 byte (X)
		// => random len = padding slots
		if utils.Blocklen(out) == target_blocklen {
			// fmt.Printf("after adding %d bytes, cipherlen changed from %d to %d blocks\n", extrabytes_attacker, res_blocklen, target_blocklen)
			random_len_attacker += paddingcnt_attacker - (extrabytes_attacker - 1)
			break
		}
		input_attacker = append(input_attacker, byte(0))
		extrabytes_attacker += 1
	}
	fmt.Printf("attacker has determined that oracle server is prepending %d bytes of random data\n", random_len_attacker)

	// Now that length of random data is known, mitigate by adding null bytes
	// to fill up to N blocks exactly
	// That will let us be sure the following block contains the <known-block> combined with mystery data for the attack
	padding_attacker := []byte{}
	for i := 0; i < aes.Blocksize_bytes - (random_len_attacker % aes.Blocksize_bytes); i += 1 {
		padding_attacker = append(padding_attacker, byte(0))
	}

	// Conceptually, the target_block is the one _after_ the last one with random data and its padding
	// That would be the random len in blocks, + 1. But then subtract 1 since blocks are 0-indexed
	target_blockidx := random_len_attacker / aes.Blocksize_bytes

	// If the random data bleeds beyond a "full" block, use the one after the block with partially random data
	if len(padding_attacker) > 0 {
		target_blockidx += 1
	}
	// fmt.Printf("calls to oracle prefixed with %d bytes of padding; target block is %d\n", len(padding_attacker), target_blockidx)

	// Repeat attack as last time
	foundblocks := []aes.Word{[]byte{}}
	blockidx := 0
	mysterylen_blocks := utils.Blocklen(mystery)
	for i := 0; i < (aes.Blocksize_bytes * mysterylen_blocks); i += aes.Blocksize_bytes {

		// If the last block isn't full, just take what's there
		var mysteryblock []byte
		if len(mystery) - i < aes.Blocksize_bytes {
			mysteryblock = mystery[i:]
		} else {
			mysteryblock = mystery[i : i + aes.Blocksize_bytes]
		}

		for k := 0; k < len(mysteryblock); k += 1 {
			end := len(knownblock)
			if len(foundblocks[blockidx]) > 0 {
				end -= len(foundblocks[blockidx]) + 1
			} else {
				end -= 1
			}
			input := append(padding_attacker, knownblock[0 : end]...)
			s := aes.Blocksize_bytes * target_blockidx
			result := oracle(input, blockidx)[s:s + aes.Blocksize_bytes]

			for j := 0; j < 255; j += 1 {
				guesspayload := append(append(input, foundblocks[blockidx]...), byte(j))
				// fmt.Printf("guessing byte %d (%c) as last byte in payload: %s\n", j, j, string(guesspayload))

				r := oracle(guesspayload, blockidx)[s:s + aes.Blocksize_bytes]
				if slices.Equal(r, result) {
					// fmt.Printf("%dth byte of block %d of %d is: %d (%c)\n", k, blockidx, mysterylen_blocks, j, byte(j))
					foundblocks[blockidx] = append(foundblocks[blockidx], byte(j))
					break
				}
			}
		}

		// Last block may not be a full block, and that's OK
		// Every other block should have aes.Blocksize_bytes at this point
		if len(foundblocks[blockidx]) < aes.Blocksize_bytes && blockidx < mysterylen_blocks - 1 {
			panic(fmt.Sprintf("16 bytes of mystery data should have been found, got %d => %v\n", len(foundblocks[blockidx]), foundblocks[blockidx]))
		}
		blockidx += 1
		foundblocks = append(foundblocks, aes.Word{})
	}

	final := aes.Wordstobytes(foundblocks)
	fmt.Printf("mystery value: %s\n", final)
	return final
}

func cbc_bitflip() bool {
	a := aes.AES{}
	key, iv := aes.RandomAESkey(), aes.RandomAESkey()
	to_prepend := "comment1=cooking%20MCs;userdata="
	to_append := ";comment2=%20like%20a%20pound%20of%20bacon"
	oracle := func(input string) []byte {
		escaped_bytes := []byte{}
		for k, _ := range input {
			b := input[k]
			a := []byte{b}
			if b == 0x3b || b == 0x3d {
				a = []byte{0x22, b, 0x22}
			}
			escaped_bytes = append(escaped_bytes, a...)
		}
		plainbytes := append([]byte(to_prepend), escaped_bytes...)
		plainbytes = append(plainbytes, []byte(to_append)...)
		// fmt.Printf("blocklen: %s: %d => %d\n", string(plainbytes), len(plainbytes), utils.Blocklen(plainbytes))
		plainbytes_padded := utils.Pkcs7pad_bytes(plainbytes, utils.Blocklen(plainbytes) * aes.Blocksize_bytes)

		return a.Encrypt_CBC(plainbytes_padded, key, iv)
	}
	check := func(cipherbytes []byte) bool {
		res := a.Decrypt_CBC(cipherbytes, key, iv)
		fmt.Printf("cbc_bitflip check decrypted result: %s\n%v\n", res, res)
		pairs := utils.Parse_kv(res, 0x3d, 0x3b, 0x22)
		fmt.Printf("cbc_bitflip: parsed k/v pairs: \n%v\n", pairs)

		p, ok := pairs["admin"]
		return ok && p == "true"
	}

	// Attack starts here

	// Z = EBC_Encrypt(X xor Y)
	// X = ;comment2=%20like%20a%20pound%20of%20bacon
	// A = ;admin=true
	// Y = ciphertext block prior to CBC_Encrypt(to_prepend + input + X)

	// ECB_Decrypt(Z) XOR Y = X (by defn of CBC_Decrypt)
	// => ECB_Decrypt(Z) = X xor Y
	// (X xor Y) xor A => bits to flip => Y'
	// ECB_Decrypt(Z) xor Y' = (X xor Y) xor Y' = A

	att_goal := ";admin=true;"
	// Since to_prepend is 32 bytes exactly (2 blocks), attacker doesn't need to supply an input at all
	att_cipherbytes := oracle("") 
	// fmt.Printf("cbc_bitflip: attacker is given ciphertext:\n%v\n", att_cipherbytes)
	preceding_blocks := 1
	att_second_cipherblock := att_cipherbytes[aes.Blocksize_bytes * preceding_blocks:aes.Blocksize_bytes * (preceding_blocks + 1)]
	att_third_cipherblock := att_cipherbytes[aes.Blocksize_bytes * (preceding_blocks + 1):]

	// => ECB_Decrypt(Z) = X xor Y
	// XOR the last block of plaintext with the preceding ciphertext block
	// This yields the input to the EBC_Encrypt func, aka what ECB_Decrypt would give
	att_lhs := utils.Fixedxor([]byte(to_append)[0:aes.Blocksize_bytes], att_second_cipherblock)
	// fmt.Printf("cbc_bitflip: ECB decrypt result of %v\n%v\n\n", att_second_cipherblock, att_lhs)

	// (X xor Y) xor A => bits to flip => Y'
	// XOR the above with the desired string to give the bytes needed to replace the preceding cipherbytes block
	// XOR will set the bits whenever a bit needs to be flipped to yield our desired string, exactly what we want
	att_modified_second_cipherblock := utils.Fixedxor(att_lhs, utils.Pkcs7pad_bytes([]byte(att_goal), aes.Blocksize_bytes))
	// fmt.Printf("cbc_bitflip: modified second block: %v\n\n", att_modified_second_cipherblock)

	// Put the modified cipherblock together with the untouched third cipherblock
	// ECB_Decrypt will be called on the third cipherblock
	// It will be XORed with our modified preceding cipherblock and yield the desired string
	return check(append(att_modified_second_cipherblock, att_third_cipherblock...))
}

func cbc_padding_oracle(plaintext string) (string, error) {
	key, iv := aes.RandomAESkey(), aes.RandomAESkey()
	first := func() (cipherbytes, used_iv []byte) {
		a := aes.AES{}
		pad_len := utils.Blocklen([]byte(plaintext)) * aes.Blocksize_bytes
		padded := utils.Pkcs7pad_bytes([]byte(plaintext),  pad_len)

		// Add extra padding as explained in https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7
		// This resolves ambiguity about how to interpret last byte
		if len(plaintext) % aes.Blocksize_bytes == 0 {
			padded = utils.Pkcs7pad_bytes([]byte(plaintext),  len(plaintext) + aes.Blocksize_bytes)
		}

		return a.Encrypt_CBC(padded, key, iv), iv
	}
	second := func(a *aes.AES, cipherbytes []byte) bool {
		_, e := utils.Validatepkcs7padding(a.Decrypt_CBC(cipherbytes, key, iv))
		return e == nil
	}

	// Attack starts here
	// See README for overall explanation
	att_cipherbytes, att_iv := first()
	att_blocklen := utils.Blocklen(att_cipherbytes)
	att_full_plainbytes := []byte{}

	type att_block_result struct {
		blockidx int
		plainbytes []byte
	}
	att_decrypted_block_chan := make(chan att_block_result)
	att_all_blocks := map[int][]byte{}
	for att_target_block := att_blocklen - 1; att_target_block >= 0; att_target_block -= 1 {
		go func(att_target_block int) {
			a := aes.AES{}
			var original_firstblock []byte
			if att_target_block == 0 {
				original_firstblock = att_iv
			} else {
				original_firstblock = utils.Nth_block(att_cipherbytes, att_target_block - 1)
			}
			secondblock := utils.Nth_block(att_cipherbytes, att_target_block)
			// fmt.Printf("target block: %d, cipherblocks: %v\n%v\n", att_target_block, original_firstblock, secondblock)

			att_plainbytes := []byte{}
			for i := aes.Blocksize_bytes - 1; i >= 0; i -= 1 {
				att_goal_padding := aes.Blocksize_bytes - i
				// fmt.Printf("att goal is to make oracle pass with padding: %d\n", att_goal_padding)
				firstblock := slices.Clone(original_firstblock)
				// fmt.Printf("firstblock before modify: %v\n", firstblock)

				// Use CBC bitflip to ensure the known plainbytes decrypt to the goal_padding (P')
				for k, j := len(att_plainbytes) - 1, i + 1; j < aes.Blocksize_bytes; k, j = k - 1, j + 1{
					firstblock[j] = utils.Xorbytes(byte(att_goal_padding), utils.Xorbytes(att_plainbytes[k], original_firstblock[j]))
				}
				// fmt.Printf("firstblock after modify: %v\n", firstblock)

				// Set C' by substituting each possible byte value
				// Do this until the oracle passes (ECB_Decrypt(T) xor C' = P')
				options := []byte{}
				for k := 0; k < 256; k += 1 {
					firstblock[i] = byte(k)
					if second(&a, append(firstblock, secondblock...)) {
						options = append(options, firstblock[i])
					}
				}

				// Attack is to find a C' for attacker goal padding P' such that oracle passes => ECB_Decrypt(T) xor C' = P'
				// The oracle will pass if T (our target byte) decrypts to P' (starts at 0x01) OR T decrypts to the "actual" padding (P)
				// On every iteration after P'=1, the other padding bytes are guaranteed to equal P'
				// Therefore on those iterations, oracle will ONLY pass in the situation we desire (T decrypts to P')
				// BUT on iteration 1, since we cannot set any bytes after the last byte to affect things,
				// the oracle can pass in either case:

				// T decrypts to P' (desired, since we know the value of P')
				// T decrypts to P (not desired since we don't actually know P), which is guaranteed to happen when C'=C

				// Thus if multiple mutations pass the oracle, choose the one where C' != C
				// Note that for length-15 plaintexts where P=1, oracle will only pass for P'=1 when C'=C
				// In that case, only one mutation will pass the oracle so everything will work BAU
				if len(options) > 0 {
					opt := options[0]
					if len(options) > 1 {
						for _, o := range options {
							if o != original_firstblock[i] {
								opt = o
								break
							}
						}
					}
					// fmt.Printf("using byte value %d (compared to %d) causes oracle to pass\n", opt, original_firstblock[i])
					att_result := utils.Xorbytes(utils.Xorbytes(byte(att_goal_padding), opt), original_firstblock[i])
					// fmt.Printf("target_block: %d plaintext at pos %d: %d (%c)\n", att_target_block, i, att_result, att_result)
					att_plainbytes = append(att_plainbytes, att_result)
				} else {
					panic("attack failed since no byte could be used to pass the oracle\n")
				}
			}

			// Each block is decrypted backwards
			slices.Reverse(att_plainbytes)
			att_decrypted_block_chan <- att_block_result{att_target_block, att_plainbytes}
		}(att_target_block)
	}

	for i := att_blocklen - 1; i >= 0; i -= 1 {
		r := <- att_decrypted_block_chan
		att_all_blocks[r.blockidx] = r.plainbytes
	}
	for i := 0; i < len(att_all_blocks); i += 1 {
		att_full_plainbytes = append(att_full_plainbytes, att_all_blocks[i]...)
	}

	att_string, err := utils.Validatepkcs7padding(att_full_plainbytes)
	fmt.Printf("att plaintext: %v\n%s\n%s\n", att_full_plainbytes, att_string, utils.Base64decode(string(att_string)))
	return string(att_string), err
}

func ctr_fixed_nonce(shortest bool) ([]byte, []byte) {
	// plaintexts := []string {
	// 	"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
	// 	"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
	// 	"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
	// 	"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
	// 	"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
	// 	"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
	// 	"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
	// 	"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
	// 	"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
	// 	"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
	// 	"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
	// 	"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
	// 	"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
	// 	"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
	// 	"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
	// 	"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
	// 	"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
	// 	"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
	// 	"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
	// 	"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
	// 	"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
	// 	"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
	// 	"U2hlIHJvZGUgdG8gaGFycmllcnM/",
	// 	"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
	// 	"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
	// 	"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
	// 	"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
	// 	"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
	// 	"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
	// 	"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
	// 	"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
	// 	"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
	// 	"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
	// 	"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
	// 	"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
	// 	"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
	// 	"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
	// 	"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
	// 	"VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
	// 	"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
	// }
	sc := utils.Read("3_20.txt")
	plaintexts := []string{}
	for sc.Scan() {
		plaintexts = append(plaintexts, sc.Text())
	}

	key := aes.RandomAESkey()
	a := aes.AES{}
	ctr_encrypt := func(input string) (cipherbytes []byte, keystream []byte, e error) {
		return a.Process_CTR(utils.Base64decode(input), key, utils.Int_to_bytes(uint64(0)), 0)
	}

	ciphertexts := make([][]byte, len(plaintexts))
	keystreams := make([][]byte, len(plaintexts))
	var longest_len, longest_idx int
	var shortest_len int = len(plaintexts[0])
	for k, v := range plaintexts {
		ciphertexts[k], keystreams[k], _ = ctr_encrypt(v)
		if len(ciphertexts[k]) > longest_len {
			longest_len = len(ciphertexts[k])
			longest_idx = k
		}
		if len(ciphertexts[k]) < shortest_len {
			shortest_len = len(ciphertexts[k])
		}
	}

	// Idea here is that the resulting plaintext needs to be valid English
	// letters, punctuation, spaces
	accept_regexp := regexp.MustCompile(`[a-zA-Z0-9]|[:;"/',!?.-]|\s`)

	// These rules have to be tuned for each plaintext
	reject_regexps := []*regexp.Regexp{

		// No sequence of punctuation chars
		regexp.MustCompile(`[:;"'/]{2}`),

		// No more than 1 space
		// regexp.MustCompile(`[\s]{2,}`),

		// H shouldn't be followed by a char that isn't these (vowels, punctuation, some consonants)
		regexp.MustCompile(`(H|h|x)[^aeiouwmbytr\s:;',!?.-]`),
		
		// These chars shouldn't be followed by certain chars (mostly consonant combinations)
		// regexp.MustCompile(`((n)[h])|t[gfdzv]|d[v]|b[j]|x[r]|r[f]|z[zg]|q[w]|i[uq]`),

		// Capital letters should be preceded by spaces since they mark a new sentence
		// except for first letter of each plaintext, but that's handled in the loop
		// regexp.MustCompile(`[^\s][A-Z]`),

		// Apostrophe must be followed by a lowercase char
		// regexp.MustCompile(`['][^a-z]`),
	}
	att_keystream := []byte{}
	att_plaintexts := make([][]byte, len(ciphertexts))

	ranker := func (plaintext []byte) float64 {
		letters := 0
		re := regexp.MustCompile(`[a-z]|\s`)
		for k, _ := range plaintext {
			if re.Find(plaintext[k: k + 1]) != nil {
				letters += 1
			}
		}
		return float64(letters) / float64(len(plaintext))
	}

	type ranking struct {
		plaintext []byte
		rank float64
	}

	// This will not correctly decrypt all the ciphertexts but it will get most of each
	// This works well in the beginning since all ciphertexts have a 0th char, 1th char, etc
	// Each kth char in a ciphertext was XORed with the same keystream byte, so there are more chances
	// to "check" a guess of a keystream byte and see if it passes/fails the above rules
	// As the end of the ciphertexts near, there are fewer chances to check, and thus bad guesses cannot be weeded out
	ending_pos := shortest_len
	if ! shortest {
		ending_pos = longest_len
	}
	for goal_pos := 0; goal_pos < ending_pos; goal_pos += 1 {
		keystream_ranks := map[byte]ranking{}
		for kval := 0; kval <= 255; kval += 1 {
			keystream_byte := byte(kval)
			plaintext_to_rank := []byte{}
			discard := false
			// fmt.Printf("testing keystream byte %v for pos %d\n", keystream_byte, goal_pos)
			for k, ciphertext := range ciphertexts {
				if goal_pos < len(ciphertext) {
					next_plainbyte := utils.Xorbytes(keystream_byte, ciphertext[goal_pos])
					s := []byte{next_plainbyte}
					plaintext_to_rank = append(plaintext_to_rank, next_plainbyte)
					if accept_regexp.Find(s) == nil	{
						// fmt.Printf("DISCARD keystream byte %v for pos %d due to failing test: %s (%d)\n", keystream_byte, goal_pos, append(slices.Clone(att_plaintexts[k]), s...), next_plainbyte)
						discard = true
						break
					}
					if ! discard && goal_pos > 0 {
						s = append(slices.Clone(att_plaintexts[k]), s...)
						for _, re := range reject_regexps {
							if o := re.Find(s); o != nil {
								// fmt.Printf("DISCARD keystream byte %v for pos %d due to passing test %v: %s (%d)\n", keystream_byte, goal_pos, re, s, next_plainbyte)
								discard = true
								break
							}
						}
					}
				}
				if discard {
					// fmt.Printf("keystream byte %v does not work at all\n", keystream_byte)
					break
				}
			}
			if ! discard {
				keystream_ranks[keystream_byte] = ranking{plaintext_to_rank, ranker(plaintext_to_rank)}
			}
		}
		if len(keystream_ranks) == 0 {
			for k, v := range att_plaintexts {
				fmt.Printf("%d %s\n", k, v)
			}
			panic(fmt.Sprintf("no keystream byte found for pos %d\n", goal_pos))
		} else {
			var best_keystream_byte byte
			for k, v := range keystream_ranks {
				t := keystream_ranks[best_keystream_byte]
				if len(t.plaintext) == 0 || v.rank > t.rank {
					best_keystream_byte = k
				}
			}
			// fmt.Printf("best keystream byte for pos %d is: %v => %s\n", goal_pos, best_keystream_byte, keystream_ranks[best_keystream_byte].plaintext)
			// fmt.Printf("all potential keystream bytes for pos %d\n", goal_pos)
			// for k, v := range keystream_ranks {
			// 	fmt.Printf("%v => %s (%v)\n", k, v.plaintext, v.rank)
			// }
			for k, ciphertext := range ciphertexts {
				if goal_pos < len(ciphertext) {
					att_plaintexts[k] = append(att_plaintexts[k], utils.Xorbytes(best_keystream_byte, ciphertext[goal_pos]))
				}
			}
			att_keystream = append(att_keystream, best_keystream_byte)
		}
	}
	for k, v := range att_plaintexts {
		fmt.Printf("%d %s\n", k, v)
	}
	return att_keystream[0:ending_pos], keystreams[longest_idx][0:ending_pos]
}

// Credit to https://book-of-gehn.github.io/articles/2018/12/23/Mersenne-Twister-PRNG.html
// for explaining this attack is just about showing easy it is to "guess" the seed when it's time based
// especially if you have a rough time window of when the seed was likely generated
func mt_seed_crack() (int, int) {
	t := time.Now()
	lower, upper := 40, 1000
	rnd, _ := time.ParseDuration(fmt.Sprintf("%ds", rand.Intn(upper - lower + 1) + lower))
	seed := int(t.Add(rnd).Unix())
	m := rng.MTrng{}
	m.Init(seed)

	att_rng_out := m.Gen()
	att_seed_lower, att_seed_upper := -1000, 1000
	att_t := time.Now()
	fmt.Printf("attacker RNG: %d, generated from seed: %d\n", att_rng_out, seed)

	var att_seed int
	for i := att_seed_lower; i <= att_seed_upper; i += 1 {
		m2 := rng.MTrng{}
		offset, _ := time.ParseDuration(fmt.Sprintf("%ds", i))
		m2.Init(int(att_t.Add(offset).Unix()))
		if m2.Gen() == att_rng_out {
			att_seed = int(att_t.Unix()) + i
			break
		}
	}
	if att_seed != 0 {
		fmt.Printf("attacker determined MT19937 seed was: %d, actual answer: %d\n", att_seed, seed)
	} else {
		panic(fmt.Sprintf("no seed found!"))
	}

	return seed, att_seed
}

func mt_clone() (rng.MTrng, rng.MTrng) {
	reverse_temper := func(n, len, shift, mask int, dir bool) int {
		nbits := utils.Bits(n, len)
		a := utils.Bits(0, len)
		maskbits := utils.Bits(mask, len)

		if dir {
			// B bits [0, shift) are 0 AND corresponding bit of the mask
			// First bit of A is corresponding bit of B xor first bit of n
			for i := 0; i < shift; i += 1 {
				a[i] = utils.Xorbytes(0, nbits[i])
			}
			// b[i] = a[i - shift] which in turn yields a[i]
			for i := shift; i < len; i += 1 {
				a[i] = utils.Xorbytes(a[i - shift] & maskbits[i], nbits[i])
			}
		} else {
			// B bits [len - 1, shift) are 0 AND mask
			// Last bit of A is corresponding bit of B xor last bit of n 
			for i := len - 1; i > len - 1 - shift; i -= 1 {
				a[i] = utils.Xorbytes(0, nbits[i])
			}
			// b[i] = a[i - shift] which in turn yields a[i]
			for i := len - 1 - shift; i >= 0; i = i - 1 {
				a[i] = utils.Xorbytes(a[i + shift] & maskbits[i], nbits[i])
			}
		}
		r := utils.Bitval(a)
		return r
	}
	reverse_all_temper := func(n int) int {
		n = reverse_temper(n, rng.Mt_w, rng.Mt_l, utils.Bit_32, true)
		n = reverse_temper(n, rng.Mt_w, rng.Mt_t, rng.Mt_c, false)
		n = reverse_temper(n, rng.Mt_w, rng.Mt_s, rng.Mt_b, false)
		return reverse_temper(n, rng.Mt_w, rng.Mt_u, rng.Mt_d, true)
	}

	m := rng.MTrng{}
	m.Init(1)
	att_state := make([]int, 624)
	for i := 0; i < 624; i += 1 {
		att_state[i] = reverse_all_temper(m.Gen())
	}

	// After 624 RNG outputs, state array is completely full of those untempered RNG outputs
	// They are used for all future generation
	// So w/o knowing seed, the RNG can be cloned and predicted
	att_m := rng.MTrng{}
	att_m.State = att_state
	att_m.Idx = 0
	return m, att_m
}

func mt_stream_break() (int, int) {
	known := "joshjoshjoshka"

	encrypt := func() ([]byte, int) {
		plain := []byte(known)
		for i := 0; i < rand.Intn(10); i += 1 {
			rndCh := byte(rand.Intn(122 - 97) + 97)
			plain = append([]byte{rndCh}, plain...)
		}

		seed := rand.Intn(0xFFFF)
		m := rng.MTrng{}
		fmt.Printf("using seed: %d and plaintext: %s\n", seed, plain)
		return m.Process_MT_crypt(seed, plain), seed
	}

	cipherbytes, true_seed := encrypt()
	// fmt.Printf("known plain: %v (%s); encrypt: %v (%d)\n", known, known, cipherbytes, len(cipherbytes))
	att_rngs := []int{}
	bytes_recovered := 0
	att_rng := 0

	// Each RNG output is broken into 4 bytes for use in keystream
	// Ciphertext length isn't always multiple of 4
	// "Parts" of an RNG output may be used as keystream for last few cipherbytes
	// Skip the ending cipherbytes that can only recover partial RNG output
	start := 0
	for i := len(cipherbytes); i >= 0; i -= 1 {
		if i % 4 == 0 {
			start = i
			break
		}
	}
	
	// Since some ending cipherbytes may be skippped, corresponding ending cipherbytes in the known
	// plain bytes also have to be skipped so that keystream is correctly recovered
	for i, k := start - 1, len(known) - 1 - (len(cipherbytes) - start); k >= 0; i, k = i - 1, k - 1 {
		if bytes_recovered == 4 {
			att_rngs = append(att_rngs, att_rng)
			att_rng = 0
			bytes_recovered = 0
		}
		recovered_keybyte := int(utils.Xorbytes(cipherbytes[i], known[k]))
		// fmt.Printf("recovered keybyte: %d\n", recovered_keybyte)
		att_rng |=  recovered_keybyte << (8 * bytes_recovered)
		bytes_recovered += 1
	}
	if bytes_recovered == 4 {
		att_rngs = append(att_rngs, att_rng)
	}

	// Determine the ordinal of the last RNG recovered
	// Last RNG recovered is the earliest one used for encrypting
	// This determines how many "test" RNG outputs should be generated for each guess of the seed to compare against recovered RNG output
	earliest_rng_idx := (len(cipherbytes) - len(known))
	if earliest_rng_idx % 4 != 0 {
		earliest_rng_idx /= 4
		earliest_rng_idx += 1
	} else {
		earliest_rng_idx /= 4
	}
	fmt.Printf("recovered RNG outputs: %v, earliest idx: %d\n", att_rngs, earliest_rng_idx)

	// Guess seed values, and generate enough RNG outputs for each guess
	// to determine if seed can eventually generate the earliest recovered RNG output
	var att_seed int
	max_seed := 0xFFFF

	rCh := make(chan int)
	doneCh := make(chan int)
	c, cancel := context.WithCancel(context.TODO())
	go func(ptr *int) {
		for i := range rCh {
				*ptr = i
				cancel()
				doneCh <- 0
				break
		}
	}(&att_seed)

	for i := 0; i < max_seed; i += 1 {
		go func(i int) {
			select {
			case <- c.Done():
				return
			default:
			}
			m := rng.MTrng{}
			m.Init(i)
			var r int
			for j := 0; j <= earliest_rng_idx; j += 1 {
				r = m.Gen()
			}
			if r == att_rngs[len(att_rngs) - 1] {
				rCh <- i
			}
			return
		}(i)
	}
	<- doneCh

	// for i := 0; i < max_seed; i += 1 {
	// 	m := rng.MTrng{}
	// 	m.Init(i)
	// 	var r int
	// 	for j := 0; j <= earliest_rng_idx; j += 1 {
	// 		r = m.Gen()
	// 	}
	// 	if r == att_rngs[len(att_rngs) - 1] {
	// 		att_seed = i
	// 		break
	// 	}
	// }

	fmt.Printf("attacker recovered seed: %d\n", att_seed)
	return true_seed, att_seed
}

func break_ctr_seek_edit() ([]byte, []byte) {
	ecb_cipherbytes := utils.Decodebase64_file("./1_7.txt")
	a := aes.AES{}
	plainbytes := a.Decrypt_ECB(ecb_cipherbytes, []byte("YELLOW SUBMARINE"))

	key, nonce := aes.RandomAESkey(), aes.RandomAESkey()[0:8]
	cipherbytes, _, err := a.Process_CTR(plainbytes, key, nonce, 0)
	if err != nil {
		fmt.Printf("error with CTR encrypt on attack setup: %s\n", err)
	}

	attacker_oracle := func(offset int, new_plainbytes []byte) ([]byte, error) {
		return a.CTR_seek_edit(slices.Clone(cipherbytes), key, nonce, offset, new_plainbytes)
	}

	// All 0s would work, but this is to show the attack works despite choice of substituted plaintext
	att_newplainbytes := make([]byte, len(cipherbytes))
	for k, _ := range att_newplainbytes {
		att_newplainbytes[k] = utils.Randombyte(0, 255)
	}
	att_modified_cipherbytes, err := attacker_oracle(0, att_newplainbytes)
	if err != nil {
		fmt.Printf("error with CTR seek edit in attack: %s\n", err)
	}
	att_recovered_keystream := utils.Fixedxor(att_modified_cipherbytes, att_newplainbytes)
	att_recovered_plainbytes := utils.Fixedxor(cipherbytes, att_recovered_keystream)
	fmt.Printf("recovered plainbytes: %s\n", att_recovered_plainbytes)
	return plainbytes, att_recovered_plainbytes
}

func ctr_bitflip() bool {
	a := aes.AES{}
	key, nonce := aes.RandomAESkey(), aes.RandomAESkey()[0:8]
	to_prepend := "comment1=cooking%20MCs;userdata="
	to_append := ";comment2=%20like%20a%20pound%20of%20bacon"
	oracle := func(input string) []byte {
		escaped_bytes := []byte{}
		for k, _ := range input {
			b := input[k]
			a := []byte{b}
			if b == 0x3b || b == 0x3d {
				a = []byte{0x22, b, 0x22}
			}
			escaped_bytes = append(escaped_bytes, a...)
		}
		plainbytes := append([]byte(to_prepend), escaped_bytes...)
		plainbytes = append(plainbytes, []byte(to_append)...)
		fmt.Printf("encrypting: %s\n", plainbytes)

		r, _, err := a.Process_CTR(plainbytes, key, nonce, 0)
		if err != nil {
			fmt.Printf("err CTR encrypting: %s\n", err)
		}
		return r
	}
	check := func(cipherbytes []byte) bool {
		res, _, _ := a.Process_CTR(cipherbytes, key, nonce, 0)
		fmt.Printf("ctr_bitflip check decrypted result: %s\n%v\n", res, res)
		pairs := utils.Parse_kv(res, 0x3d, 0x3b, 0x22)
		fmt.Printf("ctr_bitflip: parsed k/v pairs: \n%v\n", pairs)

		p, ok := pairs["admin"]
		return ok && p == "true"
	}

	// Attack starts here
	// Just like before: if a plaintext and ciphertext pair are known, keystream is known
	att_input := "+admin+true"
	att_plaintext := append(slices.Clone([]byte(to_prepend)), []byte(att_input)...)
	att_plaintext = append(att_plaintext, to_append...)

	att_ciphertext := oracle(att_input)
	att_keystream := utils.Fixedxor(att_ciphertext, att_plaintext)

	att_ciphertext[len(to_prepend)] = utils.Xorbytes(0x3b, att_keystream[len(to_prepend)])
	idx := len(to_prepend) + len("+admin")
	att_ciphertext[idx] = utils.Xorbytes(0x3d, att_keystream[idx])

	return check(att_ciphertext)
}

func cbc_key_as_iv() ([]byte, []byte) {
	a := aes.AES{}
	key := aes.RandomAESkey()
	iv := key
	to_prepend := "comment1=cooking%20MCs;userdata="
	to_append := ";comment2=%20like%20a%20pound%20of%20bacon"
	oracle := func(input []byte) []byte {
		escaped_bytes := []byte{}
		for k, _ := range input {
			b := input[k]
			a := []byte{b}
			if b == 0x3b || b == 0x3d {
				a = []byte{0x22, b, 0x22}
			}
			escaped_bytes = append(escaped_bytes, a...)
		}
		plainbytes := append([]byte(to_prepend), escaped_bytes...)
		plainbytes = append(plainbytes, []byte(to_append)...)
		plainbytes_padded := utils.Pkcs7pad_bytes(plainbytes, utils.Blocklen(plainbytes) * aes.Blocksize_bytes)

		return a.Encrypt_CBC(plainbytes_padded, key, iv)
	}
	check := func(cipherbytes []byte) ([]byte, error) {
		res := a.Decrypt_CBC(cipherbytes, key, iv)
		fmt.Printf("cbc_bitflip check decrypted result: %s\n%v\n", res, res)
		if _, e := utils.Check_ascii(res); e != nil {
			return res, e
		}
		return res, nil
	}

	// Attack starts here
	// Normal CBC enc: C_n = enc((P_n) xor C_(n-1))
	// Normal CBC dec: P_n = dec(C_n) xor C_(n-1)
	// Attack: C_1, C_2, C_3 => C_1, 0, C_1
	// P_3 = dec(C_1) xor 0 => dec(C_1) (not P_1)
	// P_2 = garbage
	// P_1 = dec(C_1) xor IV
	// P_1 xor dec(C_1) = IV => P_1 xor P_3 = IV = key

	p := []byte("joshisthebestest")
	att_plainbytes := append(slices.Clone(p), p...)
	att_plainbytes = append(att_plainbytes, p...)
	att_cipher := oracle(att_plainbytes)

	first := utils.Nth_block(att_cipher, 0)
	att_new_cipher := append(slices.Clone(first), make([]byte, aes.Blocksize_bytes)...)
	att_new_cipher = append(att_new_cipher, first...)

	att_plain, err := check(att_new_cipher)
	fmt.Printf("output: %v (%d)\nerr: %v\n", att_plain, len(att_plain), err)
	att_key := utils.Fixedxor(utils.Nth_block(att_plain, 0), utils.Nth_block(att_plain, 2))
	return key, att_key
}

func keyed_mac(h Hash, key, plainbytes []byte) string {
	return h.Hash(append(key, plainbytes...))
}
func forged_mac_oracle (h Hash, key, plainbytes []byte, mac string) (admin bool, accepted bool) {
	res := h.Hash(append(key, plainbytes...))
	// fmt.Printf("oracle calculated hash: %v\n", res)
	if res == mac {
		fmt.Printf("oracle accepted plainbytes: %v (%s)\n", plainbytes, plainbytes)
		parsed := utils.Parse_kv(plainbytes, 0x3d, 0x3b, 0x7e)
		if admin, ok := parsed["admin"]; ok {
			return admin == "true", true
		}
		return false, true
	}
	return false, false
}

func forged_sha1_mac() (admin, accepted bool) {
	key := aes.RandomAESkey()
	oracle := func(plainbytes []byte, mac string) (bool, bool) {
		return forged_mac_oracle(&sha1.SHA1{}, key, plainbytes, mac)
	}
	legit := func(plainbytes []byte) (string) {
		return keyed_mac(&sha1.SHA1{}, slices.Clone(key), plainbytes)
	}

	// Attack starts here
	// SHA-1 works by processing each block, and carries forward intermediate results 
	// into subsequent blocks (a, b, c, d, e words)
	// Ending result is the concat of the a...e words

	// Calculate SHA-1 of a given plaintext, and save the resulting a...e words
	// Generate arbitrary data D that will be appended to existing plaintext
	// This means the padding has to be adjusted to account for bit-length of D
	// Use D and the new padding to construct a new final block
	// "Resume" the SHA-1 calculation given the saved a...e words and the new final block

	msg := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	hash := legit(msg)
	att_to_add := []byte(";admin=true")

	max_key_len := 32
	for att_keylen := 0; att_keylen < max_key_len; att_keylen += 1 {

		// -1 term for the byte that stores the 1-bit appended to end of plaintext
		// -8 term for the last 8 bytes that store length
		original_len := att_keylen + len(msg)
		original_padding := sha1.Blocklen_n(original_len) * sha1.Blocksize_bytes - original_len - 1 - 8
		att_len_bytes := sha1.Blocklen_n(original_len) * sha1.Blocksize_bytes + len(att_to_add)
		att_padding_len := sha1.Blocklen_n(att_len_bytes) * sha1.Blocksize_bytes - att_len_bytes - 1 - 8
		// fmt.Printf("attacker is guessing keylen: %d, original msg len: %d, original padding: %d => new msg len: %d, new padding len: %d\n", att_keylen, original_len, original_padding, att_len_bytes, att_padding_len)

		// To get past the oracle, original padded input must be reconstructed by attacker
		// so that the hash ends up being same as the attacker calculated one
		att_orignal_input := append(
			append(
				append(
					slices.Clone(msg),
					0x80,
				),
				make([]byte, original_padding)...
			),
			utils.Int_to_bytes(uint64(original_len * 8))...
		)

		// To resume SHA-1, last block must be pre-padded so that the last 8 bytes can be set
		att_pre_padded := append(
			append(
				append(
					slices.Clone(att_to_add), 
					0x80,
				),
				make([]byte, att_padding_len)...
			),
			utils.Int_to_bytes(uint64(att_len_bytes * 8))...
		)
		// fmt.Printf("attacker synthesized original SHA-1 input: %v (%d)\n", att_orignal_input, len(att_orignal_input))
		if (len(att_orignal_input) + att_keylen) % sha1.Blocksize_bytes != 0 {
			panic(fmt.Sprintf("Failed to synthesize original SHA-1 input correctly, got %d length value", len(att_orignal_input)))
		}
		if len(att_pre_padded) != sha1.Blocksize_bytes {
			panic(fmt.Sprintf("Failed to forge pre-padded additional SHA-1 block correctly, got %d length value", len(att_pre_padded)))
		}

		hash_bytes := utils.Hexdecode(hash)
		att_h := make([]int, 5)
		for k, i := 0, 0; k < len(hash_bytes); k, i = k + 4, i + 1 {
			word := hash_bytes[k : k + 4]
			num := utils.Bytes_to_int(word)

			// Avoid arithmetic shift with uint64
			res := int(uint64(num) >> 32)

			att_h[i] = res
		}

		s := sha1.SHA1{}
		att_new_hash := s.ResumeHash(att_pre_padded, att_h, false)
		att_oracle_input := append(slices.Clone(att_orignal_input), att_to_add...)
		admin, accepted := oracle(att_oracle_input, att_new_hash)
		if accepted && admin {
			return admin, accepted
		}
	}
	return false, false
}
func forged_md4_mac() (admin, accepted bool) {
	key := aes.RandomAESkey()
	oracle := func(plainbytes []byte, mac string) (bool, bool) {
		return forged_mac_oracle(&md4.MD4{}, key, plainbytes, mac)
	}
	legit := func(plainbytes []byte) (string) {
		return keyed_mac(&md4.MD4{}, slices.Clone(key), plainbytes)
	}

	// Attack starts here
	// Exact same thing as forging SHA-1 hash
	// Remember that both the 8-byte "length in bits" sequence,
	// and the individual state "words" derived from known MD4 hash have to be reversed (unlike SHA-1)!
	msg := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	hash := legit(msg)
	att_to_add := []byte(";admin=true")

	max_key_len := 32
	for att_keylen := 0; att_keylen < max_key_len; att_keylen += 1 {

		// -1 term for the byte that stores the 1-bit appended to end of plaintext
		// -8 term for the last 8 bytes that store length
		original_len := att_keylen + len(msg)
		original_padding := md4.Blocklen_n(original_len) * md4.Blocksize_bytes - original_len - 1 - 8
		att_len_bytes := md4.Blocklen_n(original_len) * md4.Blocksize_bytes + len(att_to_add)
		att_padding_len := md4.Blocklen_n(att_len_bytes) * md4.Blocksize_bytes - att_len_bytes - 1 - 8
		// fmt.Printf("attacker is guessing keylen: %d, original msg len: %d, original padding: %d => new msg len: %d, new padding len: %d\n", att_keylen, original_len, original_padding, att_len_bytes, att_padding_len)

		// To get past the oracle, original padded input must be reconstructed by attacker
		// so that the hash ends up being same as the attacker calculated one
		original_len_bytes := utils.Int_to_bytes(uint64(original_len * 8))
		slices.Reverse(original_len_bytes)
		att_orignal_input := append(
			append(
				append(
					slices.Clone(msg),
					0x80,
				),
				make([]byte, original_padding)...
			),
			original_len_bytes...
		)

		// To resume MD4, last block must be pre-padded so that the last 8 bytes can be set
		new_len_bytes := utils.Int_to_bytes(uint64(att_len_bytes * 8))
		slices.Reverse(new_len_bytes)
		att_pre_padded := append(
			append(
				append(
					slices.Clone(att_to_add), 
					0x80,
				),
				make([]byte, att_padding_len)...
			),
			new_len_bytes...
		)
		// fmt.Printf("attacker synthesized original MD4 input: %v (%d)\n", att_orignal_input, len(att_orignal_input))
		if (len(att_orignal_input) + att_keylen) % md4.Blocksize_bytes != 0 {
			panic(fmt.Sprintf("Failed to synthesize original MD4 input correctly, got %d length value", len(att_orignal_input)))
		}
		if len(att_pre_padded) != md4.Blocksize_bytes {
			panic(fmt.Sprintf("Failed to forge pre-padded additional MD4 block correctly, got %d length value", len(att_pre_padded)))
		}

		hash_bytes := utils.Hexdecode(hash)
		att_h := make([]int, 4)
		for k, i := 0, 0; k < len(hash_bytes); k, i = k + 4, i + 1 {
			word := hash_bytes[k : k + 4]
			slices.Reverse(word)
			num := utils.Bytes_to_int(word)

			// Avoid arithmetic shift with uint64
			res := int(uint64(num) >> 32)

			att_h[i] = res
		}
		// fmt.Printf("Resuming MD4 hash from: %v and %v\n", att_pre_padded, att_h)

		s := md4.MD4{}
		att_new_hash := s.ResumeHash(att_pre_padded, att_h, false)
		att_oracle_input := append(slices.Clone(att_orignal_input), att_to_add...)
		admin, accepted := oracle(att_oracle_input, att_new_hash)
		if accepted && admin {
			return admin, accepted
		}
	}
	return false, false
}