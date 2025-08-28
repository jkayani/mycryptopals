package aes

import (
	t "testing"
	"slices"
	"os"
	"fmt"
	"os/exec"
	"jkayani.local/mycrypto/utils"
)

func setupaes() (*AES) {
	return &AES{
		key: utils.Hexdecode("00000000000000000000000000000000"),
		cipherbytes: Bytestowords([]byte("048C159D26AE37BF")),
	}
}

func nestedSliceEquals(s1, s2 []Word) bool {
	return slices.EqualFunc(s1, s2, func (w1, w2 Word) bool {
		return slices.Equal(w1, w2)
	})
}

func writehex(hex, outfile string) {
	data := utils.Hexdecode(hex)
	f, _ := os.Create(outfile)
	f.Write(data)
	f.Close()
}

func writeascii(data, outfile string) {
	f, _ := os.Create(outfile)
	f.Write([]byte(data))
	f.Close()
}

func readbytes(file string) []byte {
	data, _ := os.ReadFile(file)
	return data
}

var (
	openssl = "openssl enc %s %s -nosalt -nopad -K \"%s\""
	openssl_iv = "openssl enc %s %s -nosalt -nopad -K \"%s\" -iv \"%s\""
	hexdump = "hexdump -v -e '/1 \"%%02X\"'"
	tr = "tr '[:upper:]' '[:lower:]'"
)

func TestRotate(tt *t.T) {
	inputs := [][]byte{
		[]byte{1, 2, 3, 4},
		[]byte{1, 2, 3, 4},
		[]byte{1, 2, 3, 4},
		[]byte{1, 2, 3, 4},
	}
	shifts := []int {
		1,
		2,
		3,
		4,
	}
	leftexpected := [][]byte{
		[]byte{2, 3, 4, 1},
		[]byte{3, 4, 1, 2},
		[]byte{4, 1, 2, 3},
		[]byte{1, 2, 3, 4},
	}

	for i, input := range inputs {
		if out := rotateleft(input, shifts[i]); !slices.Equal(out, leftexpected[i]) {
			tt.Fatalf("got %v leftexpected %v for %v shift left by %d", out, leftexpected[i], input, shifts[i])
		}
	}

	rightexpected := [][]byte{
		[]byte{4, 1, 2, 3},
		[]byte{3, 4, 1, 2},
		[]byte{2, 3, 4, 1},
		[]byte{1, 2, 3, 4},
	}

	for i, input := range inputs {
		if out := rotateright(input, shifts[i]); !slices.Equal(out, rightexpected[i]) {
			tt.Fatalf("got %v rightexpected %v for %v shift right by %d", out, rightexpected[i], input, shifts[i])
		}
	}
}

func TestSBoxSub(tt *t.T) {
	inputs := []byte{
		0x9a,
		0xff,
	}
	expected := []byte{
		0xb8,
		0x16,
	}

	for i, input := range inputs {
		if out := sub(input, sbox); out != expected[i] {
			tt.Fatalf("got %d expected %d for forward sbox sub of %d", out, expected[i], input)
		}
	}
}

func TestMultiply(tt *t.T) {

	// https://en.wikipedia.org/wiki/Finite_field_arithmetic#Rijndael's_(AES)_finite_field
	if out := multiply(0x53, 0xca); out != 1 {
		tt.Fatalf("expected 1 for product of 0x53 and 0xca, got %v\n", out)
	}

	// https://en.wikipedia.org/wiki/Rijndael_MixColumns#Test_vectors_for_MixColumn()
	inputsforward := Word{0xdb, 0x13, 0x53, 0x45}
	inputsreverse := Word{0x8e, 0x4d, 0xa1, 0xbc}

	if out := matrixmul(inputsforward, mix); !slices.Equal(out, inputsreverse) {
		tt.Fatalf("expected %v for forward mixing of input vector %v, got %v\n", inputsreverse, inputsforward, out)
	}
	if out := matrixmul(inputsreverse, reversemix); !slices.Equal(out, inputsforward) {
		tt.Fatalf("expected %v for reverse mixing of input vector %v, got %v\n", inputsforward, inputsreverse, out)
	}
}

func TestAESRoundKey(tt *t.T) {
	a := setupaes()

	// https://github.com/fanosta/aeskeyschedule?tab=utils.Readme-ov-file#example-usage
	expectedroundkeys := [][]byte {
		utils.Hexdecode("00000000000000000000000000000000"),
		utils.Hexdecode("62636363626363636263636362636363"),
		utils.Hexdecode("9b9898c9f9fbfbaa9b9898c9f9fbfbaa"),
		utils.Hexdecode("90973450696ccffaf2f457330b0fac99"),
		utils.Hexdecode("ee06da7b876a1581759e42b27e91ee2b"),
		utils.Hexdecode("7f2e2b88f8443e098dda7cbbf34b9290"),
		utils.Hexdecode("ec614b851425758c99ff09376ab49ba7"),
		utils.Hexdecode("217517873550620bacaf6b3cc61bf09b"),
		utils.Hexdecode("0ef903333ba9613897060a04511dfa9f"),
		utils.Hexdecode("b1d4d8e28a7db9da1d7bb3de4c664941"),
		utils.Hexdecode("b4ef5bcb3e92e21123e951cf6f8f188e"),
	}
	a.makeroundkeys(false)
	if out := Wordstobytes(a.roundkeys[1]); !slices.Equal(out, expectedroundkeys[1]) {
		tt.Fatalf("expectedroundkeys %v, got %v for makeroundkey of 0s\n", expectedroundkeys[1], out)
	}
}

func TestAESAddRoundKey(tt *t.T) {
	a := setupaes()
	a.makeroundkeys(false)

	// expectedaddroundkey := []word{}
	old := a.cipherbytes[0]
	a.addroundkey(0)

	// XOR with 0 unchanges data
	if out := a.cipherbytes[0]; !slices.Equal(out, old) {
		tt.Fatalf("expectedshiftrows to yield block %v, got %v for add round key for round 0, key: %v\n", old, out, a.key)
	}

	// TODO add more tests
}

func TestAESShiftRows(tt *t.T) {
	a := setupaes()

	a.shiftrows(0, false)
	expectedshiftrows := transpose([]Word{
		[]byte("0123"), []byte("5674"), []byte("AB89"), []byte("FCDE"),
	})
	if out := a.cipherbytes[0]; !slices.Equal(out, expectedshiftrows[0]) {
		tt.Fatalf("expectedshiftrows to yield block %v, got %v for shiftrows for round 0, key: %v\n", expectedshiftrows[0], out, a.key)
	}
}

func TestAESSubstitute(tt *t.T) {
	a := setupaes()

	a.substitute(0, false)
	l := len(a.cipherbytes) - 1
	ll := len(a.cipherbytes[0]) - 1

	if out := a.cipherbytes[0][0]; out != 4 {
		tt.Fatalf("forward substitute for 0x30 (48) should yield 4, got %v\n", out)
	}
	if out := a.cipherbytes[l][ll]; out != 90 {
		tt.Fatalf("forward substitute for 0x46 (70) should yield 90, got %v\n", out)
	}

	a.substitute(0, true)
	if out := a.cipherbytes[0][0]; out != 48 {
		tt.Fatalf("reverse substitute for 0x04 (4) should yield 0x30 (48), got %v\n", out)
	}
	if out := a.cipherbytes[l][ll]; out != 70 {
		tt.Fatalf("forward substitute for 0x5a (90) should yield 70, got %v\n", out)
	}

	// expectedshiftrows := []word{
	// 	[]byte("0123"), []byte("5674"), []byte("AB89"), []byte("FCDE"),
	// }
	// if out := a.cipherbytes[0]; !slices.Equal(out, expectedshiftrows[0]) {
	// 	tt.Fatalf("expectedshiftrows to yield block %v, got %v for shiftrows for round 0, key: %v\n", expectedshiftrows[0], out, a.key)
	// }
}

func TestAESMixColumns(tt *t.T) {

	// https://en.wikipedia.org/wiki/Rijndael_MixColumns#Test_vectors_for_MixColumn()
	// Use first 4 rows of test cases as cipherbytes
	inputsforward := []byte{
		0xdb, 0x13, 0x53, 0x45, 
		0xf2, 0x0a, 0x22, 0x5c, 
		0x01, 0x01, 0x01, 0x01,
		0xc6, 0xc6, 0xc6, 0xc6,
	}

	inputsreverse := utils.Hexdecode("8e4da1bc")
	inputsreverse = append(inputsreverse, utils.Hexdecode("9fdc589d")...)
	inputsreverse = append(inputsreverse, utils.Hexdecode("01010101")...)
	inputsreverse = append(inputsreverse, utils.Hexdecode("c6c6c6c6")...)

	a1 := AES{
		cipherbytes: Bytestowords(inputsforward),
	}
	a1.mixcols(0, false)
	if out :=	a1.cipherbytes; !nestedSliceEquals(out, Bytestowords(inputsreverse)) {
		tt.Fatalf("expected %v for forward mix columns of %v, got %v\n", Bytestowords(inputsreverse), inputsforward, out)
	}

	a2 := AES{
		cipherbytes: Bytestowords(inputsreverse),
	}
	a2.mixcols(0, true)
	if out :=	a2.cipherbytes; !nestedSliceEquals(out, Bytestowords(inputsforward)) {
		tt.Fatalf("expected %v for reverse mix columns of %v, got %v\n", inputsforward, inputsreverse, out)
	}
}

func TestTranspose(tt *t.T) {
	// a := setupaes()
	// a.makeroundkeys()
	input := Bytestowords([]byte("0123456789ABCDEF"))
	expected := []Word{
		[]byte("048C"), []byte("159D"), []byte("26AE"), []byte("37BF"),
	}
	if out := transpose(input); !nestedSliceEquals(out, expected) {
		tt.Fatalf("expected transpose to yield %v, got %v\n", expected, out)
	}

}

func TestAESDecrypt_ECB(tt *t.T) {
	type i struct {
		cipherhex, keyhex string
	}

	// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf
	cases := map[i]string {
		i{"6d251e6944b051e04eaa6fb4dbf78465", "10a58869d74be5a374cf867cfb473859"}: "00000000000000000000000000000000",
		i{"6e29201190152df4ee058139def610bb", "caea65cdbb75e9169ecd22ebe6e54675"}: "00000000000000000000000000000000",
		i{"3D1B7BDDF46221E1E462662B56910551", "10a58869d74be5a374cf867cfb473859"}: "My super secret",
		i{"BB34FDBC265AC636B5245D02DCE04941A22B2087556FC2DFDE029A547AA2A263BB34FDBC265AC636B5245D02DCE04941A22B2087556FC2DFDE029A547AA2A263BB34FDBC265AC636B5245D02DCE04941A22B2087556FC2DFDE029A547AA2A263", "10a58869d74be5a374cf867cfb473859"}: "10a58869d74be5a374cf867cfb47385910a58869d74be5a374cf867cfb47385910a58869d74be5a374cf867cfb47385",
	}

	decryptcli := "openssl enc -d -aes-128-ecb -nosalt -K \"%s\" -nopad < ciphertest | hexdump -v -e '/1 \"%%02X\"' | tr '[:upper:]' '[:lower:]'"
	a := AES{}
	for input, _ := range cases {
		out := a.Decrypt_ECB(utils.Hexdecode(input.cipherhex), utils.Hexdecode(input.keyhex))

		writehex(input.cipherhex, "ciphertest")
		cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf(decryptcli, input.keyhex))
		expected, err := cmd.Output()
		if err != nil {
			fmt.Printf("error: %s: %s\n", err, string(err.(*exec.ExitError).Stderr))
		}

		if utils.Base16encode_bytes(out) != string(expected) {
			// tt.Fatalf("expected %v (%d)for decryption of %s with key %s, got %v (%d)\n", utils.Hexdecode(string(expected)), len(expected), input.cipherhex, input.keyhex, utils.Hexdecode(out), len(out))
			tt.Fatalf("expected %v (%d)for decryption of %s with key %s, got %v (%d)\n", expected, len(expected), input.cipherhex, input.keyhex, out, len(out))
		}
	}

	more := []string{
		"My super secret\n",
		"4p?FKJ0TfyXD-gryBBa0YS]$}U)Mr@&GuG1zDCQ/RuE5N$qq0=XH@%*L2/G0c-dTDt-2NJx/yR9=V$Y)jVbQQ*cJ!/U}k5:jx.dkq{icEaL+.$_b&51nYP)w[xW34=56N4_d]5AWYt=rkD1ke$6k/08SFh+kt-cU",
	}
	key := "YELLOW SUBMARINE"
	encryptcli := "openssl enc -aes-128-ecb -nosalt -K \"%s\" -nopad < plaintest | hexdump -v -e '/1 \"%%02X\"' | tr '[:upper:]' '[:lower:]'"
	for _, input := range more {
		writeascii(input, "plaintest")
		fmt.Printf("key %s => %s\n", key, utils.Base16encode_bytes([]byte(key)))
		cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf(encryptcli, utils.Base16encode_bytes([]byte(key))))
		cipher, err := cmd.Output()
		if err != nil {
			fmt.Printf("error: %s: %s\n", err, string(err.(*exec.ExitError).Stderr))
		}

		out := a.Decrypt_ECB(utils.Hexdecode(string(cipher)), []byte(key))
		if utils.Base16encode_bytes(out) != utils.Base16encode_bytes([]byte(input)) {
			tt.Fatalf("failed to decrypt the encryption of %s - encrypted value %s (hex), decrypted value: %s\n", input, string(cipher), out)
		}
	}

	a.DecryptFile_ECB("../1_7.txt", "YELLOW SUBMARINE")

	// aes-128-ecb CLI invoke:
	// openssl enc -aes-128-ecb -nosalt -K "10a58869d74be5a374cf867cfb473859" -nopad < plain | hexdump -v -e '/1 "%02X"'
	// openssl enc -d -aes-128-ecb -nosalt -K "10a58869d74be5a374cf867cfb473859" -nopad < cipher | hexdump -v -e '/1 "%02X"'

	// openssl enc -aes-128-ecb -nosalt -K "59454c4c4f57205355424d4152494e45" -nopad < plaintest | hexdump -v -e '/1 "%02X"' | tr '[:upper:]' '[:lower:]'

}

func TestAESEncrypt_ECB(tt *t.T) {
	type i struct {
		cipherhex, keyhex string
	}

	// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf
	cases := map[i]string {
		i{"00000000000000000000000000000000", "10a58869d74be5a374cf867cfb473859"}: "6d251e6944b051e04eaa6fb4dbf78465",
		i{"00000000000000000000000000000000", "caea65cdbb75e9169ecd22ebe6e54675"}: "6e29201190152df4ee058139def610bb",
		i{utils.Base16encode_bytes([]byte("My super secret ")), "10a58869d74be5a374cf867cfb473859"}: "3D1B7BDDF46221E1E462662B56910551" ,
	}

	encryptcli := "openssl enc -aes-128-ecb -nosalt -K \"%s\" -nopad < plaintest | hexdump -v -e '/1 \"%%02X\"' | tr '[:upper:]' '[:lower:]'"
	a := AES{}
	for input, _ := range cases {
		out := a.Encrypt_ECB(utils.Hexdecode(input.cipherhex), utils.Hexdecode(input.keyhex))

		writehex(input.cipherhex, "plaintest")
		cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf(encryptcli, input.keyhex))
		expected, err := cmd.Output()
		if err != nil {
			fmt.Printf("error: %s: %s\n", err, string(err.(*exec.ExitError).Stderr))
		}
		// fmt.Printf("cmd: %s\nexpected: %s\nactual: %s", fmt.Sprintf(encryptcli, input.keyhex), expected, out)

		if utils.Base16encode_bytes(out) != string(expected) {
			// tt.Fatalf("expected %v (%d)for decryption of %s with key %s, got %v (%d)\n", utils.Hexdecode(string(expected)), len(expected), input.cipherhex, input.keyhex, utils.Hexdecode(out), len(out))
			tt.Fatalf("expected %v (%d) for encryption of %s with key %s, got %v (%d)\n", string(expected), len(expected), input.cipherhex, input.keyhex, out, len(out))
		}
	}
}

func TestAESDecrypt_CBC(tt *t.T) {
	a := AES{
	}
	key := "YELLOW SUBMARINE"
	iv := make([]byte, 16)

	out := a.DecryptFile_CBC("../2_10.txt", key, iv)

	input := "cat ../2_10.txt | base64 -d"
	cmdstring := fmt.Sprintf(input + " | " + openssl_iv + " | " + hexdump + " | " + tr, "-d", "-aes-128-cbc", utils.Base16encode_bytes([]byte(key)), utils.Base16encode_bytes(iv))
	fmt.Println(cmdstring)
	cmd := exec.Command("/bin/sh", "-c", cmdstring)
	expected, _ := cmd.Output()

	if string(expected) != utils.Base16encode_bytes(out) {
		tt.Fatalf("expected: %s, got %s for AES CBC decrypt of 2_10.txt\n", string(expected), out)
	}
}

func TestAESEncrypt_CBC(tt *t.T) {
	a := AES{
		// debug: true,
	}
	key := "YELLOW SUBMARINE"
	iv := make([]byte, 16)

	// extract plaintext to encrypt
	input := "cat ../2_10.txt | base64 -d"
	cmdstring := fmt.Sprintf(input + " | " + openssl_iv, "-d", "-aes-128-cbc", utils.Base16encode_bytes([]byte(key)), utils.Base16encode_bytes(iv))
	cmd := exec.Command("/bin/sh", "-c", cmdstring)
	plainbytes, _ := cmd.Output()

	out := a.Encrypt_CBC(plainbytes, []byte(key), iv)
	expected := utils.Decodebase64_file("../2_10.txt")

	if !slices.Equal(expected, out) {
		tt.Fatalf("expected %v for AES CBC encryption of %s, got %v\n", expected, string(plainbytes), out)
	}
}

func TestInt_To_Bytes(tt *t.T) {
	int_to_bytes(0x01000007000000ff)
}

func TestProcess_CTR(tt *t.T) {
	a := AES{}
	input := utils.Base64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	out, keystream, err := a.Process_CTR(input, []byte("YELLOW SUBMARINE"), int_to_bytes(0), 0)
	if len(input) != len(out) {
		tt.Fatalf("incorrect len of ciphertext returned for AES-CTR mode: expected %d, got: %d\n", len(input), len(out))
	}
	if len(keystream) != len(out) {
		tt.Fatalf("incorrect keystream returned for AES-CTR mode: expected: %d, got: %d\n", len(out), len(keystream))
	}
	if err != nil {
		tt.Fatalf("err on AES-CTR: %s\n", err)
	}
	if o := utils.Fixedxor(input, keystream); !slices.Equal(out, o) {
		tt.Fatalf("keystream does not decrypt ciphertext for AES-CTR mode: expected: %d, got: %d\n", out, o)
	}
	fmt.Printf("%v\n%s\n", out, out)
}

func Test_CTR_Seek_Edit(tt *t.T) {
	og_plain := []byte("hey_its_josh")

	a := AES{}
	key, nonce := RandomAESkey(), RandomAESkey()[0:8]
	og_cipher, _, err := a.Process_CTR(og_plain, key, nonce, 0)
	if err != nil {
		tt.Fatalf("AES-CTR: err: %s\n", err)
	}
	new_cipher, err := a.CTR_seek_edit(slices.Clone(og_cipher), key, nonce, len("hey_its_"), []byte("john"))
	if err != nil {
		tt.Fatalf("CTR seek edit: AES-CTR: err: %s\n", err)
	}

	expected := []byte("hey_its_john")
	actual, _, err := a.Process_CTR(new_cipher, key, nonce, 0)
	if err != nil {
		tt.Fatalf("AES-CTR: err: %s\n", err)
	}
	if ! slices.Equal(expected, actual) {
		tt.Fatalf("expected: %s for random-access edit into CTR cipherbytes, got: %s\n", expected, actual)
	}
}