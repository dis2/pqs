package main
//import "github.com/magical/argon2"
import "golang.org/x/crypto/argon2"
import "golang.org/x/crypto/ed25519"
import "github.com/dis2/go-dilithium/dilithium"
import "flag"
import "syscall"
import "io/ioutil"
import "io"
import "os"
import "bufio"
import "bytes"
import "strings"
import "encoding/pem"
import "golang.org/x/crypto/sha3"
import "fmt"
//import "log"
import "golang.org/x/crypto/ssh/terminal"

const SKMARK = "PQ PRIVATE KEY"
const PKMARK = "PQ PUBLIC KEY"
const SIGNMARK = "PQ SIGNATURE"

var cmd_key = flag.String("key", "", "Set key file")
var cmd_force = flag.Bool("force", false, "Answer yes to all questions")
var cmd_phrase = flag.Bool("phrase", false, "Ask for a phrase to use as a key")

var dsk dilithium.SK
var dpk dilithium.PK
var edpk ed25519.PublicKey
var edsk ed25519.PrivateKey
var seed [32]byte
var seedp = seed[:]

func genkeys() {
	dpk, dsk, seedp = dilithium.KeyPair(seedp)
	edpk, edsk, _ = ed25519.GenerateKey(bytes.NewReader(seedp))
}

func iterfiles(sign bool) {
	i := 0
	done := 0
	total := 0
	for {
		var block *pem.Block
		fn := flag.Arg(i)
		i++
		if fn == "" {
			break
		}
		total++

		pqfn := fn + ".pqsig"
		if strings.HasSuffix(fn, ".pqsig") {
			continue
		}
		if !sign {
			pemdata, err := ioutil.ReadFile(pqfn)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: has no .pqsig\n", fn)
				continue
			}
			block, _ = pem.Decode(pemdata)
			if block == nil {
				fmt.Fprintf(os.Stderr, "%s: .pqsig failed to decode\n", fn)
				continue
			}
			if block.Type != SIGNMARK {
				fmt.Fprintf(os.Stderr, "%s: unknown .pqsig '%s'\n", fn, block.Type)
				continue
			}
		}
		i++
		f, err := os.Open(fn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", fn, err)
			continue
		}
		state := sha3.NewShake256()
		_, err = io.Copy(state, f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", fn, err)
			continue
		}
		var image [64]byte
		state.Read(image[:])
		if !sign {
			if !ed25519.Verify(edpk, image[:], block.Bytes[0:64]) {
				fmt.Fprintf(os.Stderr, "%s: ed25519 failed\n", fn)
				continue
			}
			if !dpk.Verify(image[:], block.Bytes[64:]) {
				fmt.Fprintf(os.Stderr, "%s: dilithium failed\n", fn)
				continue
			}
			// its good
			fmt.Printf("%s\n", fn)
			done++
			continue
		}
		// we're in signing mode
		if exists(fn + ".pqsig") && !yesno(fn + " is already signed, overwrite the old signature?") {
			continue
		}

		edsig := ed25519.Sign(edsk, image[:])
		dsig := dsk.Sign(image[:])
		writePEM(fn + ".pqsig", SIGNMARK, append(edsig, dsig...), 0644)
		// all done
		fmt.Printf("%s\n", fn)
		done++
	}
	fmt.Fprintf(os.Stderr, "%d files OK out of %d.\n", done, total);
	if done == total {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
}

func exists(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}
	return true
}

func writePEM(file string, marker string, data []byte, mode os.FileMode) {
	block := &pem.Block {
		Type: marker,
		Bytes: data,
	}
	err := ioutil.WriteFile(file, pem.EncodeToMemory(block), mode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", file, err)
		return
	}
	fmt.Fprintf(os.Stderr, "Saved %s into '%s' (%d bytes)\n", marker, file, len(data))
}

func yesno(q string) bool {
	if (*cmd_force) {
		return true
	}
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Fprintf(os.Stderr, q + " ")
	for {
		scanner.Scan()
		text := scanner.Text()
		if text == "yes" {
			return true
		}
		if text == "no" {
			return false
		}
		fmt.Fprintf(os.Stderr, "Please answer clear 'yes' or 'no': ")
	}
}

func main() {
	_ = edsk
	_ = dpk
	_ = dsk
	flag.Parse()
	pass := ""
	if *cmd_phrase {
		fmt.Fprintf(os.Stderr, "Enter passphrase, or emptry string: ")
		passb, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Scan()
			pass = scanner.Text()
		} else {
			pass = string(passb)
		}
		seedp = seed[:]
		if pass != "" {
			fmt.Fprintf(os.Stderr, "Running Argon2 KDF, this will take a while...")
			// lame, but you can't salt a passphrase
			salt := []byte("PQ-SIGNTOOL")
			seedp = argon2.Key([]byte(pass), salt, 64, 64 * 1024, 4, 32)
			fmt.Fprintf(os.Stderr, "\n")
//			sha3.ShakeSum256(seedp, []byte(pass))
		} else {
			fmt.Fprintf(os.Stderr, "Empty string entered, generating random seed.\n")
			seedp = nil
		}
		genkeys()

		// amalgam the two public keys
		pk := append([]byte(edpk), dpk[:]...)
		if *cmd_key != "" {
			sk_file := *cmd_key
			pk_file := sk_file + ".pub"
			fmt.Fprintf(os.Stderr, "Saving private key to '%s' and public key to '%s'\n", sk_file, pk_file)
			if (!exists(sk_file) || yesno("Private key " + sk_file + " exists, overwrite?")) {
				writePEM(sk_file, SKMARK, seedp, 0644)
			}
			if (!exists(pk_file) || yesno("Public key " + pk_file + " exists, overwrite?")) {
				writePEM(pk_file, PKMARK, pk, 0755)
			}
		}
	} else {
		if *cmd_key == "" {
			fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
			flag.PrintDefaults()
			fmt.Fprintf(os.Stderr, "  [file1...] [file2...]\n")
			fmt.Fprintf(os.Stderr, "        List of files to be signed or verified\n")
			fmt.Fprintf(os.Stderr, "You must set at least key or phrase. Setting both generates key files.\n")
			os.Exit(1)
		}
		// ok, now try to load the key. it can be either private or
		// public, which determines if we'll be signing or checking
		pemdata, err := ioutil.ReadFile(*cmd_key)
		if err != nil {
			panic(err)
		}
		block, _ := pem.Decode(pemdata)
		if block == nil {
			panic("failed to decode key file")
		}
		if block.Type == SKMARK {
			fmt.Fprintf(os.Stderr, "Got a private key; entering SIGNING mode\n")
			seedp = block.Bytes
			genkeys()
			iterfiles(true)
		} else if block.Type == PKMARK {
			fmt.Fprintf(os.Stderr, "Got a public key; entering CHECKING mode\n")
			edpk = block.Bytes[0:32]
			copy(dpk.Bytes()[:], block.Bytes[32:])
			if len(block.Bytes) != 32+dilithium.PK_SIZE_PACKED {
				panic("wrong key sizes")
			}
			iterfiles(false)
		} else {
			panic("unknown key file format")
		}
	}
}

