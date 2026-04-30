package words

import (
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"fmt"
	"math/big"
	"strings"
)

//go:embed wordlist.txt
var wordlistRaw string

var wordlist []string

func init() {
	lines := strings.Split(strings.TrimSpace(wordlistRaw), "\n")
	for _, l := range lines {
		w := strings.TrimSpace(l)
		if w != "" {
			wordlist = append(wordlist, w)
		}
	}
}

// Phrase represents a 3-word passphrase.
type Phrase [3]string

// Generate returns a cryptographically random 3-word phrase.
func Generate() (Phrase, error) {
	var p Phrase
	count := big.NewInt(int64(len(wordlist)))
	for i := range p {
		n, err := rand.Int(rand.Reader, count)
		if err != nil {
			return p, fmt.Errorf("words: rng failure: %w", err)
		}
		p[i] = wordlist[n.Int64()]
	}
	return p, nil
}

// Hash returns the SHA-256 hex digest of the space-joined phrase,
// prefixed with "sha256:" for clarity in stored records.
func (p Phrase) Hash() string {
	joined := strings.Join(p[:], " ")
	sum := sha256.Sum256([]byte(joined))
	return fmt.Sprintf("sha256:%x", sum)
}

// String returns the phrase as "word1 word2 word3".
func (p Phrase) String() string {
	return strings.Join(p[:], " ")
}

// FromSlice converts a []string of length 3 into a Phrase.
func FromSlice(s []string) (Phrase, error) {
	if len(s) != 3 {
		return Phrase{}, fmt.Errorf("words: phrase must have exactly 3 words, got %d", len(s))
	}
	return Phrase{s[0], s[1], s[2]}, nil
}

// WordCount returns the size of the loaded wordlist.
func WordCount() int {
	return len(wordlist)
}
