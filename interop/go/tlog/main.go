// Command tlog checks an FPP Transparency Log directory with Go's
// golang.org/x/mod/sumdb packages, an implementation independent of the
// Rust one: the checkpoint's signed note, every hash tile against the
// signed root, every entry against its leaf hash, and inclusion proofs.
//
//	go run . -dir <log dir> -origin <origin> -key <base64 Ed25519 public key>
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// tiles reads C2SP tlog-tiles ("tile/<L>/<N>"): the sumdb layout without
// the height element ("tile/8/<L>/<N>").
type tiles struct{ dir string }

func (t tiles) Height() int { return 8 }

func (t tiles) ReadTiles(ts []tlog.Tile) ([][]byte, error) {
	out := make([][]byte, len(ts))
	for i, tile := range ts {
		p := strings.Replace(tile.Path(), "tile/8/", "tile/", 1)
		b, err := os.ReadFile(filepath.Join(t.dir, p))
		if err != nil {
			return nil, err
		}
		out[i] = b
	}
	return out, nil
}

func (t tiles) SaveTiles([]tlog.Tile, [][]byte) {}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	dir := flag.String("dir", "", "log directory")
	origin := flag.String("origin", "", "log origin (and key name)")
	key := flag.String("key", "", "base64 Ed25519 public key")
	flag.Parse()

	pub, err := base64.StdEncoding.DecodeString(*key)
	if err != nil || len(pub) != 32 {
		fail("key")
	}
	material := append([]byte{0x01}, pub...)
	h := sha256.Sum256(append([]byte(*origin+"\n"), material...))
	vkey := fmt.Sprintf("%s+%x+%s", *origin, h[:4], base64.StdEncoding.EncodeToString(material))
	verifier, err := note.NewVerifier(vkey)
	if err != nil {
		fail("verifier key: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(*dir, "checkpoint"))
	if err != nil {
		fail("checkpoint: %v", err)
	}
	n, err := note.Open(raw, note.VerifierList(verifier))
	if err != nil {
		fail("checkpoint note: %v", err)
	}
	lines := strings.Split(n.Text, "\n")
	if len(lines) < 4 || lines[0] != *origin {
		fail("checkpoint text %q", n.Text)
	}
	size, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil {
		fail("size")
	}
	rootBytes, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || len(rootBytes) != 32 {
		fail("root")
	}
	var root tlog.Hash
	copy(root[:], rootBytes)

	tree := tlog.Tree{N: size, Hash: root}
	hr := tlog.TileHashReader(tree, tiles{*dir})
	got, err := tlog.TreeHash(size, hr)
	if err != nil {
		fail("tree hash from tiles: %v", err)
	}
	if got != root {
		fail("tiles hash to %v, checkpoint says %v", got, root)
	}

	// every entry, from the bundles, against its leaf hash in the tiles
	var index int64
	for index < size {
		bundle := index / 256
		width := size - bundle*256
		if width > 256 {
			width = 256
		}
		p := "tile/entries/" + strings.TrimPrefix(tlog.Tile{H: 8, L: 0, N: bundle, W: int(width)}.Path(), "tile/8/0/")
		data, err := os.ReadFile(filepath.Join(*dir, p))
		if err != nil {
			fail("entries %s: %v", p, err)
		}
		for len(data) > 0 {
			if len(data) < 2 {
				fail("entry bundle %s", p)
			}
			l := int(binary.BigEndian.Uint16(data))
			entry := data[2 : 2+l]
			data = data[2+l:]
			hashes, err := hr.ReadHashes([]int64{tlog.StoredHashIndex(0, index)})
			if err != nil {
				fail("leaf %d: %v", index, err)
			}
			if tlog.RecordHash(entry) != hashes[0] {
				fail("entry %d does not hash to its leaf", index)
			}
			if index%97 == 0 || index == size-1 {
				proof, err := tlog.ProveRecord(size, index, hr)
				if err != nil {
					fail("prove %d: %v", index, err)
				}
				if err := tlog.CheckRecord(proof, size, root, index, hashes[0]); err != nil {
					fail("inclusion of %d: %v", index, err)
				}
			}
			index++
		}
	}
	if !bytes.Equal(rootBytes, root[:]) || index != size {
		fail("count")
	}
	fmt.Printf("ok: %d entries, tiles and checkpoint verified by golang.org/x/mod/sumdb\n", size)
}
