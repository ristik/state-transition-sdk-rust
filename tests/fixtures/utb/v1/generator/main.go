// Command utbvectors writes the shared signed trust-base (UTB, record version 2) vector set for the JS and Rust SDKs.
//
// Every expected outcome is computed by the Go reference code, not written by hand: entry cases by bft-core's utbstore.Append (the single append
// path: strict decode, member limit, VerifySuccessor from the held predecessor, conflict/no-op rules), genesis cases by utbstore.Open, bundle cases
// by gettrustbase.DecodeBundle / VerifyBundle / InstallBundle. Keys and signatures are deterministic (fixed private keys, RFC 6979), so a rerun
// reproduces the file byte for byte.
//
//	go run . -out utb-vectors-v1.json
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"regexp"
	"sort"

	"github.com/fxamacker/cbor/v2"
	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	bfthex "github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/bft-core/gettrustbase"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/utbstore"
)

const network types.NetworkID = 3

type key struct {
	id     string
	pub    []byte
	signer crypto.Signer
}

func newKey(i int) key {
	priv := sha256.Sum256([]byte(fmt.Sprintf("unicity/utb-vectors/v1/key/%d", i)))
	s, err := crypto.NewInMemorySecp256K1SignerFromKey(priv[:])
	must(err)
	v, err := s.Verifier()
	must(err)
	pub, err := v.MarshalPublicKey()
	must(err)
	pk, err := p2pcrypto.UnmarshalSecp256k1PublicKey(pub)
	must(err)
	id, err := peer.IDFromPublicKey(pk)
	must(err)
	return key{id: id.String(), pub: pub, signer: s}
}

type member struct {
	k      key
	weight uint64
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func label(s string) []byte { h := sha256.Sum256([]byte("unicity/utb-vectors/v1/" + s)); return h[:] }

// build makes an unsigned entry linked to prev (genesis when prev is nil); the threshold is floor(2W/3)+1.
func build(epoch, start uint64, ms []member, prev *types.RootTrustBaseV2) *types.RootTrustBaseV2 {
	e := types.NewRootTrustBaseV2()
	e.NetworkID, e.Epoch, e.EpochStart = network, epoch, start
	var total uint64
	for _, m := range ms {
		e.RootNodes = append(e.RootNodes, &types.NodeInfo{NodeID: m.k.id, SigKey: m.k.pub, Stake: m.weight})
		total += m.weight
	}
	sort.Slice(e.RootNodes, func(i, j int) bool { return e.RootNodes[i].NodeID < e.RootNodes[j].NodeID })
	e.QuorumThreshold = total*2/3 + 1
	if prev == nil {
		e.PreviousEntryID = make([]byte, types.TrustBaseV2IDLen)
		return e
	}
	id, err := prev.EntryID()
	must(err)
	e.PreviousEntryID = id[:]
	e.StateHash = label(fmt.Sprintf("state/%d", epoch))
	e.ChangeRecordHash = label(fmt.Sprintf("change/%d", epoch))
	return e
}

func clone(e *types.RootTrustBaseV2) *types.RootTrustBaseV2 {
	b, err := e.MarshalCBOR()
	must(err)
	type alias types.RootTrustBaseV2
	var a alias
	must(types.Cbor.UnmarshalTaggedValue(types.UnicityTrustBaseTag, b, &a))
	c := types.RootTrustBaseV2(a)
	return &c
}

func signed(e *types.RootTrustBaseV2, by ...key) *types.RootTrustBaseV2 {
	c := clone(e)
	c.Signatures = nil
	for _, k := range by {
		must(c.Sign(k.id, k.signer))
	}
	return c
}

func enc(e *types.RootTrustBaseV2) []byte {
	type alias types.RootTrustBaseV2
	b, err := types.Cbor.MarshalTaggedValue(types.UnicityTrustBaseTag, (*alias)(e))
	must(err)
	return b
}

func entryID(e *types.RootTrustBaseV2) string {
	id, err := e.EntryID()
	must(err)
	return hex.EncodeToString(id[:])
}

// rawArray re-encodes a tagged entry from its array elements (for non-canonical and malformed byte forms).
func rawArray(tag uint64, elems []cbor.RawMessage) []byte {
	em, err := cbor.EncOptions{}.EncMode()
	must(err)
	inner, err := em.Marshal(elems)
	must(err)
	b, err := em.Marshal(cbor.RawTag{Number: tag, Content: inner})
	must(err)
	return b
}

func elements(b []byte) []cbor.RawMessage {
	var t cbor.RawTag
	must(cbor.Unmarshal(b, &t))
	var elems []cbor.RawMessage
	must(cbor.Unmarshal(t.Content, &elems))
	return elems
}

// mapRaw encodes a CBOR text-key map from pairs in the given order, duplicates allowed.
func mapRaw(pairs [][2][]byte) cbor.RawMessage {
	out := []byte{0xa0 | byte(len(pairs))}
	for _, p := range pairs {
		k, err := cbor.Marshal(string(p[0]))
		must(err)
		v, err := cbor.Marshal(p[1])
		must(err)
		out = append(out, k...)
		out = append(out, v...)
	}
	return out
}

// sigPairs is the signature map of an entry in canonical key order.
func sigPairs(e *types.RootTrustBaseV2) [][2][]byte {
	var ids []string
	for id := range e.Signatures {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		a, _ := cbor.Marshal(ids[i])
		b, _ := cbor.Marshal(ids[j])
		return bytes.Compare(a, b) < 0
	})
	var out [][2][]byte
	for _, id := range ids {
		out = append(out, [2][]byte{[]byte(id), e.Signatures[id]})
	}
	return out
}

// withSigs replaces each signature by f(signature).
func withSigs(e *types.RootTrustBaseV2, f func([]byte) []byte) *types.RootTrustBaseV2 {
	c := clone(e)
	for id, s := range c.Signatures {
		c.Signatures[id] = bfthex.Bytes(f(append([]byte(nil), s...)))
	}
	return c
}

var curveN, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)

func highS(s []byte) []byte {
	out := append([]byte(nil), s...)
	v := new(big.Int).SetBytes(s[32:64])
	v.Sub(curveN, v)
	vb := v.FillBytes(make([]byte, 32))
	copy(out[32:64], vb)
	out[64] ^= 1
	return out
}

// --- outcomes ---------------------------------------------------------------

type outcome struct {
	Result   string `json:"result"`           // appended | noop | gap | conflict | refused
	Reason   string `json:"reason,omitempty"` // diagnostic only (Go error text); the interface is result
	TipAfter uint64 `json:"tipAfter"`
}

// Diagnostic reasons are normalized: the Go verifier names whichever bad signer its map iteration meets first.
// The same holds for the per-signer recovery byte it quotes.
var (
	signerID   = regexp.MustCompile(`"16Uiu2[1-9A-HJ-NP-Za-km-z]+"`)
	recoveryID = regexp.MustCompile(`recovery id [0-9]+`)
)

func reason(err error) string {
	return recoveryID.ReplaceAllString(signerID.ReplaceAllString(err.Error(), "<signer>"), "recovery id <v>")
}

func classify(added bool, err error) (string, string) {
	switch {
	case err == nil && added:
		return "appended", ""
	case err == nil:
		return "noop", ""
	case errors.Is(err, utbstore.ErrGap):
		return "gap", reason(err)
	case errors.Is(err, utbstore.ErrConflict):
		return "conflict", reason(err)
	default:
		return "refused", reason(err)
	}
}

type world struct {
	genesis *types.RootTrustBaseV2
	pin     [types.TrustBaseV2IDLen]byte
	chain   [][]byte // canonical bytes, chain[0] = genesis (epoch 1)
}

// store opens a fresh store holding the chain up to epoch held.
func (w *world) store(held uint64) *utbstore.Store {
	s, err := utbstore.Open(memorydb.New(), w.genesis, w.pin)
	must(err)
	for i := uint64(1); i < held; i++ {
		_, err := s.Append(w.chain[i])
		must(err)
	}
	return s
}

type entryCase struct {
	ID          string  `json:"id"`
	Description string  `json:"description"`
	Held        uint64  `json:"held"` // the store holds the chain epochs 1..held
	Input       string  `json:"input"`
	Expected    outcome `json:"expected"`
	HeldAfter   string  `json:"heldBytesAfter,omitempty"` // for no-op replays: the stored bytes of that epoch, unchanged
}

type genesisCase struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Input       string `json:"input"`
	Pin         string `json:"pin"`
	Valid       bool   `json:"valid"`
	Reason      string `json:"reason,omitempty"`
}

type bundleCase struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Input       string `json:"input"`
	Decodes     bool   `json:"decodes"`           // DecodeBundle (complete-history rules, file budget)
	Verifies    bool   `json:"verifies"`          // VerifyBundle against the pin (offline chain check)
	Held        uint64 `json:"held,omitempty"`    // install target: a store holding 1..held (0: no install case)
	Install     string `json:"install,omitempty"` // appended | noop | refused
	TipAfter    uint64 `json:"tipAfter,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

type chainEntry struct {
	Epoch    uint64 `json:"epoch"`
	Hex      string `json:"hex"`
	EntryID  string `json:"entryId"`
	SigBytes string `json:"sigBytes"`
}

type file struct {
	Format    string        `json:"format"`
	Generator string        `json:"generator"`
	Notes     []string      `json:"notes"`
	Network   uint16        `json:"network"`
	Pin       string        `json:"pin"`
	Chain     []chainEntry  `json:"chain"`
	Genesis   []genesisCase `json:"genesisCases"`
	Entries   []entryCase   `json:"entryCases"`
	Bundles   []bundleCase  `json:"bundleCases"`
}

func main() {
	out := flag.String("out", "utb-vectors-v1.json", "output file")
	flag.Parse()

	keys := make([]key, 13)
	for i := range keys {
		keys[i] = newKey(i)
	}
	ms := func(w []uint64, idx ...int) []member {
		var r []member
		for i, k := range idx {
			r = append(r, member{keys[k], w[i]})
		}
		return r
	}
	c1 := ms([]uint64{1, 1, 1, 1}, 0, 1, 2, 3) // W 4, threshold 3
	c2 := ms([]uint64{1, 2, 3, 4}, 4, 5, 6, 7) // W 10, threshold 7
	c3 := ms([]uint64{5, 5, 5}, 8, 9, 10)      // W 15, threshold 11
	c4 := ms([]uint64{1, 1, 1, 1}, 0, 1, 2, 3)
	outsider := keys[11]

	g := build(1, 1, c1, nil)
	e2u := build(2, 100, c2, g)
	e2 := signed(e2u, keys[0], keys[1], keys[2])
	e3u := build(3, 200, c3, e2)
	e3 := signed(e3u, keys[6], keys[7]) // 3+4 = 7
	e4u := build(4, 300, c4, e3)
	e4 := signed(e4u, keys[8], keys[9], keys[10])

	gid, err := g.EntryID()
	must(err)
	w := &world{genesis: g, pin: gid, chain: [][]byte{enc(g), enc(e2), enc(e3), enc(e4)}}
	f := &file{
		Format:    "utb-vectors/v1",
		Generator: "briefs/tools/utb-vectors (ristik/bft-core a20708b64a1c, ristik/bft-go-base 6174434eeb99)",
		Notes: []string{
			"Entries are RootTrustBaseV2 (tag 39000, version 2). EntryID = SHA-256(sigBytes), sigBytes = the entry with signatures encoded as CBOR null.",
			"Witness signatures: exactly 65 bytes r||s||v, 1 <= r,s < n, low-S, v in 0..3, the recovered key must equal the member key (bft-go-base#2).",
			"A successor needs a strict quorum of the PREDECESSOR's members: every supplied signature valid and from a member, weight >= threshold = floor(2W/3)+1.",
			"Expected results come from bft-core utbstore.Append / Open and gettrustbase bundle functions. 'reason' is the Go error text, diagnostic only.",
			"The bundle is the GetTrustBase response (tag 39015, provisional) with status OK, fromEpoch = genesis, every entry, nextEpoch null.",
		},
		Network: uint16(network),
		Pin:     hex.EncodeToString(gid[:]),
	}
	for _, e := range []*types.RootTrustBaseV2{g, e2, e3, e4} {
		sb, err := e.SigBytes()
		must(err)
		f.Chain = append(f.Chain, chainEntry{Epoch: e.Epoch, Hex: hex.EncodeToString(enc(e)), EntryID: entryID(e), SigBytes: hex.EncodeToString(sb)})
	}

	// genesis
	addGenesis := func(id, desc string, input []byte, pin [32]byte) {
		gc := genesisCase{ID: id, Description: desc, Input: hex.EncodeToString(input), Pin: hex.EncodeToString(pin[:])}
		e, err := types.DecodeRootTrustBaseV2(input)
		if err == nil {
			_, err = utbstore.Open(memorydb.New(), e, pin)
		}
		gc.Valid = err == nil
		if err != nil {
			gc.Reason = reason(err)
		}
		f.Genesis = append(f.Genesis, gc)
	}
	addGenesis("genesis.ok", "the pinned genesis", enc(g), gid)
	addGenesis("genesis.pin-mismatch", "a valid genesis that is not the pinned one", enc(g), sha256.Sum256([]byte("other pin")))
	gs := clone(g)
	must(gs.Sign(keys[0].id, keys[0].signer))
	addGenesis("genesis.with-signatures", "a genesis carrying a signature map", enc(gs), gid)
	gnz := clone(g)
	gnz.PreviousEntryID = label("not zero")
	addGenesis("genesis.nonzero-predecessor", "an epoch-1 entry with a non-zero predecessor and no signatures", enc(gnz), gid)

	// entries
	add := func(id, desc string, held uint64, input []byte, heldAfter bool) {
		s := w.store(held)
		added, err := s.Append(input)
		r, reason := classify(added, err)
		ec := entryCase{ID: id, Description: desc, Held: held, Input: hex.EncodeToString(input), Expected: outcome{Result: r, Reason: reason, TipAfter: s.Tip().Epoch}}
		if heldAfter {
			e, derr := types.DecodeRootTrustBaseV2(input)
			must(derr)
			b, gerr := s.Get(e.Epoch)
			must(gerr)
			ec.HeldAfter = hex.EncodeToString(b)
		}
		f.Entries = append(f.Entries, ec)
	}
	add("append.e2", "epoch 2 (unequal weights 1,2,3,4) signed by 3 of 4 genesis members", 1, enc(e2), false)
	add("append.e3", "epoch 3 signed by epoch-2 members of weight 3+4 = threshold 7", 2, enc(e3), false)
	add("append.e4", "epoch 4 signed by all epoch-3 members (5+5+5, threshold 11)", 3, enc(e4), false)
	add("replay.identical", "the held epoch-2 entry again", 2, enc(e2), true)
	add("replay.other-witness", "epoch 2 with another valid signature subset (same EntryID): no-op, held bytes kept", 2, enc(signed(e2u, keys[1], keys[2], keys[3])), true)
	add("replay.held-invalid-witness", "epoch 2 with the same unsigned bytes but a broken signature", 2, enc(withSigs(e2, func(s []byte) []byte { s[10] ^= 1; return s })), true)
	c2alt := clone(e2u)
	c2alt.EpochStart = 101
	add("conflict.e2", "a validly signed epoch-2 entry with different unsigned bytes (start 101)", 2, enc(signed(c2alt, keys[0], keys[1], keys[2])), false)
	add("gap.e3-on-genesis", "epoch 3 while only the genesis is held", 1, enc(e3), false)
	add("gap.e2-before-genesis-held-e4", "epoch 2 again while epochs 1..4 are held is a no-op, not a gap", 4, enc(e2), true)
	add("refused.unsigned", "a successor with a null signature map", 1, enc(e2u), false)
	add("refused.below-threshold", "signatures of weight 2 < 3", 1, enc(signed(e2u, keys[0], keys[1])), false)
	add("refused.signer-not-predecessor-member", "signed by the new committee's own members (not the predecessor's)", 1, enc(signed(e2u, keys[4], keys[5], keys[6], keys[7])), false)
	bad := signed(e2u, keys[0], keys[1], keys[2], keys[3])
	bad.Signatures[keys[3].id] = signed(e3u, keys[3]).Signatures[keys[3].id] // a valid-shape signature over other bytes
	add("refused.extra-invalid-member-signature", "quorum met by 3 valid signatures plus one invalid signature of the fourth member", 1, enc(bad), false)
	unk := signed(e2u, keys[0], keys[1], keys[2])
	must(unk.Sign(outsider.id, outsider.signer))
	add("refused.unknown-extra-signer", "quorum met plus a valid signature of a non-member", 1, enc(unk), false)
	wp := clone(e2u)
	wp.PreviousEntryID = label("wrong predecessor")
	add("refused.wrong-predecessor", "previousEntryId is not the genesis EntryID", 1, enc(signed(wp, keys[0], keys[1], keys[2])), false)
	wn := clone(e2u)
	wn.NetworkID = 4
	add("refused.network", "another network identifier", 1, enc(signed(wn, keys[0], keys[1], keys[2])), false)
	ws := clone(e2u)
	ws.EpochStart = 1
	add("refused.start-not-increasing", "epoch start equal to the predecessor's", 1, enc(signed(ws, keys[0], keys[1], keys[2])), false)
	wt := clone(e2u)
	wt.QuorumThreshold = 8
	add("refused.threshold-not-floor-2w3-plus-1", "recorded threshold 8 for total weight 10 (must be 7)", 1, enc(signed(wt, keys[0], keys[1], keys[2])), false)
	wz := clone(e2u)
	wz.RootNodes[0].Stake = 0
	add("refused.weight-zero", "a member of weight 0", 1, enc(signed(wz, keys[0], keys[1], keys[2])), false)
	add("sig.64-byte", "witnesses without the recovery byte", 1, enc(withSigs(e2, func(s []byte) []byte { return s[:64] })), false)
	add("sig.wrong-recovery-id", "recovery byte flipped (0 <-> 1)", 1, enc(withSigs(e2, func(s []byte) []byte { s[64] ^= 1; return s })), false)
	add("sig.recovery-id-27", "recovery byte 27 (Ethereum style)", 1, enc(withSigs(e2, func(s []byte) []byte { s[64] += 27; return s })), false)
	add("sig.63-byte", "63-byte witnesses", 1, enc(withSigs(e2, func(s []byte) []byte { return s[:63] })), false)
	add("sig.66-byte", "66-byte witnesses", 1, enc(withSigs(e2, func(s []byte) []byte { return append(s, 0) })), false)
	add("sig.high-s", "the high-S twin of each witness (recovery byte adjusted)", 1, enc(withSigs(e2, highS)), false)

	e2b := enc(e2)
	el := elements(e2b)
	retag := append([]cbor.RawMessage(nil), el...)
	add("decode.wrong-tag", "tag 39001 instead of 39000", 1, rawArray(39001, retag), false)
	v1 := append([]cbor.RawMessage(nil), el...)
	v1[0] = cbor.RawMessage{0x01}
	add("decode.version-1", "version 1 under tag 39000", 1, rawArray(39000, v1), false)
	add("decode.trailing-byte", "one byte after the entry", 1, append(append([]byte(nil), e2b...), 0x00), false)
	nm := append([]cbor.RawMessage(nil), el...)
	nm[2] = cbor.RawMessage{0x18, 0x02} // epoch 2 encoded in two bytes
	add("decode.non-minimal-integer", "epoch encoded non-minimally", 1, rawArray(39000, nm), false)
	pairs := sigPairs(e2)
	rev := make([][2][]byte, len(pairs))
	for i := range pairs {
		rev[i] = pairs[len(pairs)-1-i]
	}
	mo := append([]cbor.RawMessage(nil), el...)
	mo[9] = mapRaw(rev)
	add("decode.map-order", "signature map keys not in canonical order", 1, rawArray(39000, mo), false)
	dup := append([]cbor.RawMessage(nil), el...)
	dup[9] = mapRaw(append(append([][2][]byte(nil), pairs...), pairs[0]))
	add("decode.duplicate-map-key", "a signer listed twice", 1, rawArray(39000, dup), false)
	short := append([]cbor.RawMessage(nil), el[:9]...)
	add("decode.arity-9", "nine array elements", 1, rawArray(39000, short), false)

	// bundles
	addBundle := func(id, desc string, input []byte, held uint64) {
		bc := bundleCase{ID: id, Description: desc, Input: hex.EncodeToString(input)}
		b, err := gettrustbase.DecodeBundle(input, gettrustbase.BundleLimits{MaxBytes: 1 << 20, MaxEntries: 1 << 10})
		bc.Decodes = err == nil
		if err == nil {
			err = gettrustbase.VerifyBundle(b, w.pin)
			bc.Verifies = err == nil
		}
		if err != nil {
			bc.Reason = reason(err)
		}
		if bc.Decodes && held > 0 {
			s := w.store(held)
			n, ierr := gettrustbase.InstallBundle(s, b)
			bc.Held, bc.TipAfter = held, s.Tip().Epoch
			switch {
			case ierr != nil:
				bc.Install, bc.Reason = "refused", reason(ierr)
			case n > 0:
				bc.Install = "appended"
			default:
				bc.Install = "noop"
			}
		}
		f.Bundles = append(f.Bundles, bc)
	}
	full, err := gettrustbase.EncodeBundle(w.chain)
	must(err)
	addBundle("bundle.complete", "epochs 1..4, installed on a genesis-only store", full, 1)
	gonly, err := gettrustbase.EncodeBundle(w.chain[:1])
	must(err)
	addBundle("bundle.genesis-only", "the genesis alone", gonly, 1)
	older, err := gettrustbase.EncodeBundle(w.chain[:2])
	must(err)
	addBundle("bundle.older-on-newer", "epochs 1..2 installed on a store holding 1..4: nothing rolls back", older, 4)
	addBundle("bundle.trailing-byte", "a complete bundle plus one byte", append(append([]byte(nil), full...), 0x00), 0)

	resp := func(entries [][]byte, next *uint64, end uint64, endID []byte) []byte {
		r := &gettrustbase.Response{Version: gettrustbase.Version, Network: network, Status: gettrustbase.StatusOK, FromEpoch: 1, EffectiveEnd: end,
			EndEntryID: endID, NextEpoch: next}
		for _, e := range entries {
			r.Entries = append(r.Entries, e)
		}
		b, err := types.Cbor.MarshalTaggedValue(gettrustbase.ResponseTag, r)
		must(err)
		return b
	}
	e4id, err := e4.EntryID()
	must(err)
	three := uint64(3)
	addBundle("bundle.continuation-cursor", "a page with nextEpoch set is not a complete bundle", resp(w.chain[:2], &three, 4, e4id[:]), 0)
	e3id, err := e3.EntryID()
	must(err)
	addBundle("bundle.gap", "epochs 1 and 3 only", resp([][]byte{w.chain[0], w.chain[2]}, nil, 3, e3id[:]), 0)
	brokenE3 := withSigs(e3, func(s []byte) []byte { s[10] ^= 1; return s })
	be3id, err := brokenE3.EntryID()
	must(err)
	addBundle("bundle.broken-signature", "epoch 3's witnesses do not verify", resp([][]byte{w.chain[0], w.chain[1], enc(brokenE3)}, nil, 3, be3id[:]), 2)
	conflictBundle := resp([][]byte{w.chain[0], enc(signed(c2alt, keys[0], keys[1], keys[2]))}, nil, 2, func() []byte { id, _ := c2alt.EntryID(); return id[:] }())
	addBundle("bundle.conflict-on-held", "a bundle whose epoch 2 conflicts with the held epoch 2", conflictBundle, 2)

	data, err := json.MarshalIndent(f, "", "  ")
	must(err)
	must(os.WriteFile(*out, append(data, '\n'), 0o644))
	fmt.Printf("%s: %d genesis, %d entry, %d bundle cases\n", *out, len(f.Genesis), len(f.Entries), len(f.Bundles))
}
