// Command b1sealvectors derives the SDK-shaped UC seal vector set from the B1 any-age corpus (bft-core b1ref/testdata/b1-vectors-anyage.json).
//
// The corpus is precompile-level: an EVM registry pre-state and CERT_BATCH_V2 request bytes. An SDK verifies a unicity certificate against a
// trust-base history instead, so each case here carries the certificate bytes taken from the request, every registry epoch as a committee with its
// root-round interval, the expected partition (the claim's) and network, and B1's verdict. Only cases whose verdict depends on the certificate or its
// seal are kept; the excluded ids are listed with the reason. Nothing is re-judged: the verdict is the corpus's own.
//
//	go run . -corpus <bft-core>/b1ref/testdata/b1-vectors-anyage.json -out b1-seal-vectors-v1.json
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
)

type corpus struct {
	Format  string   `json:"format"`
	Vectors []vector `json:"vectors"`
}

type vector struct {
	ID          string   `json:"id"`
	Family      string   `json:"family"`
	Op          string   `json:"op"`
	Description string   `json:"description"`
	PreState    preState `json:"preState"`
	Request     string   `json:"request"`
	Expected    struct {
		Status   string `json:"status"`
		Valid    bool   `json:"valid"`
		Sentinel string `json:"sentinel"`
	} `json:"expected"`
}

type preState struct {
	Network uint64     `json:"network"`
	Epochs  []regEpoch `json:"epochs"`
}

type regEpoch struct {
	Epoch   uint64 `json:"epoch"`
	Start   uint64 `json:"start"`
	End     uint64 `json:"end"`
	HasEnd  bool   `json:"hasEnd"`
	Members []struct {
		NodeID string `json:"nodeID"`
		Key    string `json:"key"`
		Weight uint64 `json:"weight"`
	} `json:"members"`
}

// verdicts that depend on the certificate or its seal (B1 sentinel -> kept). Everything else is excluded with its reason.
var ucLevel = map[string]bool{
	// seal signatures and quorum
	"ErrUnknownSigner": true, "ErrSigInvalid": true, "ErrSigFormat": true, "ErrSigRange": true, "ErrQuorum": true, "ErrDuplicateMapKey": true,
	"ErrTooManySigs": true,
	// seal context: network, epoch interval
	"ErrNetwork": true, "ErrBeforeStart": true, "ErrAfterEnd": true, "ErrEpochBeforeGenesis": true,
	// certificate content and trees
	"ErrNativeInvalid": true, "ErrTreeRoot": true, "ErrPartition": true,
	// certificate encoding and bounds
	"ErrNonCanonical": true, "ErrShape": true, "ErrForbiddenCBOR": true, "ErrInvalidUTF8": true, "ErrNodeIDTooLong": true, "ErrDepth": true,
	"ErrShardSiblings": true, "ErrSummaryTooLong": true, "ErrTooManySiblings": true, "ErrTooManySteps": true, "ErrUCTooLarge": true,
}

var excludedWhy = map[string]string{
	"ErrFuture":               "clock bound r <= O of the EVM registry; an SDK has no origin clock",
	"ErrEpochNotUsable":       "registry usability (import/acknowledgement state)",
	"ErrOriginNotReady":       "registry phase",
	"ErrPhase":                "registry phase",
	"ErrStateRoot":            "claim-level: the bridged state root is not part of the certificate",
	"ErrIRHash":               "claim-level: the claimed input-record hash",
	"ErrShardConf":            "claim-level: the claimed shard configuration hash",
	"ErrShard":                "claim-level: the claimed shard",
	"ErrShardEncoding":        "claim-level: the claim's shard field encoding",
	"ErrShardTooDeep":         "claim-level: the claim's shard field bound",
	"ErrVersion":              "request header version",
	"ErrCount":                "request claim count",
	"ErrFlags":                "request header flags",
	"ErrTruncated":            "request framing",
	"ErrTrailingBytes":        "request framing",
	"ErrInputTooLarge":        "request size",
	"ErrRegistryCommon":       "registry pre-state",
	"ErrRegistryInvalidEpoch": "registry pre-state",
	"ErrRegistryMissingEpoch": "registry pre-state",
}

type member struct {
	NodeID string `json:"nodeId"`
	Key    string `json:"key"`
	Weight uint64 `json:"weight"`
}

type epoch struct {
	Epoch     uint64   `json:"epoch"`
	Start     uint64   `json:"start"`
	End       *uint64  `json:"end"` // null: open (the newest epoch accepts every round >= start)
	Threshold uint64   `json:"threshold"`
	Members   []member `json:"members"`
}

type sealCase struct {
	ID                string  `json:"id"`
	Source            string  `json:"source"`
	Family            string  `json:"family"`
	Description       string  `json:"description"`
	Network           uint64  `json:"network"`
	ExpectedPartition uint32  `json:"expectedPartition"`
	UC                string  `json:"uc"`
	Epochs            []epoch `json:"epochs"`
	Verdict           string  `json:"verdict"` // valid | invalid | malformed
	B1Sentinel        string  `json:"b1Sentinel,omitempty"`
}

type excluded struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

type out struct {
	Format   string     `json:"format"`
	Source   source     `json:"source"`
	Notes    []string   `json:"notes"`
	Cases    []sealCase `json:"cases"`
	Excluded []excluded `json:"excluded"`
}

type source struct {
	File   string `json:"file"`
	Format string `json:"format"`
	Sha256 string `json:"sha256"`
}

type claim struct {
	partition uint32
	uc        []byte
}

// claims splits a CERT_BATCH_V2 request: version:u8 | flags:u8 | count:u16, then per claim partition:u32 | shardLen:u16 | shard | shardConf[32] |
// stateRoot[32] | irHash[32] | ucLen:u32 | uc. ok is false for any framing defect (those cases are request-level).
func claims(req []byte) ([]claim, bool) {
	if len(req) < 4 || req[0] != 2 || req[1] != 0 {
		return nil, false
	}
	n := int(binary.BigEndian.Uint16(req[2:4]))
	pos := 4
	take := func(k int) ([]byte, bool) {
		if k < 0 || pos+k > len(req) {
			return nil, false
		}
		b := req[pos : pos+k]
		pos += k
		return b, true
	}
	var out []claim
	for i := 0; i < n; i++ {
		p, ok := take(4)
		if !ok {
			return nil, false
		}
		sl, ok := take(2)
		if !ok {
			return nil, false
		}
		if _, ok := take(int(binary.BigEndian.Uint16(sl)) + 96); !ok {
			return nil, false
		}
		ul, ok := take(4)
		if !ok {
			return nil, false
		}
		uc, ok := take(int(binary.BigEndian.Uint32(ul)))
		if !ok {
			return nil, false
		}
		out = append(out, claim{partition: binary.BigEndian.Uint32(p), uc: uc})
	}
	return out, pos == len(req) && n > 0
}

func epochs(ps preState) []epoch {
	var out []epoch
	for _, e := range ps.Epochs {
		var total uint64
		var ms []member
		for _, m := range e.Members {
			ms = append(ms, member{NodeID: m.NodeID, Key: m.Key, Weight: m.Weight})
			total += m.Weight
		}
		ep := epoch{Epoch: e.Epoch, Start: e.Start, Members: ms, Threshold: total - (total-1)/3} // b1state.Threshold = floor(2W/3)+1
		if e.HasEnd {
			end := e.End
			ep.End = &end
		}
		out = append(out, ep)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Epoch < out[j].Epoch })
	return out
}

func main() {
	in := flag.String("corpus", "", "b1-vectors-anyage.json")
	dst := flag.String("out", "b1-seal-vectors-v1.json", "output")
	flag.Parse()
	raw, err := os.ReadFile(*in)
	if err != nil {
		panic(err)
	}
	var c corpus
	if err := json.Unmarshal(raw, &c); err != nil {
		panic(err)
	}
	sum := sha256.Sum256(raw)
	o := out{
		Format: "b1-seal-vectors/v1",
		Source: source{File: "bft-core b1ref/testdata/b1-vectors-anyage.json", Format: c.Format, Sha256: hex.EncodeToString(sum[:])},
		Notes: []string{
			"Each case: verify the unicity certificate `uc` for `expectedPartition` on `network` against the committees in `epochs` (the trust-base history); the verdict must equal B1's.",
			"Committee of a seal = the epoch with epoch == seal.epoch; the seal root round must be >= start and, when `end` is set, < end. No entry for the seal epoch below the first epoch is invalid.",
			"Seal signatures (B1 rule): every supplied signature checked, no early exit; an unknown signer or any bad signature fails the seal; 64 bytes, or 65 with v in {0,1} and v otherwise ignored; 1 <= r < n, 1 <= s <= n/2; ECDSA against the listed key; weighted sum >= threshold.",
			"verdict 'malformed' is B1 status=error (the input is refused before evaluation); 'invalid' is a well-formed certificate B1 judges false.",
			"Only cases whose verdict depends on the certificate or its seal are kept; `excluded` lists the rest with the reason. Every claim of an all-valid multi-claim batch is a separate valid case.",
		},
	}
	for _, v := range c.Vectors {
		if v.Op != "CERT_BATCH_V2" {
			continue
		}
		cl, ok := claims(mustHex(v.Request))
		switch {
		case !ok:
			o.Excluded = append(o.Excluded, excluded{v.ID, "request framing (certificate bytes cannot be taken from the request)"})
			continue
		case v.Expected.Status == "ok" && v.Expected.Valid && len(cl) > 1 && v.Family == "Gas/resources":
			o.Excluded = append(o.Excluded, excluded{v.ID, "multi-claim gas/resource batch: its certificates add size, not seal coverage"})
			continue
		case v.Expected.Status == "ok" && v.Expected.Valid:
			for i, x := range cl {
				id := v.ID
				if len(cl) > 1 {
					id = fmt.Sprintf("%s#%d", v.ID, i)
				}
				o.Cases = append(o.Cases, sealCase{ID: id, Source: v.ID, Family: v.Family, Description: v.Description, Network: v.PreState.Network,
					ExpectedPartition: x.partition, UC: hex.EncodeToString(x.uc), Epochs: epochs(v.PreState), Verdict: "valid"})
			}
			continue
		case len(cl) > 1:
			o.Excluded = append(o.Excluded, excluded{v.ID, "multi-claim batch judged false as a whole (" + v.Expected.Sentinel + ")"})
			continue
		case !ucLevel[v.Expected.Sentinel]:
			why := excludedWhy[v.Expected.Sentinel]
			if why == "" {
				why = "not certificate-level"
			}
			o.Excluded = append(o.Excluded, excluded{v.ID, why + " (" + v.Expected.Sentinel + ")"})
			continue
		}
		verdict := "invalid"
		if v.Expected.Status != "ok" {
			verdict = "malformed"
		}
		o.Cases = append(o.Cases, sealCase{ID: v.ID, Source: v.ID, Family: v.Family, Description: v.Description, Network: v.PreState.Network,
			ExpectedPartition: cl[0].partition, UC: hex.EncodeToString(cl[0].uc), Epochs: epochs(v.PreState), Verdict: verdict,
			B1Sentinel: v.Expected.Sentinel})
	}
	data, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(*dst, append(data, '\n'), 0o644); err != nil {
		panic(err)
	}
	counts := map[string]int{}
	for _, x := range o.Cases {
		counts[x.Verdict]++
	}
	fmt.Printf("%s: %d cases %v, %d excluded\n", *dst, len(o.Cases), counts, len(o.Excluded))
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
