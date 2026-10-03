// This builder uses the canonical go-libipni v0.9.0 schema, signed-envelope,
// signed-head and announce implementations. It never serves or announces data.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/ipfs/go-cid"
	"github.com/ipld/go-ipld-prime"
	"github.com/ipld/go-ipld-prime/codec/dagcbor"
	cidlink "github.com/ipld/go-ipld-prime/linking/cid"
	"github.com/ipni/go-libipni/announce/message"
	"github.com/ipni/go-libipni/dagsync/ipnisync/head"
	"github.com/ipni/go-libipni/ingest/schema"
	"github.com/ipni/go-libipni/metadata"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/multiformats/go-multihash"
)

const historicalProviderHost = "signalx-ipfs-provider.kamuitranslator.workers.dev"
const historicalRootCID = "bafybeianebwhw4uzkqnaekl5kyoau7hubxaens7azrftgqtz2mccciejle"
const maxBlocks = 64
const topic = "/indexer/ingest/mainnet"

var dnsLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var dnsTLD = regexp.MustCompile(`^(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$`)

type request struct {
	RootCID      string   `json:"rootCid"`
	BlockCIDs    []string `json:"blockCids"`
	ProviderID   string   `json:"providerId"`
	ProviderHost string   `json:"providerHost,omitempty"`
	ActivatedAt  string   `json:"activatedAt"`
	ExpiresAt    *string  `json:"expiresAt"`
	ServingMode  string   `json:"servingMode,omitempty"`
}

type object struct {
	CID         string `json:"cid"`
	Body        []byte `json:"bodyBase64"`
	ContentType string `json:"contentType"`
}

type announcement struct {
	AdCID       string `json:"adCid"`
	Body        []byte `json:"bodyBase64"`
	ContentType string `json:"contentType"`
}

type bundle struct {
	Version             int               `json:"version"`
	Request             request           `json:"request"`
	ProviderID          string            `json:"providerId"`
	ContextID           []byte            `json:"contextIdBase64"`
	ActiveHead          object            `json:"activeHead"`
	RemovalHead         *object           `json:"removalHead"`
	Objects             []object          `json:"objects"`
	AddAnnouncement     announcement      `json:"addAnnouncement"`
	RemovalAnnouncement *announcement     `json:"removalAnnouncement"`
	Reference           map[string]string `json:"reference"`
	Predecessor         *predecessor      `json:"predecessor,omitempty"`
}

// The historical objects are kept once in the flat bundle object set. This
// proof authenticates the immediately preceding request and head without
// recursively embedding every earlier bundle.
type predecessor struct {
	Request       request `json:"request"`
	ContextID     []byte  `json:"contextIdBase64"`
	ActiveHead    object  `json:"activeHead"`
	RetirementCID string  `json:"retirementCid"`
}

type buildInput struct {
	Request        *request `json:"request"`
	PreviousBundle *bundle  `json:"previousBundle,omitempty"`
}

func effectiveHost(r request) string {
	if r.ProviderHost == "" {
		return historicalProviderHost
	}
	return r.ProviderHost
}

func validateHost(host string) error {
	labels := strings.Split(host, ".")
	if len(host) > 253 || len(labels) < 2 || !dnsTLD.MatchString(labels[len(labels)-1]) {
		return errors.New("provider host must be a canonical public DNS hostname for HTTPS on port 443")
	}
	for _, label := range labels {
		if !dnsLabel.MatchString(label) {
			return errors.New("provider host must be a canonical public DNS hostname for HTTPS on port 443")
		}
	}
	for _, suffix := range []string{"localhost", "local", "internal", "test", "invalid", "example", "onion", "arpa", "example.com", "example.net", "example.org"} {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return errors.New("provider hostname uses a reserved or local namespace")
		}
	}
	return nil
}

func contentCID(s string) (cid.Cid, error) {
	if len(s) > 120 {
		return cid.Undef, errors.New("invalid content CID")
	}
	c, err := cid.Decode(s)
	if err != nil || c.Version() != 1 || c.String() != s || (c.Type() != cid.Raw && c.Type() != cid.DagProtobuf && c.Type() != cid.DagCBOR) {
		return cid.Undef, errors.New("expected a canonical raw, DAG-PB or DAG-CBOR content CID")
	}
	d, err := multihash.Decode(c.Hash())
	if err != nil || d.Code != multihash.SHA2_256 || len(d.Digest) != 32 {
		return cid.Undef, errors.New("expected SHA-256 content multihashes")
	}
	return c, nil
}

func validateRequest(r request) ([]multihash.Multihash, error) {
	root, err := contentCID(r.RootCID)
	if err != nil || len(r.BlockCIDs) < 1 || len(r.BlockCIDs) > maxBlocks {
		return nil, errors.New("expected a content root and 1 to 64 block CIDs")
	}
	if r.ProviderHost == "" && r.RootCID != historicalRootCID {
		return nil, errors.New("new publications must supply an explicit providerHost")
	}
	if err := validateHost(effectiveHost(r)); err != nil {
		return nil, err
	}
	start, err := time.Parse(time.RFC3339Nano, r.ActivatedAt)
	if err != nil {
		return nil, errors.New("invalid activation time")
	}
	switch r.ServingMode {
	case "continuous":
		if r.ExpiresAt != nil || r.ProviderHost == "" {
			return nil, errors.New("continuous serving requires null expiry and an explicit providerHost")
		}
	case "", "finite":
		if r.ExpiresAt == nil {
			return nil, errors.New("finite serving requires a timestamp expiry")
		}
		end, err := time.Parse(time.RFC3339Nano, *r.ExpiresAt)
		if err != nil || !end.After(start) || end.Sub(start) > 7*24*time.Hour {
			return nil, errors.New("term must be positive and at most seven days")
		}
	default:
		return nil, errors.New("servingMode must be finite or continuous")
	}
	p, err := peer.Decode(r.ProviderID)
	if err != nil || p.String() != r.ProviderID {
		return nil, errors.New("invalid provider identity")
	}
	publicKey, err := p.ExtractPublicKey()
	if err != nil || publicKey.Type() != crypto.Ed25519 {
		return nil, errors.New("dedicated Ed25519 provider identity required")
	}
	seen := map[string]bool{}
	entries := make([]multihash.Multihash, 0, len(r.BlockCIDs))
	foundRoot := false
	for _, s := range r.BlockCIDs {
		c, err := contentCID(s)
		if err != nil {
			return nil, errors.New("invalid content CID")
		}
		h := c.Hash()
		if seen[string(h)] {
			return nil, errors.New("expected distinct SHA-256 content multihashes")
		}
		seen[string(h)] = true
		foundRoot = foundRoot || c.Equals(root)
		entries = append(entries, h)
	}
	if !foundRoot {
		return nil, errors.New("publication root missing from content entries")
	}
	return entries, nil
}

func contextID(r request) []byte {
	if r.ServingMode == "continuous" {
		canonical, _ := json.Marshal(r)
		d := sha256.Sum256(append([]byte("signalx-http-provider-continuous-v2\x00"), canonical...))
		return d[:]
	}
	// Keep historical finite contexts byte-compatible.
	d := sha256.Sum256([]byte("signalx-http-provider-v1\x00" + r.RootCID + "\x00" + r.ActivatedAt + "\x00" + *r.ExpiresAt))
	return d[:]
}

func encodeObject(n ipld.Node) (object, cidlink.Link, error) {
	b, err := ipld.Encode(n, dagcbor.Encode)
	if err != nil {
		return object{}, cidlink.Link{}, err
	}
	c, err := (cid.Prefix{Version: 1, Codec: cid.DagCBOR, MhType: multihash.SHA2_256, MhLength: 32}).Sum(b)
	if err != nil {
		return object{}, cidlink.Link{}, err
	}
	return object{CID: c.String(), Body: b, ContentType: "application/vnd.ipld.dag-cbor"}, cidlink.Link{Cid: c}, nil
}

func signedAd(ad *schema.Advertisement, k crypto.PrivKey) (object, cidlink.Link, error) {
	if err := ad.Validate(); err != nil {
		return object{}, cidlink.Link{}, err
	}
	if err := ad.Sign(k); err != nil {
		return object{}, cidlink.Link{}, err
	}
	n, err := ad.ToNode()
	if err != nil {
		return object{}, cidlink.Link{}, err
	}
	return encodeObject(n)
}

func signedHead(c cid.Cid, k crypto.PrivKey) (object, error) {
	h, err := head.NewSignedHead(c, topic, k)
	if err != nil {
		return object{}, err
	}
	b, err := h.Encode()
	return object{CID: c.String(), Body: b, ContentType: "application/vnd.ipld.dag-json"}, err
}

func makeAnnouncement(c cid.Cid, p peer.ID, host string) (announcement, error) {
	address, err := ma.NewMultiaddr("/dns4/" + host + "/tcp/443/tls/http/p2p/" + p.String())
	if err != nil {
		return announcement{}, err
	}
	m := message.Message{Cid: c}
	m.SetAddrs([]ma.Multiaddr{address})
	b, err := json.Marshal(m)
	return announcement{AdCID: c.String(), Body: b, ContentType: "application/json"}, err
}

func buildBundle(r request, k crypto.PrivKey, previous ...*bundle) (*bundle, error) {
	if len(previous) > 1 {
		return nil, errors.New("at most one previous public bundle is accepted")
	}
	var prior *bundle
	if len(previous) == 1 {
		prior = previous[0]
	}
	if r.ServingMode == "continuous" {
		return buildContinuousBundle(r, k, prior)
	}
	if prior != nil {
		return nil, errors.New("predecessor migration requires continuous serving")
	}
	return buildFiniteBundle(r, k)
}

func buildFiniteBundle(r request, k crypto.PrivKey) (*bundle, error) {
	entries, err := validateRequest(r)
	if err != nil {
		return nil, err
	}
	if k.Type() != crypto.Ed25519 {
		return nil, errors.New("dedicated Ed25519 provider key required")
	}
	p, err := peer.IDFromPrivateKey(k)
	if err != nil || p.String() != r.ProviderID {
		return nil, errors.New("provider key does not match approved identity")
	}
	chunk := schema.EntryChunk{Entries: entries}
	n, err := chunk.ToNode()
	if err != nil {
		return nil, err
	}
	entryObj, entryLink, err := encodeObject(n)
	if err != nil {
		return nil, err
	}
	metadataValue := metadata.Default.New(&metadata.IpfsGatewayHttp{})
	md, err := metadataValue.MarshalBinary()
	if err != nil {
		return nil, err
	}
	ctx := contextID(r)
	addresses := []string{"/dns4/" + effectiveHost(r) + "/tcp/443/tls/http"}
	ad := &schema.Advertisement{Provider: p.String(), Addresses: addresses, Entries: entryLink, ContextID: ctx, Metadata: md, IsRm: false}
	addObj, addLink, err := signedAd(ad, k)
	if err != nil {
		return nil, err
	}
	rm := &schema.Advertisement{PreviousID: addLink, Provider: p.String(), Addresses: addresses, Entries: schema.NoEntries, ContextID: ctx, Metadata: md, IsRm: true}
	rmObj, rmLink, err := signedAd(rm, k)
	if err != nil {
		return nil, err
	}
	activeHead, err := signedHead(addLink.Cid, k)
	if err != nil {
		return nil, err
	}
	removalHead, err := signedHead(rmLink.Cid, k)
	if err != nil {
		return nil, err
	}
	addAnnounce, err := makeAnnouncement(addLink.Cid, p, effectiveHost(r))
	if err != nil {
		return nil, err
	}
	rmAnnounce, err := makeAnnouncement(rmLink.Cid, p, effectiveHost(r))
	if err != nil {
		return nil, err
	}
	b := &bundle{Version: 1, Request: r, ProviderID: p.String(), ContextID: ctx, ActiveHead: activeHead, RemovalHead: &removalHead, Objects: []object{entryObj, addObj, rmObj}, AddAnnouncement: addAnnounce, RemovalAnnouncement: &rmAnnounce, Reference: map[string]string{"goLibipni": "v0.9.0", "goLibp2p": "v0.50.0"}}
	if err := verifyBundle(b); err != nil {
		return nil, err
	}
	return b, nil
}

func samePublication(a, b request) bool {
	if a.RootCID != b.RootCID || a.ProviderID != b.ProviderID || effectiveHost(a) != effectiveHost(b) || len(a.BlockCIDs) != len(b.BlockCIDs) {
		return false
	}
	seen := make(map[string]bool, len(a.BlockCIDs))
	for _, c := range a.BlockCIDs {
		seen[c] = true
	}
	for _, c := range b.BlockCIDs {
		if !seen[c] {
			return false
		}
	}
	return true
}

func buildContinuousBundle(r request, k crypto.PrivKey, previous *bundle) (*bundle, error) {
	entries, err := validateRequest(r)
	if err != nil {
		return nil, err
	}
	if k.Type() != crypto.Ed25519 {
		return nil, errors.New("dedicated Ed25519 provider key required")
	}
	p, err := peer.IDFromPrivateKey(k)
	if err != nil || p.String() != r.ProviderID {
		return nil, errors.New("provider key does not match approved identity")
	}
	ctx := contextID(r)
	metadataValue := metadata.Default.New(&metadata.IpfsGatewayHttp{})
	md, err := metadataValue.MarshalBinary()
	if err != nil {
		return nil, err
	}
	addresses := []string{"/dns4/" + effectiveHost(r) + "/tcp/443/tls/http"}
	objects := make([]object, 0, 8)
	known := map[string]bool{}
	appendObject := func(o object) {
		if !known[o.CID] {
			known[o.CID] = true
			objects = append(objects, o)
		}
	}
	var priorProof *predecessor
	var previousLink ipld.Link
	if previous != nil {
		if err := verifyBundle(previous); err != nil {
			return nil, fmt.Errorf("previous public bundle: %w", err)
		}
		if !samePublication(r, previous.Request) || bytes.Equal(ctx, previous.ContextID) {
			return nil, errors.New("migration requires the same publication, provider and host, with a fresh continuous context")
		}
		for _, o := range previous.Objects {
			appendObject(o)
		}
		var retirementCID string
		if previous.RemovalHead != nil {
			// The existing finite removal is already signed, references the old
			// addition and removes only the old context. Reuse its exact CID.
			retirementCID = previous.RemovalHead.CID
		} else {
			// A later continuous update creates one retirement bridge, rather
			// than publishing a second unlinked genesis advertisement.
			rm := &schema.Advertisement{PreviousID: cidlink.Link{Cid: cid.MustParse(previous.ActiveHead.CID)}, Provider: p.String(), Addresses: addresses, Entries: schema.NoEntries, ContextID: previous.ContextID, Metadata: md, IsRm: true}
			o, link, err := signedAd(rm, k)
			if err != nil {
				return nil, err
			}
			appendObject(o)
			retirementCID = link.Cid.String()
		}
		previousLink = cidlink.Link{Cid: cid.MustParse(retirementCID)}
		priorProof = &predecessor{Request: previous.Request, ContextID: previous.ContextID, ActiveHead: previous.ActiveHead, RetirementCID: retirementCID}
	}
	chunk := schema.EntryChunk{Entries: entries}
	n, err := chunk.ToNode()
	if err != nil {
		return nil, err
	}
	entryObj, entryLink, err := encodeObject(n)
	if err != nil {
		return nil, err
	}
	appendObject(entryObj)
	ad := &schema.Advertisement{PreviousID: previousLink, Provider: p.String(), Addresses: addresses, Entries: entryLink, ContextID: ctx, Metadata: md, IsRm: false}
	addObj, addLink, err := signedAd(ad, k)
	if err != nil {
		return nil, err
	}
	appendObject(addObj)
	if len(objects) > 64 {
		return nil, errors.New("retained advertisement history exceeds 64 objects")
	}
	activeHead, err := signedHead(addLink.Cid, k)
	if err != nil {
		return nil, err
	}
	addAnnounce, err := makeAnnouncement(addLink.Cid, p, effectiveHost(r))
	if err != nil {
		return nil, err
	}
	b := &bundle{Version: 2, Request: r, ProviderID: p.String(), ContextID: ctx, ActiveHead: activeHead, Objects: objects, AddAnnouncement: addAnnounce, Reference: map[string]string{"goLibipni": "v0.9.0", "goLibp2p": "v0.50.0"}, Predecessor: priorProof}
	if err := verifyBundle(b); err != nil {
		return nil, err
	}
	return b, nil
}

func publicObjects(values []object) (map[string]object, error) {
	if len(values) < 2 || len(values) > 64 {
		return nil, errors.New("public sync object set exceeds bound")
	}
	objects := make(map[string]object, len(values))
	for _, o := range values {
		c, err := cid.Decode(o.CID)
		if err != nil || c.Version() != 1 || c.String() != o.CID || c.Prefix().Codec != cid.DagCBOR || c.Prefix().MhType != multihash.SHA2_256 || c.Prefix().MhLength != 32 || o.ContentType != "application/vnd.ipld.dag-cbor" || len(o.Body) > 16384 {
			return nil, errors.New("invalid public sync object")
		}
		actual, err := c.Prefix().Sum(o.Body)
		if err != nil || !actual.Equals(c) {
			return nil, errors.New("public sync object CID mismatch")
		}
		if _, exists := objects[o.CID]; exists {
			return nil, errors.New("duplicate public sync object")
		}
		objects[o.CID] = o
	}
	return objects, nil
}

func verifyHead(h object, provider string) error {
	if h.ContentType != "application/vnd.ipld.dag-json" || len(h.Body) > 16384 {
		return errors.New("head must be bounded reference DAG-JSON")
	}
	sh, err := head.Decode(bytes.NewReader(h.Body))
	if err != nil {
		return errors.New("invalid signed head encoding")
	}
	p, err := sh.Validate()
	if err != nil || p.String() != provider || sh.Topic == nil || *sh.Topic != topic || sh.Head.String() != h.CID {
		return errors.New("signed head identity, topic or signature mismatch")
	}
	canonical, err := sh.Encode()
	if err != nil || !bytes.Equal(canonical, h.Body) {
		return errors.New("noncanonical reference signed head")
	}
	return nil
}

func readAdvertisement(o object, r request) (*schema.Advertisement, error) {
	ad, err := schema.BytesToAdvertisement(cid.MustParse(o.CID), o.Body)
	if err != nil {
		return nil, err
	}
	if _, ok := ad.Entries.(cidlink.Link); !ok {
		return nil, errors.New("advertisement entries must be a CID link")
	}
	p, err := ad.VerifySignature()
	if err != nil || p.String() != r.ProviderID || ad.Provider != r.ProviderID {
		return nil, errors.New("advertisement signature or provider mismatch")
	}
	if err := ad.Validate(); err != nil {
		return nil, err
	}
	n, err := ad.ToNode()
	if err != nil {
		return nil, err
	}
	canonical, _, err := encodeObject(n)
	if err != nil || canonical.CID != o.CID || !bytes.Equal(canonical.Body, o.Body) {
		return nil, errors.New("noncanonical reference advertisement")
	}
	metadataValue := metadata.Default.New(&metadata.IpfsGatewayHttp{})
	md, err := metadataValue.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if len(ad.Addresses) != 1 || ad.Addresses[0] != "/dns4/"+effectiveHost(r)+"/tcp/443/tls/http" || !bytes.Equal(ad.Metadata, md) || len(ad.ContextID) != sha256.Size || ad.ExtendedProvider != nil {
		return nil, errors.New("advertisement policy mismatch")
	}
	return &ad, nil
}

func readEntryChunk(o object) (*schema.EntryChunk, error) {
	chunk, err := schema.BytesToEntryChunk(cid.MustParse(o.CID), o.Body)
	if err != nil || chunk.Next != nil || len(chunk.Entries) < 1 || len(chunk.Entries) > maxBlocks {
		return nil, errors.New("invalid bounded EntryChunk")
	}
	n, err := chunk.ToNode()
	if err != nil {
		return nil, err
	}
	canonical, _, err := encodeObject(n)
	if err != nil || canonical.CID != o.CID || !bytes.Equal(canonical.Body, o.Body) {
		return nil, errors.New("noncanonical reference EntryChunk")
	}
	return &chunk, nil
}

func exactEntries(actual, expected []multihash.Multihash) bool {
	if len(actual) != len(expected) {
		return false
	}
	for i, e := range expected {
		if !bytes.Equal(e, actual[i]) {
			return false
		}
	}
	return true
}

func sameEntries(actual, expected []multihash.Multihash) bool {
	if len(actual) != len(expected) {
		return false
	}
	seen := map[string]bool{}
	for _, e := range expected {
		seen[string(e)] = true
	}
	for _, e := range actual {
		if !seen[string(e)] {
			return false
		}
		delete(seen, string(e))
	}
	return len(seen) == 0
}

func verifyAnnouncement(a announcement, h object, r request) error {
	var m message.Message
	if a.ContentType != "application/json" || len(a.Body) > 16384 || json.Unmarshal(a.Body, &m) != nil || a.AdCID != h.CID || m.Cid.String() != h.CID || len(m.ExtraData) != 0 || m.OrigPeer != "" {
		return errors.New("invalid reference announce message")
	}
	addresses, err := m.GetAddrs()
	if err != nil || len(addresses) != 1 || addresses[0].String() != "/dns4/"+effectiveHost(r)+"/tcp/443/tls/http/p2p/"+r.ProviderID {
		return errors.New("announce publisher address mismatch")
	}
	canonical, err := json.Marshal(m)
	if err != nil || !bytes.Equal(canonical, a.Body) {
		return errors.New("noncanonical announce JSON")
	}
	return nil
}

func verifyContinuousBundle(b *bundle) error {
	entries, err := validateRequest(b.Request)
	if err != nil {
		return err
	}
	if b.Version != 2 || b.Request.ServingMode != "continuous" || b.Request.ExpiresAt != nil || b.RemovalHead != nil || b.RemovalAnnouncement != nil || b.ProviderID != b.Request.ProviderID || !bytes.Equal(b.ContextID, contextID(b.Request)) {
		return errors.New("continuous identity, context or removal policy mismatch")
	}
	if len(b.Reference) != 2 || b.Reference["goLibipni"] != "v0.9.0" || b.Reference["goLibp2p"] != "v0.50.0" {
		return errors.New("pinned reference versions mismatch")
	}
	objects, err := publicObjects(b.Objects)
	if err != nil {
		return err
	}
	if err := verifyHead(b.ActiveHead, b.ProviderID); err != nil {
		return err
	}
	if err := verifyAnnouncement(b.AddAnnouncement, b.ActiveHead, b.Request); err != nil {
		return err
	}
	var priorEntries []multihash.Multihash
	if b.Predecessor != nil {
		prior := b.Predecessor
		priorEntries, err = validateRequest(prior.Request)
		if err != nil || !samePublication(b.Request, prior.Request) || !bytes.Equal(prior.ContextID, contextID(prior.Request)) || bytes.Equal(prior.ContextID, b.ContextID) {
			return errors.New("predecessor publication or context mismatch")
		}
		if err := verifyHead(prior.ActiveHead, b.ProviderID); err != nil {
			return err
		}
		if prior.ActiveHead.CID == b.ActiveHead.CID || prior.RetirementCID == prior.ActiveHead.CID {
			return errors.New("invalid predecessor retirement link")
		}
	}
	// Traverse the complete flat chain newest-to-oldest. Every retirement must
	// remove the immediately older addition's context, never the newer context.
	// The signed current head commits to these CID links and exact object bytes.
	used := map[string]bool{}
	contexts := map[string]bool{}
	next := b.ActiveHead.CID
	expectAddition := true
	var removalContext []byte
	var newerContext []byte
	position := 0
	for next != "" {
		if used[next] || position >= 64 {
			return errors.New("cyclic or oversized advertisement history")
		}
		o, exists := objects[next]
		if !exists {
			return errors.New("advertisement history object not served")
		}
		used[next] = true
		ad, err := readAdvertisement(o, b.Request)
		if err != nil {
			return err
		}
		if expectAddition {
			if ad.IsRm || contexts[string(ad.ContextID)] || (removalContext != nil && !bytes.Equal(ad.ContextID, removalContext)) {
				return errors.New("historical addition context or retirement ordering mismatch")
			}
			contexts[string(ad.ContextID)] = true
			entryObj, exists := objects[ad.Entries.String()]
			if !exists {
				return errors.New("advertised EntryChunk not served")
			}
			chunk, err := readEntryChunk(entryObj)
			if err != nil || !sameEntries(chunk.Entries, entries) {
				return errors.New("historical EntryChunk differs from the exact publication")
			}
			used[entryObj.CID] = true
			if position == 0 {
				if !bytes.Equal(ad.ContextID, b.ContextID) || !exactEntries(chunk.Entries, entries) {
					return errors.New("current addition request mismatch")
				}
				if b.Predecessor == nil && ad.PreviousID != nil || b.Predecessor != nil && (ad.PreviousID == nil || ad.PreviousID.String() != b.Predecessor.RetirementCID) {
					return errors.New("current addition predecessor mismatch")
				}
			}
			if position == 2 && b.Predecessor != nil {
				if next != b.Predecessor.ActiveHead.CID || !bytes.Equal(ad.ContextID, b.Predecessor.ContextID) || !exactEntries(chunk.Entries, priorEntries) {
					return errors.New("predecessor addition request mismatch")
				}
			}
			newerContext = ad.ContextID
		} else {
			link, ok := ad.Entries.(cidlink.Link)
			if !ad.IsRm || !ok || !link.Cid.Equals(schema.NoEntries.Cid) || ad.PreviousID == nil || bytes.Equal(ad.ContextID, newerContext) {
				return errors.New("retirement must remove only the older context using NoEntries")
			}
			if position == 1 && b.Predecessor != nil && (next != b.Predecessor.RetirementCID || ad.PreviousID.String() != b.Predecessor.ActiveHead.CID || !bytes.Equal(ad.ContextID, b.Predecessor.ContextID)) {
				return errors.New("predecessor retirement context or link mismatch")
			}
			removalContext = ad.ContextID
		}
		if ad.PreviousID == nil {
			if !expectAddition {
				return errors.New("advertisement history ends in a retirement")
			}
			next = ""
		} else {
			next = ad.PreviousID.String()
		}
		expectAddition = !expectAddition
		position++
	}
	if b.Predecessor != nil && position < 3 || len(used) != len(objects) {
		return errors.New("incomplete predecessor chain or extra public sync objects")
	}
	return nil
}

// verifyBundle checks actual reference-library signatures plus our narrower
// request-bound root, hostname, provider, context, metadata and linked removal.
func verifyBundle(b *bundle) error {
	if b == nil {
		return errors.New("missing public bundle")
	}
	if b.Version == 2 {
		return verifyContinuousBundle(b)
	}
	return verifyFiniteBundle(b)
}

func verifyFiniteBundle(b *bundle) error {
	entries, err := validateRequest(b.Request)
	if err != nil {
		return err
	}
	if b.Version != 1 || b.Request.ServingMode == "continuous" || b.Predecessor != nil || b.RemovalHead == nil || b.RemovalAnnouncement == nil || b.ProviderID != b.Request.ProviderID || !bytes.Equal(b.ContextID, contextID(b.Request)) || len(b.Objects) != 3 {
		return errors.New("bundle identity, context or object set mismatch")
	}
	if len(b.Reference) != 2 || b.Reference["goLibipni"] != "v0.9.0" || b.Reference["goLibp2p"] != "v0.50.0" {
		return errors.New("pinned reference versions mismatch")
	}
	objects := map[string]object{}
	for _, o := range b.Objects {
		c, err := cid.Decode(o.CID)
		if err != nil || c.Version() != 1 || c.String() != o.CID || c.Prefix().Codec != cid.DagCBOR || c.Prefix().MhType != multihash.SHA2_256 || c.Prefix().MhLength != 32 || o.ContentType != "application/vnd.ipld.dag-cbor" || len(o.Body) > 16384 {
			return errors.New("invalid public sync object")
		}
		actual, err := c.Prefix().Sum(o.Body)
		if err != nil || !actual.Equals(c) {
			return errors.New("public sync object CID mismatch")
		}
		if _, exists := objects[o.CID]; exists {
			return errors.New("duplicate public sync object")
		}
		objects[o.CID] = o
	}
	adCIDs := []string{b.ActiveHead.CID, b.RemovalHead.CID}
	var add schema.Advertisement
	metadataValue := metadata.Default.New(&metadata.IpfsGatewayHttp{})
	md, err := metadataValue.MarshalBinary()
	if err != nil {
		return err
	}
	for i, h := range []object{b.ActiveHead, *b.RemovalHead} {
		if h.ContentType != "application/vnd.ipld.dag-json" || len(h.Body) > 16384 {
			return errors.New("head must be reference DAG-JSON")
		}
		sh, err := head.Decode(bytes.NewReader(h.Body))
		if err != nil {
			return errors.New("invalid signed head encoding")
		}
		p, err := sh.Validate()
		if err != nil || p.String() != b.ProviderID || sh.Topic == nil || *sh.Topic != topic || sh.Head.String() != h.CID {
			return errors.New("signed head identity, topic or signature mismatch")
		}
		canonicalHead, err := sh.Encode()
		if err != nil || !bytes.Equal(canonicalHead, h.Body) {
			return errors.New("noncanonical reference signed head")
		}
		o, exists := objects[h.CID]
		if !exists {
			return errors.New("head advertisement not served")
		}
		ad, err := schema.BytesToAdvertisement(cid.MustParse(h.CID), o.Body)
		if err != nil {
			return err
		}
		p, err = ad.VerifySignature()
		if err != nil || p.String() != b.ProviderID || ad.Provider != b.ProviderID {
			return errors.New("advertisement signature or provider mismatch")
		}
		if err := ad.Validate(); err != nil {
			return err
		}
		adNode, err := ad.ToNode()
		if err != nil {
			return err
		}
		canonicalAd, _, err := encodeObject(adNode)
		if err != nil || canonicalAd.CID != o.CID || !bytes.Equal(canonicalAd.Body, o.Body) {
			return errors.New("noncanonical reference advertisement")
		}
		if len(ad.Addresses) != 1 || ad.Addresses[0] != "/dns4/"+effectiveHost(b.Request)+"/tcp/443/tls/http" || !bytes.Equal(ad.Metadata, md) || !bytes.Equal(ad.ContextID, b.ContextID) || ad.ExtendedProvider != nil {
			return errors.New("advertisement policy mismatch")
		}
		if i == 0 {
			if ad.IsRm || ad.PreviousID != nil {
				return errors.New("invalid initial addition")
			}
			add = ad
		} else {
			entriesLink, isCID := ad.Entries.(cidlink.Link)
			if !ad.IsRm || ad.PreviousID == nil || ad.PreviousID.String() != b.ActiveHead.CID || !isCID || !entriesLink.Cid.Equals(schema.NoEntries.Cid) {
				return errors.New("removal must be contextual, linked and NoEntries")
			}
		}
	}
	entryObj, exists := objects[add.Entries.String()]
	if !exists {
		return errors.New("advertised EntryChunk not served")
	}
	chunk, err := schema.BytesToEntryChunk(cid.MustParse(entryObj.CID), entryObj.Body)
	if err != nil || chunk.Next != nil || len(chunk.Entries) != len(entries) {
		return errors.New("EntryChunk must contain the exact request multihashes")
	}
	chunkNode, err := chunk.ToNode()
	if err != nil {
		return err
	}
	canonicalChunk, _, err := encodeObject(chunkNode)
	if err != nil || canonicalChunk.CID != entryObj.CID || !bytes.Equal(canonicalChunk.Body, entryObj.Body) {
		return errors.New("noncanonical reference EntryChunk")
	}
	for i, e := range entries {
		if !bytes.Equal(e, chunk.Entries[i]) {
			return errors.New("content multihash mismatch")
		}
	}
	for i, a := range []announcement{b.AddAnnouncement, *b.RemovalAnnouncement} {
		var m message.Message
		if a.ContentType != "application/json" || json.Unmarshal(a.Body, &m) != nil || a.AdCID != adCIDs[i] || m.Cid.String() != a.AdCID || len(m.ExtraData) != 0 || m.OrigPeer != "" {
			return errors.New("invalid reference announce message")
		}
		as, err := m.GetAddrs()
		if err != nil || len(as) != 1 || as[0].String() != "/dns4/"+effectiveHost(b.Request)+"/tcp/443/tls/http/p2p/"+b.ProviderID {
			return errors.New("announce publisher address mismatch")
		}
		canonical, err := json.Marshal(m)
		if err != nil || !bytes.Equal(canonical, a.Body) {
			return errors.New("noncanonical announce JSON")
		}
	}
	return nil
}

func run() error {
	keyPath := flag.String("key", "", "private libp2p protobuf key file; never emitted")
	verify := flag.Bool("verify", false, "verify public bundle from stdin; no private key")
	flag.Parse()
	input, err := io.ReadAll(io.LimitReader(os.Stdin, 131073))
	if err != nil || len(input) > 131072 {
		return errors.New("input exceeds 128 KiB")
	}
	if *verify {
		if *keyPath != "" {
			return errors.New("verification must not receive a private key")
		}
		var b bundle
		if err := json.Unmarshal(input, &b); err != nil {
			return errors.New("invalid public bundle JSON")
		}
		if err := verifyBundle(&b); err != nil {
			return err
		}
		var removalCID any
		if b.RemovalHead != nil {
			removalCID = b.RemovalHead.CID
		}
		mode := b.Request.ServingMode
		if mode == "" {
			mode = "finite"
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"verified": true, "providerId": b.ProviderID, "providerHost": effectiveHost(b.Request), "entryCount": len(b.Request.BlockCIDs), "addCid": b.ActiveHead.CID, "removalCid": removalCID, "servingMode": mode, "expiresAt": b.Request.ExpiresAt})
	}
	var r request
	var envelope buildInput
	if err := json.Unmarshal(input, &envelope); err != nil {
		return errors.New("invalid public build request")
	}
	if envelope.Request != nil {
		r = *envelope.Request
	} else if envelope.PreviousBundle != nil {
		return errors.New("previousBundle requires a request envelope")
	} else if err := json.Unmarshal(input, &r); err != nil {
		return errors.New("invalid public build request")
	}
	if _, err := validateRequest(r); err != nil {
		return err
	}
	if envelope.PreviousBundle != nil {
		if err := verifyBundle(envelope.PreviousBundle); err != nil {
			return fmt.Errorf("previous public bundle: %w", err)
		}
		if r.ServingMode != "continuous" || !samePublication(r, envelope.PreviousBundle.Request) || bytes.Equal(contextID(r), envelope.PreviousBundle.ContextID) {
			return errors.New("migration requires the same publication, provider and host, with a fresh continuous context")
		}
	}
	info, err := os.Lstat(*keyPath)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 || info.Mode().Perm()&0077 != 0 {
		return errors.New("key must be a private regular file, at most 4 KiB, without group/other permissions")
	}
	kb, err := os.ReadFile(*keyPath)
	if err != nil {
		return errors.New("cannot read provider key")
	}
	k, err := crypto.UnmarshalPrivateKey(kb)
	clear(kb)
	if err != nil {
		return errors.New("invalid libp2p private key")
	}
	b, err := buildBundle(r, k, envelope.PreviousBundle)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(b)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "IPNI bundle:", err)
		os.Exit(1)
	}
}
