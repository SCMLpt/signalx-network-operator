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
	ExpiresAt    string   `json:"expiresAt"`
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
	RemovalHead         object            `json:"removalHead"`
	Objects             []object          `json:"objects"`
	AddAnnouncement     announcement      `json:"addAnnouncement"`
	RemovalAnnouncement announcement      `json:"removalAnnouncement"`
	Reference           map[string]string `json:"reference"`
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
	end, err := time.Parse(time.RFC3339Nano, r.ExpiresAt)
	if err != nil || !end.After(start) || end.Sub(start) > 7*24*time.Hour {
		return nil, errors.New("term must be positive and at most seven days")
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
	d := sha256.Sum256([]byte("signalx-http-provider-v1\x00" + r.RootCID + "\x00" + r.ActivatedAt + "\x00" + r.ExpiresAt))
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

func buildBundle(r request, k crypto.PrivKey) (*bundle, error) {
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
	b := &bundle{Version: 1, Request: r, ProviderID: p.String(), ContextID: ctx, ActiveHead: activeHead, RemovalHead: removalHead, Objects: []object{entryObj, addObj, rmObj}, AddAnnouncement: addAnnounce, RemovalAnnouncement: rmAnnounce, Reference: map[string]string{"goLibipni": "v0.9.0", "goLibp2p": "v0.50.0"}}
	if err := verifyBundle(b); err != nil {
		return nil, err
	}
	return b, nil
}

// verifyBundle checks actual reference-library signatures plus our narrower
// request-bound root, hostname, provider, context, metadata and linked removal.
func verifyBundle(b *bundle) error {
	entries, err := validateRequest(b.Request)
	if err != nil {
		return err
	}
	if b.Version != 1 || b.ProviderID != b.Request.ProviderID || !bytes.Equal(b.ContextID, contextID(b.Request)) || len(b.Objects) != 3 {
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
	for i, h := range []object{b.ActiveHead, b.RemovalHead} {
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
	for i, a := range []announcement{b.AddAnnouncement, b.RemovalAnnouncement} {
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
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"verified": true, "providerId": b.ProviderID, "providerHost": effectiveHost(b.Request), "entryCount": len(b.Request.BlockCIDs), "addCid": b.ActiveHead.CID, "removalCid": b.RemovalHead.CID})
	}
	var r request
	if err := json.Unmarshal(input, &r); err != nil {
		return errors.New("invalid public build request")
	}
	if _, err := validateRequest(r); err != nil {
		return err
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
	b, err := buildBundle(r, k)
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
