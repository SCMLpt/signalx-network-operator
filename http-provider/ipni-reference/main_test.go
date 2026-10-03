package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"testing"
	"time"

	"github.com/ipfs/go-cid"
	cidlink "github.com/ipld/go-ipld-prime/linking/cid"
	"github.com/ipld/go-ipld-prime/storage/memstore"
	selectorparse "github.com/ipld/go-ipld-prime/traversal/selector/parse"
	"github.com/ipni/go-libipni/dagsync/ipnisync"
	"github.com/ipni/go-libipni/dagsync/ipnisync/head"
	"github.com/ipni/go-libipni/ingest/schema"
	"github.com/ipni/go-libipni/maurl"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/multiformats/go-multihash"
)

const rootCID = "bafybeianebwhw4uzkqnaekl5kyoau7hubxaens7azrftgqtz2mccciejle"

func timestamp(value string) *string { return &value }

func fixture(t *testing.T) (*bundle, crypto.PrivKey) {
	t.Helper()
	// Fresh ephemeral identity exists in memory only. No private key is a fixture,
	// written to disk, included in the public bundle, or used for an announcement.
	k, _, err := crypto.GenerateEd25519Key(nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := peer.IDFromPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	r := request{RootCID: rootCID, ProviderID: p.String(), ActivatedAt: "2026-10-03T09:50:00.370Z", ExpiresAt: timestamp("2026-10-10T09:50:00.370Z"), BlockCIDs: []string{
		rootCID,
		"bafkreiauikfcizmttxtlpn6yafmwbsnldv6nncnd766bvlpfash5sq3esq",
		"bafkreiczuc5w3fp5kxfls44jxrpwsx6jzzqrgha3pldjnzf5wpyxjbr7yi",
		"bafkreic2wxszhkrbme2urvplgm5yt2zyitek5m3nmimde5vhzpogqmaaym",
		"bafkreiaikqu4umpoxeeolgojxzhivj5cyrrmiwvadjrwyqtqmwodovesfa",
	}}
	b, err := buildBundle(r, k)
	if err != nil {
		t.Fatal(err)
	}
	return b, k
}

func clone(t *testing.T, b *bundle) *bundle {
	t.Helper()
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	var c bundle
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return &c
}

func TestReferencePublicBundle(t *testing.T) {
	b, k := fixture(t)
	if err := verifyBundle(b); err != nil {
		t.Fatal(err)
	}
	if b.ActiveHead.CID == b.RemovalHead.CID {
		t.Fatal("removal must be a separate signed advertisement")
	}
	for _, h := range []object{b.ActiveHead, *b.RemovalHead} {
		sh, err := head.Decode(bytes.NewReader(h.Body))
		if err != nil {
			t.Fatal(err)
		}
		p, err := sh.Validate()
		if err != nil || p.String() != b.ProviderID {
			t.Fatal("reference head did not verify")
		}
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes, err := crypto.MarshalPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, keyBytes) {
		t.Fatal("private key escaped into public bundle")
	}
	if bytes.Contains(raw, []byte("privateKey")) {
		t.Fatal("private key field in public bundle")
	}
	if err := verifyBundle(clone(t, b)); err != nil {
		t.Fatal(err)
	}
}

func TestTamperedPublicBundlesRejected(t *testing.T) {
	b, _ := fixture(t)
	cases := map[string]func(*bundle){
		"object bytes":    func(b *bundle) { b.Objects[0].Body[0] ^= 1 },
		"head bytes":      func(b *bundle) { b.ActiveHead.Body[20] ^= 1 },
		"provider":        func(b *bundle) { b.ProviderID = "wrong" },
		"context":         func(b *bundle) { b.ContextID[0] ^= 1 },
		"removal link":    func(b *bundle) { b.RemovalHead.CID = b.ActiveHead.CID },
		"announce":        func(b *bundle) { b.AddAnnouncement.Body[10] ^= 1 },
		"missing entries": func(b *bundle) { b.Objects = b.Objects[1:] },
		"long term":       func(b *bundle) { b.Request.ExpiresAt = timestamp("2026-10-11T09:50:00.370Z") },
		"hostname":        func(b *bundle) { b.Request.ProviderHost = "another-ipfs-provider.kamuitranslator.workers.dev" },
		"entry CID": func(b *bundle) {
			b.Request.BlockCIDs[1], b.Request.BlockCIDs[2] = b.Request.BlockCIDs[2], b.Request.BlockCIDs[1]
		},
		"entry removed": func(b *bundle) { b.Request.BlockCIDs = b.Request.BlockCIDs[:4] },
		"reference":     func(b *bundle) { b.Reference["goLibipni"] = "other" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := clone(t, b)
			mutate(c)
			if verifyBundle(c) == nil {
				t.Fatal("tampered bundle accepted")
			}
		})
	}
}

func TestPortableRootHostnameAndEntryBounds(t *testing.T) {
	b, k := fixture(t)
	for _, count := range []int{1, 25, 64} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			r := b.Request
			r.ProviderHost = "another-ipfs-provider.kamuitranslator.workers.dev"
			r.BlockCIDs = nil
			for i := range count {
				c, err := (cid.Prefix{Version: 1, Codec: cid.Raw, MhType: multihash.SHA2_256, MhLength: 32}).Sum([]byte(fmt.Sprintf("portable graph block %d", i)))
				if err != nil {
					t.Fatal(err)
				}
				r.BlockCIDs = append(r.BlockCIDs, c.String())
			}
			r.RootCID = r.BlockCIDs[0]
			actual, err := buildBundle(r, k)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyBundle(clone(t, actual)); err != nil {
				t.Fatal(err)
			}
			for _, h := range []object{actual.ActiveHead, *actual.RemovalHead} {
				var adObject object
				for _, o := range actual.Objects {
					if o.CID == h.CID {
						adObject = o
					}
				}
				ad, err := schema.BytesToAdvertisement(cid.MustParse(h.CID), adObject.Body)
				if err != nil || len(ad.Addresses) != 1 || ad.Addresses[0] != "/dns4/"+r.ProviderHost+"/tcp/443/tls/http" {
					t.Fatal("signed address did not use supplied hostname")
				}
			}
			bad := clone(t, actual)
			bad.Request.ProviderHost = historicalProviderHost
			if verifyBundle(bad) == nil {
				t.Fatal("changed request hostname accepted")
			}
		})
	}
	for _, count := range []int{0, 65} {
		r := b.Request
		r.BlockCIDs = make([]string, count)
		if _, err := validateRequest(r); err == nil {
			t.Fatal("entry count outside bounds accepted")
		}
	}
	for _, host := range []string{"https://provider.org", "provider.org:443", "127.0.0.1", "Provider.org", "provider.local", "provider.test", "provider.example.org", "provider.org.", "-provider.org", "provider..org"} {
		r := b.Request
		r.ProviderHost = host
		if _, err := validateRequest(r); err == nil {
			t.Fatalf("nonpublic or noncanonical host accepted: %s", host)
		}
	}
}

func TestForgedAdRejectedAfterCIDRecomputed(t *testing.T) {
	b, _ := fixture(t)
	o := b.Objects[1]
	ad, err := schema.BytesToAdvertisement(cid.MustParse(o.CID), o.Body)
	if err != nil {
		t.Fatal(err)
	}
	ad.Addresses[0] = "/dns4/forged.example/tcp/443/tls/http"
	// Recompute the object's CID so rejection must come from the actual reference
	// signature check, rather than a trivial content hash mismatch.
	n, err := ad.ToNode()
	if err != nil {
		t.Fatal(err)
	}
	forged, c, err := encodeObject(n)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := schema.BytesToAdvertisement(c.Cid, forged.Body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parsed.VerifySignature(); err == nil {
		t.Fatal("reference accepted changed signed address")
	}
}

func TestRequestAndKeyBoundaries(t *testing.T) {
	b, _ := fixture(t)
	r := b.Request
	for _, duration := range []time.Duration{0, -time.Second, 7*24*time.Hour + time.Millisecond} {
		bad := r
		start, _ := time.Parse(time.RFC3339Nano, r.ActivatedAt)
		bad.ExpiresAt = timestamp(start.Add(duration).Format(time.RFC3339Nano))
		if _, err := validateRequest(bad); err == nil {
			t.Fatal("invalid term accepted")
		}
	}
	other, _, err := crypto.GenerateEd25519Key(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := buildBundle(r, other); err == nil {
		t.Fatal("different provider key accepted")
	}
	r.BlockCIDs = append([]string(nil), r.BlockCIDs...)
	r.BlockCIDs[1] = r.BlockCIDs[0]
	if _, err := validateRequest(r); err == nil {
		t.Fatal("duplicate multihash accepted")
	}
}

func TestContinuousMigrationRetiresOnlyThePredecessorContext(t *testing.T) {
	prior, key := fixture(t)
	r := prior.Request
	r.ProviderHost = historicalProviderHost
	r.ServingMode = "continuous"
	r.ExpiresAt = nil
	current, err := buildBundle(r, key, prior)
	if err != nil {
		t.Fatal(err)
	}
	if current.Version != 2 || current.RemovalHead != nil || current.RemovalAnnouncement != nil || current.Predecessor == nil || current.Predecessor.RetirementCID != prior.RemovalHead.CID || bytes.Equal(current.ContextID, prior.ContextID) {
		t.Fatal("continuous migration policy or retirement mismatch")
	}
	if err := verifyBundle(clone(t, current)); err != nil {
		t.Fatal(err)
	}
	objects := map[string]object{}
	for _, o := range current.Objects {
		objects[o.CID] = o
	}
	for _, old := range prior.Objects {
		if !bytes.Equal(objects[old.CID].Body, old.Body) {
			t.Fatal("historical exact sync object lost")
		}
	}
	bridge, err := readAdvertisement(objects[prior.RemovalHead.CID], r)
	if err != nil || !bridge.IsRm || !bytes.Equal(bridge.ContextID, prior.ContextID) || bytes.Equal(bridge.ContextID, current.ContextID) || bridge.PreviousID.String() != prior.ActiveHead.CID {
		t.Fatal("delayed old removal can affect the new context, or predecessor link is wrong")
	}
	r.ActivatedAt = "2026-10-03T09:51:00.370Z"
	later, err := buildBundle(r, key, current)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyBundle(clone(t, later)); err != nil {
		t.Fatal(err)
	}
	if later.Predecessor.ActiveHead.CID != current.ActiveHead.CID || bytes.Equal(later.ContextID, current.ContextID) {
		t.Fatal("later update did not extend the same identity chain with a fresh context")
	}
	if _, err := buildBundle(r, key, later); err == nil {
		t.Fatal("reusing the same continuous context accepted")
	}
	for name, mutate := range map[string]func(*bundle){
		"expiry":              func(b *bundle) { b.Request.ExpiresAt = timestamp("2026-10-10T09:50:00.370Z") },
		"mode":                func(b *bundle) { b.Request.ServingMode = "finite" },
		"scheduled removal":   func(b *bundle) { b.RemovalHead = prior.RemovalHead },
		"predecessor context": func(b *bundle) { b.Predecessor.ContextID = b.ContextID },
		"retirement CID":      func(b *bundle) { b.Predecessor.RetirementCID = prior.ActiveHead.CID },
		"predecessor head":    func(b *bundle) { b.Predecessor.ActiveHead = b.ActiveHead },
		"predecessor host": func(b *bundle) {
			b.Predecessor.Request.ProviderHost = "another-ipfs-provider.kamuitranslator.workers.dev"
		},
		"history missing": func(b *bundle) { b.Objects = b.Objects[1:] },
		"history changed": func(b *bundle) { b.Objects[0].Body[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := clone(t, current)
			mutate(bad)
			if verifyBundle(bad) == nil {
				t.Fatal("tampered continuous migration accepted")
			}
		})
	}
}

func TestContinuousGenesisAndExplicitFinitePolicy(t *testing.T) {
	prior, key := fixture(t)
	r := prior.Request
	r.ServingMode = "finite"
	finite, err := buildBundle(r, key)
	if err != nil || !bytes.Equal(finite.ContextID, prior.ContextID) {
		t.Fatal("explicit finite policy changed historical context")
	}
	r.ServingMode = "continuous"
	r.ProviderHost = historicalProviderHost
	r.ExpiresAt = nil
	genesis, err := buildBundle(r, key)
	if err != nil || verifyBundle(genesis) != nil || genesis.Predecessor != nil || len(genesis.Objects) != 2 {
		t.Fatal("continuous genesis did not verify")
	}
	for _, mode := range []string{"", "finite", "unknown"} {
		bad := r
		bad.ServingMode = mode
		if _, err := validateRequest(bad); err == nil {
			t.Fatal("implicit null or unknown serving mode accepted")
		}
	}
}

func TestOfficialHTTPSyncAcceptsExactCBORBodies(t *testing.T) {
	b, _ := fixture(t)
	objects := map[string]object{}
	for _, o := range b.Objects {
		objects[o.CID] = o
	}
	// A short-lived loopback test server only. No native libp2p host, public
	// listener, daemon, ingest request, or production provider key is involved.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ipni/v1/ad/head" {
			w.Header().Set("Content-Type", b.ActiveHead.ContentType)
			_, _ = w.Write(b.ActiveHead.Body)
			return
		}
		o, exists := objects[path.Base(r.URL.Path)]
		if !exists {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Accept") != "" {
			t.Error("reference SDK unexpectedly sent an Accept header")
		}
		w.Header().Set("Content-Type", o.ContentType)
		_, _ = w.Write(o.Body)
	}))
	defer server.Close()
	ls := cidlink.DefaultLinkSystem()
	store := &memstore.Store{}
	ls.SetReadStorage(store)
	ls.SetWriteStorage(store)
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	a, err := maurl.FromURL(u)
	if err != nil {
		t.Fatal(err)
	}
	p, err := peer.Decode(b.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	syncer, err := ipnisync.NewSync(ls, nil).NewSyncer(peer.AddrInfo{ID: p, Addrs: []ma.Multiaddr{a}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	h, err := syncer.GetHead(ctx)
	if err != nil || h.String() != b.ActiveHead.CID {
		t.Fatalf("head fetch: %v", err)
	}
	for _, o := range b.Objects {
		c := cid.MustParse(o.CID)
		if err := syncer.Sync(ctx, c, selectorparse.CommonSelector_MatchPoint); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(store.Bag[c.KeyString()], o.Body) {
			t.Fatal("SDK did not store exact CID-bound CBOR bytes")
		}
	}
}
