package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
)

// harnessParty is a party the suite plays whose documents a deployed server
// may fetch: its metadata at issuer/.well-known/document and the JWKS that
// names. Parties sharing an issuer share one JWKS holding every party's keys.
// A party with no document only reserves its name on the suite's listener,
// for a role that serves it per case through Harness.Handle.
type harnessParty struct {
	issuer, document string
	keys             keySet
	// metadata adds members to the metadata document.
	metadata map[string]any
}

// party returns a fixture party signing with one seed.
func party(issuer, document, seed, kid string) harnessParty {
	return harnessParty{issuer: issuer, document: document, keys: fixtureKeys(seed, kid)}
}

// harnessParties lists every party any remote role has the suite play: the
// fixture's Agent Provider, Resource and Person Server, then each registered
// remote driver's own parties. They keep their fixture names in remote mode,
// so a deployment reaches them by routing those names to the suite.
func harnessParties(f Fixture) []harnessParty {
	parties := []harnessParty{party(f.Issuer, "aauth-agent.json", f.APSeed, f.Kid)}
	if p := f.Person; p != nil {
		parties = append(parties,
			party(f.Origin, "aauth-resource.json", p.ResourceSeed, p.ResourceKid),
			party(p.Issuer, "aauth-person.json", p.Seed, p.Kid))
	}
	roles := make([]string, 0, len(remoteDrivers))
	for role := range remoteDrivers {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	for _, role := range roles {
		if extra := remoteDrivers[role].parties; extra != nil {
			parties = append(parties, extra(f)...)
		}
	}
	return parties
}

// HarnessNames lists the host names the suite serves in remote mode. The
// suite's certificate must cover all of them, and a deployment must route
// each to the suite's listener on port 443.
func HarnessNames(f Fixture) []string {
	names := []string{}
	for _, p := range harnessParties(f) {
		if u, err := url.Parse(p.issuer); err == nil && u.Hostname() != "" && !slices.Contains(names, u.Hostname()) {
			names = append(names, u.Hostname())
		}
	}
	sort.Strings(names)
	return names
}

// HarnessDocuments returns each harness party's metadata and JWKS by URL,
// for a deployment that pins its trust instead of discovering it.
func HarnessDocuments(f Fixture) map[string][]byte {
	metadata := map[string]map[string]any{}
	jwks := map[string][]any{}
	order := []string{}
	for _, p := range harnessParties(f) {
		if p.document == "" {
			continue
		}
		at := p.issuer + "/.well-known/" + p.document
		if metadata[at] == nil {
			metadata[at] = map[string]any{"issuer": p.issuer, "jwks_uri": p.issuer + "/.well-known/jwks.json"}
			order = append(order, at)
		}
		for name, value := range p.metadata {
			metadata[at][name] = value
		}
		kids := make([]string, 0, len(p.keys))
		for kid := range p.keys {
			kids = append(kids, kid)
		}
		sort.Strings(kids)
		set := p.issuer + "/.well-known/jwks.json"
		for _, kid := range kids {
			key := map[string]any{"kid": kid}
			for name, value := range p.keys[kid] {
				key[name] = value
			}
			if !slices.ContainsFunc(jwks[set], func(k any) bool { return k.(map[string]any)["kid"] == kid }) {
				jwks[set] = append(jwks[set], key)
			}
		}
	}
	documents := map[string][]byte{}
	for _, at := range order {
		documents[at], _ = json.Marshal(metadata[at])
	}
	for set, keys := range jwks {
		documents[set], _ = json.Marshal(map[string]any{"keys": keys})
	}
	return documents
}

// Harness serves the suite's parties on its HTTPS listener in remote mode:
// the fixed documents of HarnessDocuments, and the handlers a remote driver
// installs for one case, such as a per-case document or an endpoint that
// captures what a deployed server sends.
type Harness struct {
	documents map[string][]byte
	mu        sync.Mutex
	handlers  map[string]*harnessRoute
}

type harnessRoute struct{ handler http.Handler }

// NewHarness returns the harness for a suite fixture.
func NewHarness(f Fixture) *Harness {
	return &Harness{documents: HarnessDocuments(f), handlers: map[string]*harnessRoute{}}
}

// HarnessHandler serves HarnessDocuments, choosing the party by Host.
func HarnessHandler(f Fixture) http.Handler { return NewHarness(f) }

// Handle routes requests for target to handler until the returned function
// is called. target is an absolute HTTPS URL; one ending in "/" also covers
// every path below it. A handler takes precedence over the fixed documents,
// and the longest matching target wins.
func (h *Harness) Handle(target string, handler http.Handler) func() {
	h.mu.Lock()
	defer h.mu.Unlock()
	route := &harnessRoute{handler}
	h.handlers[target] = route
	return func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.handlers[target] == route {
			delete(h.handlers, target)
		}
	}
}

func (h *Harness) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	target := "https://" + r.Host + r.URL.Path
	h.mu.Lock()
	var handler http.Handler
	best := -1
	for prefix, route := range h.handlers {
		if (target == prefix || strings.HasSuffix(prefix, "/") && strings.HasPrefix(target, prefix)) && len(prefix) > best {
			handler, best = route.handler, len(prefix)
		}
	}
	h.mu.Unlock()
	if handler != nil {
		r.URL.Scheme, r.URL.Host = "https", r.Host
		handler.ServeHTTP(w, r)
		return
	}
	body, ok := h.documents[target]
	if !ok || r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprint(len(body)))
	w.Write(body)
}

// Inbound is one request a deployed server sent to the suite.
type Inbound struct {
	Method string      `json:"method"`
	URL    string      `json:"url"`
	Header http.Header `json:"headers"`
	Body   []byte      `json:"body,omitempty"`
}

// Capture installs a handler at target that records each request and
// answers it with respond. It returns the channel of recorded requests and
// the function that removes the handler.
func (h *Harness) Capture(target string, respond func(Inbound) (int, http.Header, []byte)) (<-chan Inbound, func()) {
	captured := make(chan Inbound, 16)
	remove := h.Handle(target, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 65536))
		in := Inbound{Method: r.Method, URL: r.URL.String(), Header: r.Header.Clone(), Body: body}
		in.Header.Set("Host", r.Host)
		status, header, reply := respond(in)
		select {
		case captured <- in:
		default:
		}
		for name, values := range header {
			w.Header()[name] = values
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(reply)))
		w.WriteHeader(status)
		io.Copy(w, bytes.NewReader(reply))
	}))
	return captured, remove
}

type harnessKey struct{}

// WithHarness returns a context whose remote runs install per-case handlers
// on h, the harness the suite's HTTPS listener serves.
func WithHarness(ctx context.Context, h *Harness) context.Context {
	return context.WithValue(ctx, harnessKey{}, h)
}

func harnessFrom(ctx context.Context) *Harness {
	h, _ := ctx.Value(harnessKey{}).(*Harness)
	return h
}
