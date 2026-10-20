// Package conformance runs wire assertions against Resource implementations.
package conformance

import (
	"encoding/json"
	"net/http"
)

type Fixture struct {
	Version   int    `json:"version"`
	ID        string `json:"id"`
	Now       int64  `json:"now"`
	Issuer    string `json:"issuer"`
	Origin    string `json:"origin"`
	Path      string `json:"path"`
	Kid       string `json:"kid"`
	Subject   string `json:"subject"`
	APSeed    string `json:"ap_seed_hex"`
	AgentSeed string `json:"agent_seed_hex"`
}
type TokenSpec struct {
	IATOffset int64 `json:"iat_offset"`
	EXPOffset int64 `json:"exp_offset"`
}
type RequestSpec struct {
	Method        string   `json:"method"`
	Path          string   `json:"path"`
	Proof         string   `json:"proof"`
	CreatedOffset int64    `json:"created_offset"`
	Covered       []string `json:"covered"`
	Tamper        bool     `json:"tamper_signature"`
}
type Scenario struct {
	Version    int         `json:"version"`
	ID         string      `json:"id"`
	Title      string      `json:"title"`
	Role       string      `json:"role_under_test"`
	Given      string      `json:"given"`
	Token      TokenSpec   `json:"token"`
	Request    RequestSpec `json:"request"`
	Assertions []Assertion `json:"assertions"`
}
type Assertion struct {
	ID     string          `json:"id"`
	Clause string          `json:"clause"`
	Kind   string          `json:"kind"`
	Header string          `json:"header,omitempty"`
	Member string          `json:"member,omitempty"`
	Equals json.RawMessage `json:"equals"`
}
type Source struct {
	ID     string `json:"id"`
	Commit string `json:"commit"`
	SHA256 string `json:"sha256"`
	URL    string `json:"url"`
}
type Clause struct {
	ID      string `json:"id"`
	Source  string `json:"source"`
	Section string `json:"section"`
	Anchor  string `json:"anchor"`
	Scope   string `json:"scope"`
}
type Catalog struct {
	Version int      `json:"version"`
	Sources []Source `json:"sources"`
	Clauses []Clause `json:"clauses"`
}
type Suite struct {
	Fixture   Fixture
	Catalog   Catalog
	Scenarios []Scenario
	Digest    string
}
type Target struct {
	ID       string   `json:"id"`
	Revision string   `json:"revision"`
	Command  []string `json:"command"`
	Claims   []string `json:"claims"`
}
type Targets struct {
	Version         int      `json:"version"`
	Implementations []Target `json:"implementations"`
}
type Bootstrap struct {
	Version     int    `json:"version"`
	Now         int64  `json:"now"`
	Issuer      string `json:"issuer"`
	Resource    string `json:"resource"`
	APTransport string `json:"ap_transport"`
}
type Ready struct {
	Version int    `json:"version"`
	URL     string `json:"url"`
}
type Response struct {
	Status int         `json:"status"`
	Header http.Header `json:"headers"`
	Body   []byte      `json:"body_base64"`
}
type Result struct {
	Assertion string          `json:"assertion"`
	Clause    string          `json:"clause"`
	State     string          `json:"state"`
	Expected  json.RawMessage `json:"expected"`
	Actual    any             `json:"actual,omitempty"`
	Detail    string          `json:"detail,omitempty"`
}
