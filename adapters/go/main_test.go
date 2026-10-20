package main

import (
	"net/http"
	"net/url"
	"testing"
)

// Transport must preserve an explicit Host even when the SUT changed it;
// otherwise the adapter can repair invalid signed output into a false pass.
func TestPhysicalMappingPreservesExplicitHost(t *testing.T) {
	physical, _ := url.Parse("http://127.0.0.1:12345")
	for _, tc := range []struct{ host, want string }{{"foreign.example", "foreign.example"}, {"", "resource.example"}} {
		req, _ := http.NewRequest("GET", "https://resource.example/path?q=x", nil)
		req.Host = tc.host
		mapped := mapPhysicalRequest(req, physical)
		if mapped.Host != tc.want || mapped.URL.Host != "127.0.0.1:12345" || mapped.URL.RequestURI() != "/path?q=x" {
			t.Fatalf("%+v", mapped)
		}
		if req.URL.Host != "resource.example" || req.Host != tc.host {
			t.Fatal("input mutated")
		}
	}
}
