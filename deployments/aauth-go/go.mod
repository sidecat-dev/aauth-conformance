module gitlab.com/sidecat-dev/aauth-conformance/deployments/aauth-go

go 1.25

require gitlab.com/sidecat-dev/aauth-go v0.0.0

require (
	github.com/dunglas/httpsfv v1.1.1 // indirect
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.3 // indirect
	golang.org/x/text v0.14.0 // indirect
)

// library links to the aauth-go checkout being deployed; see README.md.
replace gitlab.com/sidecat-dev/aauth-go => ./library
