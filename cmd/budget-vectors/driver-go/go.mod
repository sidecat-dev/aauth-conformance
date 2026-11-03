module gitlab.com/sidecat-dev/aauth-conformance/cmd/budget-vectors/driver-go

go 1.25

require gitlab.com/sidecat-dev/aauth-go v0.0.0

// aauth-go-src is a symlink to an aauth-go checkout, created before building.
replace gitlab.com/sidecat-dev/aauth-go => ./aauth-go-src
